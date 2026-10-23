import { randomBytes } from 'node:crypto';
import { and, count, desc, eq, gt, inArray, max, ne, sql } from 'drizzle-orm';
import type { Db } from '../db/index.js';
import {
  challenges,
  credentials,
  paymasterState,
  paymasterTenants,
  pendingAdditions,
  sessions,
  sponsorshipReservations,
  tenantAdminKeys,
  tenantHistory,
  tenants,
  useropLog,
  users,
} from '../db/schema.js';
import type { PlatformAdminContext } from './platform-sessions.js';
import {
  appendTenantHistory,
  checkOriginClaims,
  originClaims,
  sha256hex,
  TenantWriteError,
  tenantUniqueViolation,
  validateTenantUpdate,
  type Tenant,
  type TenantCreate,
  type TenantPatch,
  type Tx,
} from './tenants.js';

/**
 * What a platform admin can do to tenants (specs/PLATFORM-ADMIN-SPECS.md §5, §7). Every write runs in
 * one transaction holding the tenant's row lock, checks the source state, and appends history in
 * the same transaction. Refusals are TenantWriteErrors carrying the status and code the API
 * returns, so the routes stay thin.
 */

export const actorOf = (admin: PlatformAdminContext) => `platform-admin:${admin.id}:${admin.address}`;

/** 32 random bytes, base64url, `gak_`-prefixed so a leaked key is recognisable (H-i, §7.3). */
const generateAdminKey = () => `gak_${randomBytes(32).toString('base64url')}`;

const keyDetail = (key: { id: string; label: string | null; keyHash: string }) => ({ keyId: key.id, label: key.label, hashPrefix: key.keyHash.slice(0, 8) });

const notFound = (slug: string) => new TenantWriteError(404, 'not-found', `tenant "${slug}" not found`);
const invalidTransition = (tenant: Tenant, what: string) => new TenantWriteError(409, 'invalid-transition', `cannot ${what} tenant "${tenant.slug}" while it is ${tenant.status}`);

async function lockBySlug(tx: Tx, slug: string): Promise<Tenant> {
  const [tenant] = await tx.select().from(tenants).where(eq(tenants.slug, slug)).for('update');
  if (!tenant) throw notFound(slug);
  return tenant;
}

/** Runs a write, turning a unique violation on a tenant identity field into a 409 naming it. */
async function mappingConflicts<T>(write: () => Promise<T>): Promise<T> {
  try {
    return await write();
  } catch (error) {
    const field = tenantUniqueViolation(error);
    if (field) throw new TenantWriteError(409, 'conflict', `another tenant already has this ${field}`, { field });
    throw error;
  }
}

export type DeletePreconditions = {
  /** Chains whose paymaster ledger this deployment keeps. */
  sponsoringChainIds: number[];
  /** Each sponsoring chain's head, read before the transaction; null when it could not be read. */
  heads: Map<number, bigint | null>;
  maxLagBlocks: number;
};

export function createTenantAdminService(db: Db) {
  return {
    async list({ status }: { status?: Tenant['status'] }) {
      const userCounts = db.select({ tenantId: users.tenantId, users: count().as('users') }).from(users).groupBy(users.tenantId).as('user_counts');
      const rows = await db
        .select({ tenant: tenants, users: userCounts.users })
        .from(tenants)
        .leftJoin(userCounts, eq(userCounts.tenantId, tenants.id))
        .where(status ? eq(tenants.status, status) : ne(tenants.status, 'deleted'))
        .orderBy(desc(tenants.createdAt));
      return rows.map((row) => ({ ...row.tenant, users: Number(row.users ?? 0) }));
    },

    async detail(slug: string) {
      const [tenant] = await db.select().from(tenants).where(eq(tenants.slug, slug));
      if (!tenant) throw notFound(slug);
      const [keys, [userCount], [credentialCount], [lastUserop], ledger] = await Promise.all([
        db.select().from(tenantAdminKeys).where(eq(tenantAdminKeys.tenantId, tenant.id)).orderBy(tenantAdminKeys.createdAt),
        db.select({ n: count() }).from(users).where(eq(users.tenantId, tenant.id)),
        db.select({ n: count() }).from(credentials).where(eq(credentials.tenantId, tenant.id)),
        db.select({ at: max(useropLog.createdAt) }).from(useropLog).where(eq(useropLog.tenantId, tenant.id)),
        db.select().from(paymasterTenants).where(eq(paymasterTenants.tenantId, tenant.id)).orderBy(paymasterTenants.chainId),
      ]);
      return {
        tenant,
        adminKeys: keys.map((key) => ({ id: key.id, label: key.label, hashPrefix: key.keyHash.slice(0, 8), createdBy: key.createdBy, createdAt: key.createdAt })),
        users: Number(userCount.n),
        credentials: Number(credentialCount.n),
        lastUseropAt: lastUserop?.at ?? null,
        ledger: ledger.map((row) => ({
          chainId: row.chainId,
          balanceWei: row.balanceWei,
          deficitWei: row.deficitWei,
          lastSyncedBlock: row.lastSyncedBlock?.toString() ?? null,
        })),
      };
    },

    /** Active from birth. Admin keys are generated here and returned once. */
    async create(input: TenantCreate, admin: PlatformAdminContext) {
      const actor = actorOf(admin);
      return mappingConflicts(() =>
        db.transaction(async (tx) => {
          const clash = await checkOriginClaims(tx, { selfId: null, claims: originClaims(input) });
          if (clash) {
            throw new TenantWriteError(409, 'origin-claimed', `origin ${clash.origin} is already claimed by tenant "${clash.slug}"`, { origin: clash.origin, slug: clash.slug });
          }
          const { adminKeys: labels, id, ...fields } = input;
          const [tenant] = await tx
            .insert(tenants)
            .values({ ...fields, ...(id ? { id } : {}), managedBy: 'operator' })
            .returning();
          const issued = labels.map(({ label }) => ({ label, key: generateAdminKey() }));
          const keys =
            issued.length > 0
              ? await tx
                  .insert(tenantAdminKeys)
                  .values(issued.map(({ label, key }) => ({ tenantId: tenant.id, keyHash: sha256hex(key), label, createdBy: actor })))
                  .returning()
              : [];
          await appendTenantHistory(tx, {
            tenantId: tenant.id,
            action: 'create',
            actor,
            platformAdminSessionId: admin.sessionId,
            before: null,
            after: tenant,
            detail: keys.length > 0 ? { adminKeys: keys.map(keyDetail) } : null,
          });
          return { tenant, adminKeys: keys.map((row, i) => ({ id: row.id, label: issued[i].label, key: issued[i].key })) };
        }),
      );
    },

    /** Optimistic: `version` is the precondition, and the patch is validated as the merged result. */
    async update(slug: string, patch: TenantPatch, version: number, admin: PlatformAdminContext) {
      return mappingConflicts(() =>
        db.transaction(async (tx) => {
          const tenant = await lockBySlug(tx, slug);
            if (tenant.status !== 'active') throw invalidTransition(tenant, 'edit');
          if (tenant.version !== version) {
            throw new TenantWriteError(412, 'version-mismatch', `tenant "${slug}" is at version ${tenant.version}`, { version: tenant.version });
          }
          const [{ n: adminKeyCount }] = await tx.select({ n: count() }).from(tenantAdminKeys).where(eq(tenantAdminKeys.tenantId, tenant.id));
          const validated = validateTenantUpdate(tenant, patch, { adminKeyCount: Number(adminKeyCount) });
          if (!validated.ok) throw new TenantWriteError(400, 'invalid-tenant', 'the tenant would violate its invariants', { issues: validated.issues });
          const clash = await checkOriginClaims(tx, { selfId: tenant.id, claims: originClaims(validated.fields) });
          if (clash) {
            throw new TenantWriteError(409, 'origin-claimed', `origin ${clash.origin} is already claimed by tenant "${clash.slug}"`, { origin: clash.origin, slug: clash.slug });
          }
          const { slug: _slug, id: _id, walletOrigin: _origin, rpId: _rpId, ...mutable } = validated.fields;
          const [updated] = await tx
            .update(tenants)
            .set({ ...mutable, version: sql`${tenants.version} + 1`, updatedAt: sql`now()` })
            .where(eq(tenants.id, tenant.id))
            .returning();
          await appendTenantHistory(tx, { tenantId: tenant.id, action: 'update', actor: actorOf(admin), platformAdminSessionId: admin.sessionId, before: tenant, after: updated });
          return updated;
        }),
      );
    },

    /** active → suspended: the incident tool. */
    async suspend(slug: string, reason: string, admin: PlatformAdminContext) {
      return transition(slug, admin, { from: 'active', to: 'suspended', action: 'suspend', detail: { reason } });
    },

    async resume(slug: string, admin: PlatformAdminContext) {
      return transition(slug, admin, { from: 'suspended', to: 'active', action: 'resume' });
    },

    /**
     * suspended → deleted, a tombstone (§5.3). The row stays so its slug, id, wallet origin and RP
     * ID are never reusable; the tenant's sessions, open challenges, pending additions and admin
     * keys go. Refused while money is attached, or while the ledger that says so is stale.
     */
    async remove(slug: string, admin: PlatformAdminContext, preconditions: DeletePreconditions) {
      return db.transaction(async (tx) => {
        const tenant = await lockBySlug(tx, slug);
        if (tenant.status === 'deleted') throw invalidTransition(tenant, 'delete');
        if (tenant.status !== 'suspended') {
          throw new TenantWriteError(409, 'tenant-not-suspended', `tenant "${slug}" must be suspended before it is deleted`);
        }

        const ledger = await tx.select().from(paymasterTenants).where(eq(paymasterTenants.tenantId, tenant.id));
        const funded = ledger.filter((row) => BigInt(row.balanceWei) !== 0n || BigInt(row.deficitWei) !== 0n);
        if (funded.length > 0) {
          throw new TenantWriteError(409, 'tenant-has-funds', `tenant "${slug}" has a balance or deficit; the tenant must withdraw first`, {
            chains: funded.map((row) => ({
              chainId: row.chainId,
              balanceWei: row.balanceWei,
              deficitWei: row.deficitWei,
              lastSyncedBlock: row.lastSyncedBlock?.toString() ?? null,
            })),
          });
        }

        // only the watcher marks reservations expired, so an unswept one past its expiry must not count
        const [{ n: open }] = await tx
          .select({ n: count() })
          .from(sponsorshipReservations)
          .where(and(eq(sponsorshipReservations.tenantId, tenant.id), eq(sponsorshipReservations.state, 'reserved'), gt(sponsorshipReservations.expiresAt, sql`now()`)));
        if (Number(open) > 0) {
          throw new TenantWriteError(409, 'tenant-has-reservations', `tenant "${slug}" has sponsorship reservations still open`, { reservations: Number(open) });
        }

        if (preconditions.sponsoringChainIds.length > 0) {
          const states = await tx.select().from(paymasterState).where(inArray(paymasterState.chainId, preconditions.sponsoringChainIds));
          const stale = preconditions.sponsoringChainIds.flatMap((chainId) => {
            const head = preconditions.heads.get(chainId) ?? null;
            const synced = states.find((state) => state.chainId === chainId)?.lastSyncedBlock ?? null;
            const fresh = head !== null && synced !== null && head - synced <= BigInt(preconditions.maxLagBlocks);
            return fresh ? [] : [{ chainId, headBlock: head?.toString() ?? null, lastSyncedBlock: synced?.toString() ?? null }];
          });
          if (stale.length > 0) {
            throw new TenantWriteError(409, 'ledger-stale', 'the paymaster ledger is too far behind the chain to trust a zero balance', { chains: stale });
          }
        }

        const [deleted] = await tx
          .update(tenants)
          .set({ status: 'deleted', statusChangedAt: sql`now()`, version: sql`${tenants.version} + 1`, updatedAt: sql`now()` })
          .where(eq(tenants.id, tenant.id))
          .returning();
        // sessions carry no tenant column: a session's tenant is its user's
        const removedSessions = await tx
          .delete(sessions)
          .where(inArray(sessions.userId, tx.select({ id: users.id }).from(users).where(eq(users.tenantId, tenant.id))))
          .returning({ id: sessions.id });
        const removedChallenges = await tx.delete(challenges).where(eq(challenges.tenantId, tenant.id)).returning({ id: challenges.id });
        const removedAdditions = await tx.delete(pendingAdditions).where(eq(pendingAdditions.tenantId, tenant.id)).returning({ id: pendingAdditions.id });
        const removedKeys = await tx.delete(tenantAdminKeys).where(eq(tenantAdminKeys.tenantId, tenant.id)).returning();
        await appendTenantHistory(tx, {
          tenantId: tenant.id,
          action: 'delete',
          actor: actorOf(admin),
          platformAdminSessionId: admin.sessionId,
          before: tenant,
          after: deleted,
          detail: {
            removed: {
              sessions: removedSessions.length,
              challenges: removedChallenges.length,
              pendingAdditions: removedAdditions.length,
              adminKeys: removedKeys.map(keyDetail),
            },
          },
        });
        return deleted;
      });
    },

    async issueAdminKey(slug: string, label: string, admin: PlatformAdminContext) {
      return db.transaction(async (tx) => {
        const tenant = await lockBySlug(tx, slug);
        if (tenant.status !== 'active') throw invalidTransition(tenant, 'issue an admin key for');
        const key = generateAdminKey();
        const [row] = await tx
          .insert(tenantAdminKeys)
          .values({ tenantId: tenant.id, keyHash: sha256hex(key), label, createdBy: actorOf(admin) })
          .returning();
        await appendTenantHistory(tx, {
          tenantId: tenant.id,
          action: 'admin-key-issue',
          actor: actorOf(admin),
          platformAdminSessionId: admin.sessionId,
          before: tenant,
          after: tenant,
          detail: keyDetail(row),
        });
        return { id: row.id, label, key };
      });
    },

    /** Allowed while suspended too: revoking a leaked key must not wait for a resume. */
    async revokeAdminKey(slug: string, keyId: string, admin: PlatformAdminContext) {
      return db.transaction(async (tx) => {
        const tenant = await lockBySlug(tx, slug);
        if (tenant.status === 'deleted') throw invalidTransition(tenant, 'revoke an admin key of');
        const keys = await tx.select().from(tenantAdminKeys).where(eq(tenantAdminKeys.tenantId, tenant.id));
        const key = keys.find((candidate) => candidate.id === keyId);
        if (!key) throw new TenantWriteError(404, 'not-found', 'admin key not found');
        if (keys.length === 1 && !tenant.openRegistration) {
          throw new TenantWriteError(409, 'last-admin-key', `tenant "${slug}" has closed registration and this is its last admin key`);
        }
        await tx.delete(tenantAdminKeys).where(eq(tenantAdminKeys.id, key.id));
        await appendTenantHistory(tx, {
          tenantId: tenant.id,
          action: 'admin-key-revoke',
          actor: actorOf(admin),
          platformAdminSessionId: admin.sessionId,
          before: tenant,
          after: tenant,
          detail: keyDetail(key),
        });
      });
    },

    /** Newest first. `before` is the id of the last entry of the previous page. */
    async history(slug: string, { before, limit }: { before?: string; limit: number }) {
      const [tenant] = await db.select({ id: tenants.id }).from(tenants).where(eq(tenants.slug, slug));
      if (!tenant) throw notFound(slug);
      const cursor = before
        ? sql`(${tenantHistory.createdAt}, ${tenantHistory.id}) < (SELECT created_at, id FROM tenant_history WHERE id = ${before})`
        : undefined;
      const rows = await db
        .select()
        .from(tenantHistory)
        .where(and(eq(tenantHistory.tenantId, tenant.id), cursor))
        .orderBy(desc(tenantHistory.createdAt), desc(tenantHistory.id))
        .limit(limit + 1);
      const entries = rows.slice(0, limit);
      return { entries, next: rows.length > limit ? entries[entries.length - 1].id : null };
    },
  };

  async function transition(
    slug: string,
    admin: PlatformAdminContext,
    move: { from: Tenant['status']; to: Tenant['status']; action: 'suspend' | 'resume'; detail?: Record<string, unknown> },
  ) {
    return db.transaction(async (tx) => {
      const tenant = await lockBySlug(tx, slug);
      if (tenant.status !== move.from) throw invalidTransition(tenant, move.action);
      const [moved] = await tx
        .update(tenants)
        .set({ status: move.to, statusChangedAt: sql`now()`, version: sql`${tenants.version} + 1`, updatedAt: sql`now()` })
        .where(eq(tenants.id, tenant.id))
        .returning();
      await appendTenantHistory(tx, {
        tenantId: tenant.id,
        action: move.action,
        actor: actorOf(admin),
        platformAdminSessionId: admin.sessionId,
        before: tenant,
        after: moved,
        detail: move.detail ?? null,
      });
      return moved;
    });
  }
}

export type TenantAdminService = ReturnType<typeof createTenantAdminService>;
