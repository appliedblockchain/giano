import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createDb, type Db } from '../src/db/index.js';
import { tenantAdminKeys, tenantHistory, tenants } from '../src/db/schema.js';
import { runMigrations } from '../src/migrate.js';
import { checkOriginClaims, seedTenants, sha256hex, tenantUniqueViolation, validateTenantSeed } from '../src/services/tenants.js';

/**
 * The boot seed after operators can write tenants too (specs/OPERATOR-ADMIN-SPECS.md §6.2, §9):
 * every seed write passes the cross-tenant origin check, ownership decides who may write a row,
 * and an idle restart writes nothing.
 */
describe('seedTenants with the tenant lifecycle', () => {
  let container: StartedPostgreSqlContainer;
  let db: Db;
  let pool: { end: () => Promise<void> };

  const acme = (overrides: Record<string, unknown> = {}) =>
    validateTenantSeed({
      slug: 'acme',
      walletOrigin: 'https://wallet.acme.app',
      rpName: 'Acme',
      adminKeys: ['acme-admin-key-0001'],
      ...overrides,
    });

  const row = async (slug: string) => (await db.select().from(tenants).where(eq(tenants.slug, slug)))[0];
  const history = async (slug: string) => {
    const tenant = await row(slug);
    return db.select().from(tenantHistory).where(eq(tenantHistory.tenantId, tenant.id)).orderBy(tenantHistory.createdAt);
  };
  const keyHashes = async (slug: string) => {
    const tenant = await row(slug);
    return (await db.select({ keyHash: tenantAdminKeys.keyHash }).from(tenantAdminKeys).where(eq(tenantAdminKeys.tenantId, tenant.id))).map((r) => r.keyHash);
  };
  const operatorTenant = (slug: string, walletOrigin: string, status: 'active' | 'suspended' | 'deleted' = 'active') =>
    db
      .insert(tenants)
      .values({ slug, walletOrigin, rpId: new URL(walletOrigin).hostname, rpName: slug, expectedOrigins: [walletOrigin], managedBy: 'operator', status })
      .returning();

  beforeAll(async () => {
    container = await new PostgreSqlContainer('postgres:17-alpine').start();
    await runMigrations(container.getConnectionUri());
    ({ db, pool } = createDb(container.getConnectionUri()));
  });

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
  });

  beforeEach(async () => {
    await db.execute(sql`TRUNCATE tenant_history, tenant_admin_keys, tenants CASCADE`);
  });

  it('creates an unknown slug as seed-managed, with a create entry by seed', async () => {
    await seedTenants(db, [acme()]);
    const tenant = await row('acme');
    expect(tenant).toMatchObject({ status: 'active', managedBy: 'seed', version: 1 });
    expect((await history('acme')).map((h) => [h.action, h.actor])).toEqual([['create', 'seed']]);
  });

  it('an idle restart writes nothing and keeps the version', async () => {
    await seedTenants(db, [acme()]);
    await seedTenants(db, [acme()]);
    expect((await row('acme')).version).toBe(1);
    expect(await history('acme')).toHaveLength(1);
  });

  it('a changed seed applies, bumps the version and records seed-apply with before and after', async () => {
    await seedTenants(db, [acme()]);
    await seedTenants(db, [acme({ rpName: 'Acme Renamed', adminKeys: ['acme-admin-key-0002'] })]);
    const tenant = await row('acme');
    expect(tenant).toMatchObject({ rpName: 'Acme Renamed', version: 2, managedBy: 'seed' });
    expect(await keyHashes('acme')).toEqual([sha256hex('acme-admin-key-0002')]);
    const entries = await history('acme');
    expect(entries.map((h) => h.action)).toEqual(['create', 'seed-apply']);
    expect(entries[1]).toMatchObject({ before: expect.objectContaining({ rpName: 'Acme' }), after: expect.objectContaining({ rpName: 'Acme Renamed' }) });
    expect(JSON.stringify(entries)).not.toContain('acme-admin-key');
  });

  it('never changes the lifecycle state: a suspended seed tenant stays suspended across a restart', async () => {
    await seedTenants(db, [acme()]);
    await db.update(tenants).set({ status: 'suspended' }).where(eq(tenants.slug, 'acme'));
    await seedTenants(db, [acme({ rpName: 'Acme Renamed' })]);
    expect((await row('acme')).status).toBe('suspended');
  });

  it('takes over an operator-managed tenant with the same slug, replacing fields and keys, and warns', async () => {
    const [tenant] = await operatorTenant('acme', 'https://wallet.acme.app');
    await db.insert(tenantAdminKeys).values({ tenantId: tenant.id, keyHash: sha256hex('gak_operator-issued'), createdBy: 'operator:ops:0xabc' });
    const warnings: string[] = [];
    await seedTenants(db, [acme()], { warn: (message) => warnings.push(message) });
    expect(await row('acme')).toMatchObject({ managedBy: 'seed', rpName: 'Acme', version: 2 });
    expect(await keyHashes('acme')).toEqual([sha256hex('acme-admin-key-0001')]);
    expect((await history('acme')).map((h) => h.action)).toEqual(['seed-takeover']);
    expect(warnings).toEqual([expect.stringMatching(/"acme" was operator-managed/)]);
  });

  it('refuses boot for a slug that names a deleted tenant', async () => {
    await operatorTenant('acme', 'https://wallet.acme.app', 'deleted');
    await expect(seedTenants(db, [acme()])).rejects.toThrow(/"acme" was deleted; a deleted tenant is never re-created/);
  });

  it('leaves a seed-managed tenant that has left the seed as it is', async () => {
    await seedTenants(db, [acme()]);
    await seedTenants(db, []);
    expect(await row('acme')).toMatchObject({ managedBy: 'seed', status: 'active', version: 1 });
  });

  it('refuses boot when a seed entry claims an origin an operator tenant holds, naming it, its owner and state', async () => {
    await operatorTenant('runtime', 'https://pay.wallet.acme.app', 'suspended');
    await expect(seedTenants(db, [acme({ expectedOrigins: ['https://pay.wallet.acme.app'] })])).rejects.toThrow(
      /origin https:\/\/pay\.wallet\.acme\.app is already claimed by tenant "runtime" \(managed by operator, suspended\)/,
    );
  });

  it("keeps a deleted tenant's origins claimed", async () => {
    await operatorTenant('gone', 'https://pay.wallet.acme.app', 'deleted');
    await expect(seedTenants(db, [acme({ expectedOrigins: ['https://pay.wallet.acme.app'] })])).rejects.toThrow(/claimed by tenant "gone"/);
  });

  it('serialises concurrent claims of one origin: exactly one writer wins', async () => {
    const claim = (slug: string) =>
      db.transaction(async (tx) => {
        const walletOrigin = `https://${slug}.wallet.acme.app`;
        const claims = [walletOrigin, 'https://shared.wallet.acme.app'];
        const clash = await checkOriginClaims(tx, { selfId: null, claims });
        if (clash) return 'clash';
        // widen the race window: without the lock both would pass the check
        await tx.execute(sql`SELECT pg_sleep(0.2)`);
        await tx.insert(tenants).values({ slug, walletOrigin, rpId: new URL(walletOrigin).hostname, rpName: slug, expectedOrigins: claims, managedBy: 'operator' });
        return 'created';
      });
    expect((await Promise.all([claim('one'), claim('two')])).sort()).toEqual(['clash', 'created']);
  });

  it('two replicas applying the same changed seed at once leave one seed-apply entry', async () => {
    await seedTenants(db, [acme()]);
    const { db: replica, pool: replicaPool } = createDb(container.getConnectionUri());
    try {
      await Promise.all([seedTenants(db, [acme({ rpName: 'Acme v2' })]), seedTenants(replica, [acme({ rpName: 'Acme v2' })])]);
    } finally {
      await replicaPool.end();
    }
    expect((await row('acme')).version).toBe(2);
    expect((await history('acme')).map((h) => h.action)).toEqual(['create', 'seed-apply']);
  });

  it('maps a unique violation to the tenant field it is about', async () => {
    await seedTenants(db, [acme()]);
    const error = await db
      .insert(tenants)
      .values({ slug: 'acme', walletOrigin: 'https://other.app', rpId: 'other.app', rpName: 'x', expectedOrigins: [] })
      .catch((e: unknown) => e);
    expect(tenantUniqueViolation(error)).toBe('slug');
    expect(tenantUniqueViolation(new Error('unrelated'))).toBeNull();
  });
});
