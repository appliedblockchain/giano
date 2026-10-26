import { createHash } from 'node:crypto';
import { and, eq, ne, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { tenantAdminKeys, tenantHistory, tenantHistoryActions, tenants } from '../db/schema.js';
import type { PolicyConfig } from './userop-policy.js';

/**
 * Tenancy model (specs/DEVELOPER-GUIDE.md §1): tenant ≡ wallet origin ≡ RP ID, 1:1.
 * Tenants are written at runtime by Giano's platform admins (specs/PLATFORM-ADMIN-SPECS.md), and on
 * local stacks by the tenant fixtures (tenant-fixtures.ts). EVERY write passes through
 * checkTenantInvariants and checkOriginClaims, so the RP/origin invariant can never be
 * violated in the database and no origin can ever resolve to two tenants.
 */

export const sha256hex = (value: string) => createHash('sha256').update(value).digest('hex');

const isBareOrigin = (value: string) => {
  try {
    return new URL(value).origin === value;
  } catch {
    return false;
  }
};

/** Decimal-string bigint: policy overrides live in jsonb, so bigints stay strings at rest. */
const bigintString = z.string().regex(/^\d+$/, 'expected a decimal string (bigints are stored as strings)');

const addressArray = z
  .array(z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'expected a 0x address'))
  .transform((addrs) => addrs.map((a) => a.toLowerCase()));

/**
 * Chain-agnostic overrides: gas and fee caps and the rate limit are safe to state once for
 * every chain (and refine per chain under `perChain`). Address-valued fields are NOT here —
 * see below.
 */
const tenantPolicyBaseSchema = z.object({
  maxCallGas: bigintString.optional(),
  maxVerificationGas: bigintString.optional(),
  maxFeePerGas: bigintString.optional(),
  maxPriorityFeePerGas: bigintString.optional(),
  /** Per-tenant override of USEROP_RATE_LIMIT_PER_MINUTE — shared across chains (MC-63). */
  relayRateLimitPerMinute: z.number().int().positive().optional(),
});

/**
 * The per-chain layer. Address-valued policy (`allowedTargets`, `allowedPaymasters`) exists
 * ONLY here, keyed by chain id — the same address denotes different contracts on different
 * chains, so a chain-agnostic address allowlist is deliberately not expressible (MC-61, S6):
 * the violation is unrepresentable rather than prevented by a resolution rule someone could
 * misread. The existing sense of an empty array — any value allowed — is preserved WITHIN
 * an entry.
 */
const tenantPolicyPerChainSchema = z
  .object({
    // no relayRateLimitPerMinute here: the relay limit is shared across chains (MC-63)
    maxCallGas: bigintString.optional(),
    maxVerificationGas: bigintString.optional(),
    maxFeePerGas: bigintString.optional(),
    maxPriorityFeePerGas: bigintString.optional(),
    allowedTargets: addressArray.optional(),
    allowedPaymasters: addressArray.optional(),
  })
  .strict();

/** Partial per-tenant overrides of the deployment-wide userop policy defaults. */
export const tenantPolicySchema = tenantPolicyBaseSchema
  .extend({
    perChain: z.record(z.string().regex(/^\d+$/, 'perChain keys are chain ids'), tenantPolicyPerChainSchema).optional(),
  })
  .strict();

export type TenantPolicy = z.infer<typeof tenantPolicySchema>;

const originList = z.array(z.string().refine(isBareOrigin, 'must be a bare origin')).default([]);

/**
 * Field shapes only, shared by every write path. Strict: an unknown key is refused rather than
 * silently dropped, so a typo in a fixture or a request never reads as "applied".
 */
export const tenantFieldsSchema = z
  .object({
    slug: z.string().min(1).max(64).regex(/^[a-z0-9-]+$/, 'lowercase slug'),
    /**
     * Pins the tenant's UUID instead of letting the database generate one.
     *
     * Needed because the tenant id is not purely internal: the paymaster keys per-tenant balances
     * on its 16 bytes, so a deployment that registers a tenant on chain must be able to make the
     * database agree. Used by the devnet and e2e stacks, where the paymaster is pre-registered
     * against fixed ids and a random id would leave every sponsorship refused as "unknown tenant".
     *
     * Immutable once set, like `rpId`: changing it would orphan that tenant's on-chain balance.
     */
    id: z.string().uuid().optional(),
    walletOrigin: z.string().refine(isBareOrigin, 'must be a bare origin, e.g. https://wallet.example.com'),
    /** Defaults to the host of walletOrigin; if supplied it must equal it (D1). */
    rpId: z.string().min(1).optional(),
    rpName: z.string().min(1).max(256),
    expectedOrigins: originList,
    allowedDappOrigins: originList,
    corsOrigins: originList,
    openRegistration: z.boolean().default(false),
    policy: tenantPolicySchema.default({}),
    branding: z.record(z.unknown()).default({}),
  })
  .strict();

export type TenantFields = z.infer<typeof tenantFieldsSchema>;
export type TenantIssue = { path: (string | number)[]; message: string };

/**
 * The single-tenant invariants every write must satisfy. Returns issues rather than throwing, so
 * the fixture loader can fail with them and the platform API can return them as a 400.
 */
export function checkTenantInvariants(
  fields: Pick<TenantFields, 'walletOrigin' | 'rpId' | 'expectedOrigins' | 'openRegistration'>,
  { adminKeyCount }: { adminKeyCount: number },
): TenantIssue[] {
  // a malformed origin is already reported by the field schema
  if (!isBareOrigin(fields.walletOrigin)) return [];
  const walletHost = new URL(fields.walletOrigin).hostname;
  if (fields.rpId && fields.rpId !== walletHost) {
    // D1: RP_ID must be the wallet host. Registrable-parent RP IDs need the client
    // rpId plumbing first (gap doc §3.2) and are deliberately not offered here.
    return [{ path: ['rpId'], message: `rpId "${fields.rpId}" must equal the walletOrigin host "${walletHost}"` }];
  }
  const rpId = fields.rpId ?? walletHost;
  const issues: TenantIssue[] = [];
  // passkeys bind to rp_id irreversibly, so verification-time failures are too late:
  // every ceremony origin's host must equal rp_id or be a subdomain of it
  for (const origin of fields.expectedOrigins) {
    if (!isBareOrigin(origin)) continue;
    const host = new URL(origin).hostname;
    if (host !== rpId && !host.endsWith(`.${rpId}`)) {
      issues.push({
        path: ['expectedOrigins'],
        message: `origin ${origin} is not valid for rpId "${rpId}" — its host must equal the rpId or be a subdomain of it`,
      });
    }
  }
  if (!fields.openRegistration && adminKeyCount === 0) {
    issues.push({ path: ['adminKeys'], message: 'adminKeys is required when openRegistration is false (something must authorize registration)' });
  }
  return issues;
}

/** rpId defaults to the wallet host, and the wallet origin is always an expected origin. */
export function normaliseTenantFields<T extends TenantFields>(fields: T): T & { rpId: string } {
  const rpId = fields.rpId ?? new URL(fields.walletOrigin).hostname;
  const expectedOrigins = fields.expectedOrigins.includes(fields.walletOrigin) ? fields.expectedOrigins : [fields.walletOrigin, ...fields.expectedOrigins];
  return { ...fields, rpId, expectedOrigins };
}

const addIssues = (ctx: z.RefinementCtx, issues: TenantIssue[]) => {
  for (const issue of issues) ctx.addIssue({ code: z.ZodIssueCode.custom, path: issue.path, message: issue.message });
};

/** A platform admin create: the fields plus labels for admin keys the server generates (H-i). */
export const tenantCreateSchema = tenantFieldsSchema
  .extend({
    adminKeys: z.array(z.object({ label: z.string().min(1).max(64) }).strict()).default([]),
  })
  .superRefine((input, ctx) => addIssues(ctx, checkTenantInvariants(input, { adminKeyCount: input.adminKeys.length })))
  .transform(normaliseTenantFields);

export type TenantCreate = z.infer<typeof tenantCreateSchema>;

/** Never changeable through the API (H-f): passkeys and the paymaster balance key on them. */
export const IMMUTABLE_TENANT_FIELDS = ['slug', 'id', 'walletOrigin', 'rpId'] as const;

/** The mutable subset. Absent fields stay as stored. */
export const tenantPatchSchema = tenantFieldsSchema
  .pick({ rpName: true, expectedOrigins: true, allowedDappOrigins: true, corsOrigins: true, openRegistration: true, policy: true, branding: true })
  .partial()
  .strict();

export type TenantPatch = z.infer<typeof tenantPatchSchema>;

/**
 * Validates an update the way a create is validated: the patch is merged onto the stored row and
 * the RESULT is checked, with the admin-key count taken from storage — so a patch can never leave
 * a tenant in a state a create would have refused.
 */
export function validateTenantUpdate(
  stored: Tenant,
  patch: TenantPatch,
  { adminKeyCount }: { adminKeyCount: number },
): { ok: true; fields: TenantFields & { rpId: string } } | { ok: false; issues: TenantIssue[] } {
  const parsed = tenantFieldsSchema.safeParse({ ...storedFields(stored), ...patch });
  if (!parsed.success) return { ok: false, issues: parsed.error.issues.map((issue) => ({ path: issue.path, message: issue.message })) };
  const issues = checkTenantInvariants(parsed.data, { adminKeyCount });
  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, fields: normaliseTenantFields(parsed.data) };
}

/** The writable fields of a stored row, in the shape the field schema takes. */
function storedFields(row: Tenant) {
  return {
    slug: row.slug,
    walletOrigin: row.walletOrigin,
    rpId: row.rpId,
    rpName: row.rpName,
    expectedOrigins: row.expectedOrigins,
    allowedDappOrigins: row.allowedDappOrigins,
    corsOrigins: row.corsOrigins,
    openRegistration: row.openRegistration,
    policy: row.policy,
    branding: row.branding,
  };
}

/** A tenant's origin claims: the origins that resolve to it. No origin may be claimed twice (H-g). */
export function originClaims(fields: { walletOrigin: string; expectedOrigins?: string[] }): string[] {
  return [...new Set([fields.walletOrigin, ...(fields.expectedOrigins ?? [])])];
}

// ── Writing ────────────────────────────────────────────────────────────────────

export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];
export type TenantHistoryAction = (typeof tenantHistoryActions)[number];

/** A refused tenant write, carrying the HTTP status and error code the platform API returns. */
export class TenantWriteError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly detail: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

/**
 * Serialises every write of `wallet_origin` or `expected_origins` across the deployment, for the
 * length of the transaction. Postgres cannot put a unique constraint across array elements, so
 * this lock is what makes the origin-claim check race-free. Tenant writes are rare, so one lock
 * per deployment costs nothing.
 */
export async function lockTenantWrites(tx: Tx): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('giano:tenant-origin-claims'))`);
}

export type OriginClaimClash = { origin: string; slug: string; status: Tenant['status'] };

/**
 * Finds another tenant — in ANY lifecycle state, deleted included (H-d) — that already claims one
 * of `claims`. Takes the tenant-write lock first, so the answer holds until the transaction ends.
 */
export async function checkOriginClaims(tx: Tx, { selfId, claims }: { selfId: string | null; claims: string[] }): Promise<OriginClaimClash | null> {
  await lockTenantWrites(tx);
  if (claims.length === 0) return null;
  const list = sql`ARRAY[${sql.join(
    claims.map((claim) => sql`${claim}`),
    sql`, `,
  )}]::text[]`;
  const [row] = await tx
    .select({ slug: tenants.slug, walletOrigin: tenants.walletOrigin, expectedOrigins: tenants.expectedOrigins, status: tenants.status })
    .from(tenants)
    .where(and(selfId ? ne(tenants.id, selfId) : undefined, sql`(${tenants.walletOrigin} = ANY(${list}) OR ${tenants.expectedOrigins} && ${list})`))
    .limit(1);
  if (!row) return null;
  const origin = claims.find((claim) => claim === row.walletOrigin || row.expectedOrigins.includes(claim))!;
  return { origin, slug: row.slug, status: row.status };
}

const UNIQUE_TENANT_FIELDS: Record<string, string> = {
  tenants_pkey: 'id',
  tenants_slug_key: 'slug',
  tenants_wallet_origin_key: 'walletOrigin',
  tenants_rp_id_key: 'rpId',
};

/**
 * The tenant field a unique violation is about, or null if the error is not one. drizzle-orm
 * ≥0.44 wraps the driver error in a DrizzleQueryError and keeps the pg error as `cause`.
 */
export function tenantUniqueViolation(error: unknown): string | null {
  if (typeof error !== 'object' || error === null) return null;
  const { code, constraint, cause } = error as { code?: string; constraint?: string; cause?: unknown };
  if (code === '23505' && constraint && constraint in UNIQUE_TENANT_FIELDS) return UNIQUE_TENANT_FIELDS[constraint];
  return tenantUniqueViolation(cause);
}

/** A tenant row as history records it. Tenants carry no key material, so nothing is redacted. */
export function tenantSnapshot(row: Tenant): Record<string, unknown> {
  return {
    ...row,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    statusChangedAt: row.statusChangedAt?.toISOString() ?? null,
  };
}

export async function appendTenantHistory(
  tx: Tx,
  entry: {
    tenantId: string;
    action: TenantHistoryAction;
    actor: string;
    platformAdminSessionId?: string | null;
    before: Tenant | null;
    after: Tenant | null;
    detail?: Record<string, unknown> | null;
  },
): Promise<void> {
  await tx.insert(tenantHistory).values({
    tenantId: entry.tenantId,
    action: entry.action,
    actor: entry.actor,
    platformAdminSessionId: entry.platformAdminSessionId ?? null,
    before: entry.before ? tenantSnapshot(entry.before) : null,
    after: entry.after ? tenantSnapshot(entry.after) : null,
    detail: entry.detail ?? null,
  });
}

export type Tenant = typeof tenants.$inferSelect;

/** Strips an optional :port (Host header form) down to the hostname. */
export function hostHeaderToHostname(hostHeader: string): string | null {
  try {
    return new URL(`http://${hostHeader}`).hostname;
  } catch {
    return null;
  }
}

export type TenantService = ReturnType<typeof createTenantService>;

/**
 * Every resolver that decides which tenant a REQUEST belongs to answers for active tenants only:
 * a suspended or deleted tenant is indistinguishable from an unknown one everywhere
 * (specs/PLATFORM-ADMIN-SPECS.md §8). Resolution stays per request from the database, with no
 * cache, so a lifecycle change is in force on the next request on every replica.
 */
const isActive = eq(tenants.status, 'active');

export function createTenantService(db: Db) {
  return {
    /** The session path: a session whose tenant is not active authorises nothing. */
    async getActiveById(id: string): Promise<Tenant | null> {
      return (await db.query.tenants.findFirst({ where: and(eq(tenants.id, id), isActive) })) ?? null;
    },

    /**
     * Any lifecycle state — for platform admin routes and background accounting, never for deciding
     * whether a request may act as the tenant. Named so that choice is visible at the call site.
     */
    async getByIdAnyStatus(id: string): Promise<Tenant | null> {
      return (await db.query.tenants.findFirst({ where: eq(tenants.id, id) })) ?? null;
    },

    /** Resolves a browser Origin header: exact wallet_origin or expected_origins member. */
    async getByOrigin(origin: string): Promise<Tenant | null> {
      const row = await db.query.tenants.findFirst({
        where: and(sql`(${tenants.walletOrigin} = ${origin} OR ${origin} = ANY(${tenants.expectedOrigins}))`, isActive),
      });
      return row ?? null;
    },

    /** Resolves a Host header (may carry a port) by rp_id. */
    async getByHost(hostHeader: string): Promise<Tenant | null> {
      const hostname = hostHeaderToHostname(hostHeader);
      if (!hostname) return null;
      return (await db.query.tenants.findFirst({ where: and(eq(tenants.rpId, hostname), isActive) })) ?? null;
    },

    /** Resolves an admin key hash to its tenant (O(1) unique-index lookup). */
    async getByAdminKeyHash(keyHash: string): Promise<{ tenant: Tenant; keyHash: string } | null> {
      const [row] = await db
        .select({ tenant: tenants, keyHash: tenantAdminKeys.keyHash })
        .from(tenantAdminKeys)
        .innerJoin(tenants, eq(tenantAdminKeys.tenantId, tenants.id))
        .where(and(eq(tenantAdminKeys.keyHash, keyHash), isActive))
        .limit(1);
      return row ?? null;
    },

    /** CORS delegate lookup: any active tenant's cors_origins (or wallet origin itself). */
    async isCorsOrigin(origin: string): Promise<boolean> {
      const row = await db.query.tenants.findFirst({
        where: and(sql`(${tenants.walletOrigin} = ${origin} OR ${origin} = ANY(${tenants.corsOrigins}))`, isActive),
      });
      return !!row;
    },
  };
}

/**
 * Per-request policy for one (tenant, chain), per specs/MULTICHAIN_SPECS.md §9.5.
 *
 * `defaults` is already per chain (deployment env defaults + the chain descriptor's policy).
 * On top of it: chain-agnostic caps resolve `tenant base` ← `tenant perChain[chainId]`
 * (later wins — inheritance across chains is fine and wanted for numbers, MC-62); the
 * address-valued allowlists resolve from `perChain[chainId]` ONLY, falling back to the
 * chain's own defaults — never to another chain's values, and never to a tenant base value,
 * which the schema cannot even express (MC-61).
 */
export function mergePolicy(defaults: PolicyConfig, tenantPolicy: unknown, chainId: number): PolicyConfig & { relayRateLimitPerMinute?: number } {
  const parsed = tenantPolicySchema.safeParse(tenantPolicy ?? {});
  // fail safe: an unparseable stored policy falls back to the deployment defaults
  const overrides = parsed.success ? parsed.data : {};
  const perChain = parsed.success ? (parsed.data.perChain?.[String(chainId)] ?? {}) : {};
  const cap = (chain: string | undefined, base: string | undefined, fallback: bigint) =>
    chain ? BigInt(chain) : base ? BigInt(base) : fallback;
  return {
    maxCallGas: cap(perChain.maxCallGas, overrides.maxCallGas, defaults.maxCallGas),
    maxVerificationGas: cap(perChain.maxVerificationGas, overrides.maxVerificationGas, defaults.maxVerificationGas),
    maxFeePerGas: cap(perChain.maxFeePerGas, overrides.maxFeePerGas, defaults.maxFeePerGas),
    maxPriorityFeePerGas: cap(perChain.maxPriorityFeePerGas, overrides.maxPriorityFeePerGas, defaults.maxPriorityFeePerGas),
    allowedTargets: perChain.allowedTargets ?? defaults.allowedTargets,
    allowedPaymasters: perChain.allowedPaymasters ?? defaults.allowedPaymasters,
    // The relay rate limit is SHARED across chains (MC-63) — one window per tenant — so a
    // per-chain value would be meaningless and only the base override applies.
    relayRateLimitPerMinute: overrides.relayRateLimitPerMinute,
  };
}
