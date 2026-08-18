import { createHash } from 'node:crypto';
import { and, eq, notInArray, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { tenantAdminKeys, tenants } from '../db/schema.js';
import type { PolicyConfig } from './userop-policy.js';

/**
 * Tenancy model (specs/DEVELOPER-GUIDE.md §1): tenant ≡ wallet origin ≡ RP ID, 1:1.
 * Tenants are provisioned declaratively at boot via the TENANTS_SEED env var; every
 * write goes through validateTenantSeed so the RP/origin invariant can never be
 * violated in the database.
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

/** Partial per-tenant overrides of the deployment-wide userop policy defaults. */
export const tenantPolicySchema = z
  .object({
    maxCallGas: bigintString.optional(),
    maxVerificationGas: bigintString.optional(),
    maxFeePerGas: bigintString.optional(),
    maxPriorityFeePerGas: bigintString.optional(),
    allowedTargets: addressArray.optional(),
    allowedPaymasters: addressArray.optional(),
    /** Per-tenant override of USEROP_RATE_LIMIT_PER_MINUTE. */
    relayRateLimitPerMinute: z.number().int().positive().optional(),
  })
  .strict();

export type TenantPolicy = z.infer<typeof tenantPolicySchema>;

export const tenantSeedSchema = z
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
    expectedOrigins: z.array(z.string().refine(isBareOrigin, 'must be a bare origin')).default([]),
    allowedDappOrigins: z.array(z.string().refine(isBareOrigin, 'must be a bare origin')).default([]),
    corsOrigins: z.array(z.string().refine(isBareOrigin, 'must be a bare origin')).default([]),
    openRegistration: z.boolean().default(false),
    /** Plaintext admin keys — stored sha256-hashed, never persisted or logged as-is. */
    adminKeys: z.array(z.string().min(16, 'admin keys must be at least 16 characters')).default([]),
    policy: tenantPolicySchema.default({}),
    branding: z.record(z.unknown()).default({}),
  })
  .superRefine((seed, ctx) => {
    const walletHost = new URL(seed.walletOrigin).hostname;
    if (seed.rpId && seed.rpId !== walletHost) {
      // D1: RP_ID must be the wallet host. Registrable-parent RP IDs need the client
      // rpId plumbing first (gap doc §3.2) and are deliberately not offered here.
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['rpId'],
        message: `rpId "${seed.rpId}" must equal the walletOrigin host "${walletHost}"`,
      });
      return;
    }
    const rpId = seed.rpId ?? walletHost;
    // passkeys bind to rp_id irreversibly, so verification-time failures are too late:
    // every ceremony origin's host must equal rp_id or be a subdomain of it
    for (const origin of seed.expectedOrigins) {
      const host = new URL(origin).hostname;
      if (host !== rpId && !host.endsWith(`.${rpId}`)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['expectedOrigins'],
          message: `origin ${origin} is not valid for rpId "${rpId}" — its host must equal the rpId or be a subdomain of it`,
        });
      }
    }
    if (!seed.openRegistration && seed.adminKeys.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['adminKeys'],
        message: 'adminKeys is required when openRegistration is false (something must authorize registration)',
      });
    }
  })
  .transform((seed) => {
    const rpId = seed.rpId ?? new URL(seed.walletOrigin).hostname;
    const expectedOrigins = seed.expectedOrigins.includes(seed.walletOrigin) ? seed.expectedOrigins : [seed.walletOrigin, ...seed.expectedOrigins];
    return { ...seed, rpId, expectedOrigins };
  });

export type TenantSeed = z.infer<typeof tenantSeedSchema>;

export const tenantsSeedSchema = z
  .array(tenantSeedSchema)
  .superRefine((seeds, ctx) => {
    const duplicate = (values: string[], what: string) => {
      const seen = new Set<string>();
      for (const value of values) {
        if (seen.has(value)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: `duplicate ${what} across tenants: ${value}` });
        seen.add(value);
      }
    };
    duplicate(seeds.map((s) => s.slug), 'slug');
    duplicate(seeds.map((s) => s.id).filter((id): id is string => Boolean(id)), 'id');
    duplicate(seeds.map((s) => s.walletOrigin), 'walletOrigin');
    duplicate(seeds.map((s) => s.rpId), 'rpId');
    // a plaintext key shared by two tenants would make key → tenant resolution ambiguous
    duplicate(seeds.flatMap((s) => s.adminKeys), 'admin key');
  });

/** Validates one tenant input through the seed schema; throws with readable messages. */
export function validateTenantSeed(input: unknown): TenantSeed {
  const parsed = tenantSeedSchema.safeParse(input);
  if (!parsed.success) {
    const details = parsed.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`).join('\n');
    throw new Error(`invalid tenant:\n${details}`);
  }
  return parsed.data;
}

/**
 * Idempotent, declarative upsert by slug. rp_id is immutable per tenant (passkeys bind
 * to it) with one documented exception: a row whose rp_id ends in '.invalid' — the
 * migration backfill sentinel — may be claimed and rewritten by a seed entry with the
 * same slug. Admin keys are a replace-set of sha256 hashes.
 */
export async function seedTenants(db: Db, seeds: TenantSeed[]): Promise<void> {
  for (const seed of seeds) {
    await db.transaction(async (tx) => {
      const existing = await tx.query.tenants.findFirst({ where: eq(tenants.slug, seed.slug) });

      const values = {
        walletOrigin: seed.walletOrigin,
        rpId: seed.rpId,
        rpName: seed.rpName,
        expectedOrigins: seed.expectedOrigins,
        allowedDappOrigins: seed.allowedDappOrigins,
        corsOrigins: seed.corsOrigins,
        openRegistration: seed.openRegistration,
        policy: seed.policy,
        branding: seed.branding,
      };

      let tenantId: string;
      if (existing) {
        const claimableSentinel = existing.rpId.endsWith('.invalid');
        if (existing.rpId !== seed.rpId && !claimableSentinel) {
          throw new Error(
            `tenant "${seed.slug}": rp_id is immutable (stored "${existing.rpId}", seed "${seed.rpId}") — ` +
              'passkeys bind to it irreversibly; create a new tenant instead',
          );
        }
        if (seed.id && seed.id !== existing.id) {
          throw new Error(
            `tenant "${seed.slug}": id is immutable (stored "${existing.id}", seed "${seed.id}") — ` +
              'the paymaster keys this tenant\'s gas balance on it, so changing it would orphan those funds',
          );
        }
        await tx
          .update(tenants)
          .set({ ...values, updatedAt: sql`now()` })
          .where(eq(tenants.id, existing.id));
        tenantId = existing.id;
      } else {
        const [inserted] = await tx
          .insert(tenants)
          .values({ slug: seed.slug, ...(seed.id ? { id: seed.id } : {}), ...values })
          .returning({ id: tenants.id });
        tenantId = inserted.id;
      }

      // admin keys: declarative replace-set of hashes for this tenant
      const hashes = seed.adminKeys.map(sha256hex);
      if (hashes.length > 0) {
        await tx
          .insert(tenantAdminKeys)
          .values(hashes.map((keyHash) => ({ tenantId, keyHash })))
          .onConflictDoNothing({ target: tenantAdminKeys.keyHash });
        await tx.delete(tenantAdminKeys).where(and(eq(tenantAdminKeys.tenantId, tenantId), notInArray(tenantAdminKeys.keyHash, hashes)));
      } else {
        await tx.delete(tenantAdminKeys).where(eq(tenantAdminKeys.tenantId, tenantId));
      }
    });
  }
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

export function createTenantService(db: Db) {
  return {
    async getById(id: string): Promise<Tenant | null> {
      return (await db.query.tenants.findFirst({ where: eq(tenants.id, id) })) ?? null;
    },

    /** Resolves a browser Origin header: exact wallet_origin or expected_origins member. */
    async getByOrigin(origin: string): Promise<Tenant | null> {
      const row = await db.query.tenants.findFirst({
        where: sql`${tenants.walletOrigin} = ${origin} OR ${origin} = ANY(${tenants.expectedOrigins})`,
      });
      return row ?? null;
    },

    /** Resolves a Host header (may carry a port) by rp_id. */
    async getByHost(hostHeader: string): Promise<Tenant | null> {
      const hostname = hostHeaderToHostname(hostHeader);
      if (!hostname) return null;
      return (await db.query.tenants.findFirst({ where: eq(tenants.rpId, hostname) })) ?? null;
    },

    /** Resolves an admin key hash to its tenant (O(1) unique-index lookup). */
    async getByAdminKeyHash(keyHash: string): Promise<{ tenant: Tenant; keyHash: string } | null> {
      const [row] = await db
        .select({ tenant: tenants, keyHash: tenantAdminKeys.keyHash })
        .from(tenantAdminKeys)
        .innerJoin(tenants, eq(tenantAdminKeys.tenantId, tenants.id))
        .where(eq(tenantAdminKeys.keyHash, keyHash))
        .limit(1);
      return row ?? null;
    },

    /** CORS delegate lookup: any tenant's cors_origins (or wallet origin itself). */
    async isCorsOrigin(origin: string): Promise<boolean> {
      const row = await db.query.tenants.findFirst({
        where: sql`${tenants.walletOrigin} = ${origin} OR ${origin} = ANY(${tenants.corsOrigins})`,
      });
      return !!row;
    },
  };
}

/** Per-request policy: tenant jsonb overrides (already validated at seed time) over env defaults. */
export function mergePolicy(defaults: PolicyConfig, tenantPolicy: unknown): PolicyConfig & { relayRateLimitPerMinute?: number } {
  const parsed = tenantPolicySchema.safeParse(tenantPolicy ?? {});
  // fail safe: an unparseable stored policy falls back to the deployment defaults
  const overrides = parsed.success ? parsed.data : {};
  return {
    maxCallGas: overrides.maxCallGas ? BigInt(overrides.maxCallGas) : defaults.maxCallGas,
    maxVerificationGas: overrides.maxVerificationGas ? BigInt(overrides.maxVerificationGas) : defaults.maxVerificationGas,
    maxFeePerGas: overrides.maxFeePerGas ? BigInt(overrides.maxFeePerGas) : defaults.maxFeePerGas,
    maxPriorityFeePerGas: overrides.maxPriorityFeePerGas ? BigInt(overrides.maxPriorityFeePerGas) : defaults.maxPriorityFeePerGas,
    allowedTargets: overrides.allowedTargets ?? defaults.allowedTargets,
    allowedPaymasters: overrides.allowedPaymasters ?? defaults.allowedPaymasters,
    relayRateLimitPerMinute: overrides.relayRateLimitPerMinute,
  };
}
