import { gianoAddresses } from '@appliedblockchain/giano-contracts';
import { z } from 'zod';
import { tenantsSeedSchema } from './services/tenants.js';

const addressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'must be a 0x-prefixed 20-byte hex address');

const csv = (value: string) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

/**
 * Deployment-wide configuration. Everything tenant-specific (RP ID, expected origins,
 * registration mode, admin keys, CORS origins, policy overrides) lives on the tenant
 * rows, provisioned via TENANTS_SEED — see src/services/tenants.ts and
 * docs/MULTI-TENANCY-GAPS.md. The USEROP_* values are defaults a tenant's policy
 * jsonb may override per field.
 */
const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('production'),
    /**
     * What kind of deployment this is, as distinct from how the process was built.
     *
     * `NODE_ENV` cannot answer this question. A testnet deployment legitimately runs as a
     * production build, and testnet is where an environment-variable signing key is acceptable —
     * so gating the signer on `NODE_ENV` would refuse a configuration that is intended. Stated
     * rather than defaulted on purpose: a default that happens to be permissive is exactly how an
     * env-var key reaches production.
     */
    GIANO_DEPLOYMENT_CLASS: z.enum(['development', 'testnet', 'production']),
    HOST: z.string().default('0.0.0.0'),
    PORT: z.coerce.number().int().min(1).max(65535).default(8080),
    LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),

    DATABASE_URL: z.string().url(),
    /** When "true", src/index.ts applies pending migrations before listening. */
    RUN_MIGRATIONS: z
      .enum(['true', 'false'])
      .default('false')
      .transform((v) => v === 'true'),

    /**
     * JSON array of tenants, upserted by slug at boot (after migrations, before listen).
     * Each entry: { slug, walletOrigin, rpId?, rpName, expectedOrigins?, allowedDappOrigins?,
     * corsOrigins?, openRegistration?, adminKeys?, policy?, branding? }.
     */
    TENANTS_SEED: z
      .string()
      .optional()
      .transform((raw, ctx) => {
        if (!raw) return [];
        let json: unknown;
        try {
          json = JSON.parse(raw);
        } catch (error) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: `not valid JSON: ${(error as Error).message}` });
          return z.NEVER;
        }
        const parsed = tenantsSeedSchema.safeParse(json);
        if (!parsed.success) {
          for (const issue of parsed.error.issues) {
            ctx.addIssue({ code: z.ZodIssueCode.custom, message: `${issue.path.join('.') || '(root)'}: ${issue.message}` });
          }
          return z.NEVER;
        }
        return parsed.data;
      }),

    CHAIN_ID: z.coerce.number().int().positive(),
    RPC_URL: z.string().url(),
    BUNDLER_URL: z.string().url(),
    /** Defaulted from the contracts address registry for CHAIN_ID when unset. */
    ENTRYPOINT_ADDRESS: addressSchema.optional(),
    FACTORY_ADDRESS: addressSchema.optional(),

    CHALLENGE_TTL_SECONDS: z.coerce.number().int().positive().default(300),
    SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(86400),

    /** UserOp policy caps — deployment defaults, overridable per tenant via policy jsonb. */
    USEROP_MAX_CALL_GAS: z.coerce.bigint().positive().default(5_000_000n),
    USEROP_MAX_VERIFICATION_GAS: z.coerce.bigint().positive().default(5_000_000n),
    USEROP_MAX_FEE_PER_GAS: z.coerce.bigint().positive().default(500_000_000_000n),
    USEROP_MAX_PRIORITY_FEE_PER_GAS: z.coerce.bigint().positive().default(500_000_000_000n),
    /** Comma-separated addresses; empty/unset = any target allowed. */
    USEROP_ALLOWED_TARGETS: z.string().optional().transform((v) => (v ? csv(v).map((a) => a.toLowerCase()) : [])),
    /** Comma-separated addresses; empty/unset = any paymaster allowed. */
    USEROP_ALLOWED_PAYMASTERS: z.string().optional().transform((v) => (v ? csv(v).map((a) => a.toLowerCase()) : [])),

    // ── Gas sponsorship ─────────────────────────────────────────────────────────────
    //
    // The paymaster's own configuration — the fee, the overhead allowance, the penalty rate, the
    // signer set, the pause state and tenant registration — is deliberately NOT here. It is
    // on-chain state, changed through the contract's roles, which is what makes it auditable by
    // a tenant rather than something they have to take Giano's word for.

    /** Deployment-wide master switch. Off means the sponsorship routes 404 and nothing is signed. */
    SPONSORSHIP_ENABLED: z
      .enum(['true', 'false'])
      .default('false')
      .transform((v) => v === 'true'),
    /** The production sponsorship paymaster. Defaults from the contracts registry for known chains. */
    SPONSORSHIP_PAYMASTER_ADDRESS: addressSchema.optional(),
    /**
     * Where the signing key lives. `hsm` asks a hardware-backed key service for each signature and
     * never sees the key; `local` holds it in this process and is refused outright for a production
     * deployment, because this key authorises spending against customer funds and an environment
     * variable is the worst blast radius of the available options.
     */
    SPONSORSHIP_SIGNER_KIND: z.enum(['hsm', 'local']).default('local'),
    /** The HSM key resource name, or — for `local` only — a 32-byte hex private key. */
    SPONSORSHIP_SIGNER_KEY_REF: z.string().optional(),
    /**
     * The platform's cap on a single wallet-management operation, in wei.
     *
     * Wallet management is sponsored whatever a tenant's allowlist says, so the tenant cannot be
     * the only thing bounding it — this is the bound on the one spend path a tenant cannot close.
     * Deliberately tight: adding a passkey is a small, predictable operation. A tenant may lower
     * this figure for itself and never raise it.
     */
    SPONSORSHIP_WALLET_MANAGEMENT_CAP_WEI: z.coerce.bigint().positive().default(2_000_000_000_000_000n),
    /** `validUntil` window. Minutes, not hours: an authorisation commits real money. */
    SPONSORSHIP_VALIDITY_SECONDS: z.coerce.number().int().positive().max(1800).default(180),
    /**
     * Reservation lifetime. Must exceed the validity window, so an operation can never still be
     * valid on-chain after its reservation has been swept back.
     */
    SPONSORSHIP_RESERVATION_TTL_SECONDS: z.coerce.number().int().positive().default(300),
    /** Per-tenant sponsorship request limit. Its own budget, so pre-flight traffic cannot hammer the signer. */
    SPONSORSHIP_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().default(120),
    /**
     * Stops issuance immediately without a restart — the first response to a suspected key
     * compromise. `pause()` on the contract is the second, stronger lever, which stops even a
     * leaked key from being useful.
     */
    SPONSORSHIP_EMERGENCY_STOP: z
      .enum(['true', 'false'])
      .default('false')
      .transform((v) => v === 'true'),

    /** Chain watcher: ingests paymaster events, settles reservations, reconciles the ledger. */
    PAYMASTER_WATCHER_ENABLED: z
      .enum(['true', 'false'])
      .default('false')
      .transform((v) => v === 'true'),
    PAYMASTER_WATCHER_POLL_MS: z.coerce.number().int().positive().default(4000),
    PAYMASTER_WATCHER_CONFIRMATIONS: z.coerce.number().int().nonnegative().default(1),
    /** How often the accounting invariant and the deposit drawdown are checked. */
    PAYMASTER_RECONCILE_INTERVAL_MS: z.coerce.number().int().positive().default(60_000),
    /** Low-balance alert threshold for tenants that set none of their own, in wei. */
    PAYMASTER_LOW_BALANCE_DEFAULT_WEI: z.coerce.bigint().nonnegative().default(10_000_000_000_000_000n),

    /** Rate limit for ceremony endpoints, requests per minute per tenant+IP. */
    CEREMONY_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().default(30),
    /** Relay rate limit for POST /v1/userops, per tenant per minute (policy-overridable). */
    USEROP_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().default(60),

    /** When set (non-empty), GET /metrics requires this bearer token; unset = open (dev only). */
    METRICS_BEARER_TOKEN: z
      .string()
      .optional()
      .transform((v) => (v ? v : undefined))
      .refine((v) => v === undefined || v.length >= 16, 'must be at least 16 characters'),
  })
  .superRefine((env, ctx) => {
    const deployment = gianoAddresses[env.CHAIN_ID];

    if (env.SPONSORSHIP_ENABLED) {
      if (!env.SPONSORSHIP_PAYMASTER_ADDRESS && !deployment?.sponsorshipPaymaster) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SPONSORSHIP_PAYMASTER_ADDRESS'],
          message: `required: chain ${env.CHAIN_ID} has no sponsorship paymaster in the contracts registry`,
        });
      }
      if (!env.SPONSORSHIP_SIGNER_KEY_REF) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SPONSORSHIP_SIGNER_KEY_REF'],
          message: 'required when SPONSORSHIP_ENABLED=true',
        });
      }
      // The key that authorises spending customer funds must not sit in this process where the
      // funds are real, and refusing to boot is the only enforcement that cannot be forgotten.
      //
      // Gated on the deployment's class rather than on NODE_ENV: development and testnet may hold
      // the key locally (on testnet the balances are worthless, and it is what lets the demo stack
      // provision itself without a credential), and both of those can run as a production build.
      if (env.SPONSORSHIP_SIGNER_KIND === 'local' && env.GIANO_DEPLOYMENT_CLASS === 'production') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SPONSORSHIP_SIGNER_KIND'],
          message:
            'must be "hsm" when GIANO_DEPLOYMENT_CLASS=production — a local key authorising spend against ' +
            'customer funds has the worst blast radius of the available options',
        });
      }
      if (env.SPONSORSHIP_SIGNER_KIND === 'local' && !/^0x[0-9a-fA-F]{64}$/.test(env.SPONSORSHIP_SIGNER_KEY_REF ?? '')) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SPONSORSHIP_SIGNER_KEY_REF'],
          message: 'must be a 32-byte hex private key when SPONSORSHIP_SIGNER_KIND=local',
        });
      }
      if (env.SPONSORSHIP_RESERVATION_TTL_SECONDS <= env.SPONSORSHIP_VALIDITY_SECONDS) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SPONSORSHIP_RESERVATION_TTL_SECONDS'],
          message:
            `must exceed SPONSORSHIP_VALIDITY_SECONDS (${env.SPONSORSHIP_VALIDITY_SECONDS}) — otherwise a reservation ` +
            'can be swept back while its authorisation is still valid on-chain, and the balance it was protecting ' +
            'gets spent twice',
        });
      }
    }
    if (!env.ENTRYPOINT_ADDRESS && !deployment) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ENTRYPOINT_ADDRESS'],
        message: `required: chain ${env.CHAIN_ID} is not in the giano-contracts address registry`,
      });
    }
    if (!env.FACTORY_ADDRESS && !deployment) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['FACTORY_ADDRESS'],
        message: `required: chain ${env.CHAIN_ID} is not in the giano-contracts address registry`,
      });
    }
  })
  .transform((env) => {
    const deployment = gianoAddresses[env.CHAIN_ID];
    return {
      ...env,
      ENTRYPOINT_ADDRESS: (env.ENTRYPOINT_ADDRESS ?? deployment!.entryPoint) as `0x${string}`,
      FACTORY_ADDRESS: (env.FACTORY_ADDRESS ?? deployment!.factory) as `0x${string}`,
      SPONSORSHIP_PAYMASTER_ADDRESS: (env.SPONSORSHIP_PAYMASTER_ADDRESS ?? deployment?.sponsorshipPaymaster) as
        | `0x${string}`
        | undefined,
    };
  });

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    const details = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid environment configuration:\n${details}`);
  }
  return parsed.data;
}
