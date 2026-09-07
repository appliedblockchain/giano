import {
  backendChainDescriptorSchema,
  defaultChainName,
  gianoAddresses,
  validateChainList,
  type BackendChainDescriptor,
} from '@appliedblockchain/giano-contracts';
import { z } from 'zod';
import { tenantsSeedSchema } from './services/tenants.js';

const addressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'must be a 0x-prefixed 20-byte hex address');

const csv = (value: string) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

/**
 * A chain the deployment serves, with every address resolved. This is what the chain
 * registry is built from: one entry per chain, and NOTHING chain-bound lives outside it.
 */
export type ResolvedChain = {
  chainId: number;
  /** Human-readable — consent screens and operators never see a bare id (MC-81). */
  name: string;
  rpcUrl: string;
  bundlerUrl: string;
  entryPoint: `0x${string}`;
  factory: `0x${string}`;
  sponsorshipPaymaster?: `0x${string}`;
  /**
   * Per-chain policy defaults. Address-valued fields live HERE and only here — the same
   * address denotes different contracts on different chains, so a chain-agnostic address
   * allowlist is not expressible (MC-61).
   */
  policy: {
    maxCallGas?: bigint;
    maxVerificationGas?: bigint;
    maxFeePerGas?: bigint;
    maxPriorityFeePerGas?: bigint;
    /** lowercase; empty = no restriction */
    allowedTargets: string[];
    /** lowercase; empty = no restriction */
    allowedPaymasters: string[];
  };
};

/**
 * Deployment-wide configuration. Everything tenant-specific (RP ID, expected origins,
 * registration mode, admin keys, CORS origins, policy overrides) lives on the tenant
 * rows, provisioned via TENANTS_SEED — see src/services/tenants.ts and
 * specs/DEVELOPER-GUIDE.md §1. The USEROP_* values are defaults a tenant's policy
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

    /**
     * The chains this deployment serves, as a JSON array of chain descriptors (MC-46):
     * `[{ "chainId": 8453, "name": "Base", "rpcUrl": "…", "bundlerUrl": "…" }, …]`.
     * Mutually exclusive with the single-chain scalar shorthand below: supplying both is a
     * configuration ERROR, not a merge — silent precedence between two ways of saying the
     * same thing is how a deployment ends up on a chain nobody chose (§3.4).
     */
    GIANO_CHAINS: z
      .string()
      .optional()
      .transform((raw, ctx) => {
        if (!raw) return undefined;
        let json: unknown;
        try {
          json = JSON.parse(raw);
        } catch (error) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: `not valid JSON: ${(error as Error).message}` });
          return z.NEVER;
        }
        const parsed = z.array(backendChainDescriptorSchema).safeParse(json);
        if (!parsed.success) {
          for (const issue of parsed.error.issues) {
            ctx.addIssue({ code: z.ZodIssueCode.custom, message: `${issue.path.join('.') || '(root)'}: ${issue.message}` });
          }
          return z.NEVER;
        }
        return parsed.data;
      }),

    /**
     * Single-chain shorthand (MC-47, MC-88): the complete configuration for the on-premises
     * profile, normalised internally into a one-entry chain list. An operator serving one
     * chain never needs to know the multi-chain shape exists.
     */
    CHAIN_ID: z.coerce.number().int().positive().optional(),
    RPC_URL: z.string().url().optional(),
    BUNDLER_URL: z.string().url().optional(),
    /** Single-chain shorthand only; defaulted from the contracts address registry for CHAIN_ID. */
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
    const scalarsPresent = env.CHAIN_ID !== undefined || env.RPC_URL !== undefined || env.BUNDLER_URL !== undefined;

    if (env.GIANO_CHAINS && scalarsPresent) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['GIANO_CHAINS'],
        message:
          'GIANO_CHAINS and the CHAIN_ID/RPC_URL/BUNDLER_URL shorthand are mutually exclusive — supply one, not both. ' +
          'Silent precedence between two ways of saying the same thing is how a deployment ends up on a chain nobody chose.',
      });
      return;
    }
    if (!env.GIANO_CHAINS && !scalarsPresent) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['GIANO_CHAINS'],
        message: 'either GIANO_CHAINS (a JSON list of chains) or CHAIN_ID + RPC_URL + BUNDLER_URL must be set',
      });
      return;
    }

    if (env.GIANO_CHAINS) {
      // Address-valued scalars cannot be chain-agnostic (MC-61): in multi-chain mode they
      // belong inside each descriptor, never as deployment-wide environment variables.
      for (const [key, present] of [
        ['ENTRYPOINT_ADDRESS', env.ENTRYPOINT_ADDRESS !== undefined],
        ['FACTORY_ADDRESS', env.FACTORY_ADDRESS !== undefined],
        ['SPONSORSHIP_PAYMASTER_ADDRESS', env.SPONSORSHIP_PAYMASTER_ADDRESS !== undefined],
        ['USEROP_ALLOWED_TARGETS', env.USEROP_ALLOWED_TARGETS.length > 0],
        ['USEROP_ALLOWED_PAYMASTERS', env.USEROP_ALLOWED_PAYMASTERS.length > 0],
      ] as const) {
        if (present) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is single-chain shorthand — with GIANO_CHAINS, set the equivalent field inside each chain descriptor`,
          });
        }
      }

      const { errors } = validateChainList(env.GIANO_CHAINS);
      for (const message of errors) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['GIANO_CHAINS'], message });
      }
      for (const descriptor of env.GIANO_CHAINS) {
        const registry = gianoAddresses[descriptor.chainId];
        if (!descriptor.entryPoint && !registry) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['GIANO_CHAINS'],
            message: `chain ${descriptor.chainId}: entryPoint required — the chain is not in the giano-contracts address registry`,
          });
        }
        if (!descriptor.factory && !registry) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['GIANO_CHAINS'],
            message: `chain ${descriptor.chainId}: factory required — the chain is not in the giano-contracts address registry`,
          });
        }
      }
    } else {
      if (env.CHAIN_ID === undefined || !env.RPC_URL || !env.BUNDLER_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['CHAIN_ID'],
          message: 'the single-chain shorthand needs all of CHAIN_ID, RPC_URL and BUNDLER_URL',
        });
        return;
      }
      const deployment = gianoAddresses[env.CHAIN_ID];
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
    }

    if (env.SPONSORSHIP_ENABLED) {
      const anyPaymaster = env.GIANO_CHAINS
        ? env.GIANO_CHAINS.some((d) => d.sponsorshipPaymaster ?? gianoAddresses[d.chainId]?.sponsorshipPaymaster)
        : Boolean(env.SPONSORSHIP_PAYMASTER_ADDRESS ?? (env.CHAIN_ID !== undefined && gianoAddresses[env.CHAIN_ID]?.sponsorshipPaymaster));
      if (!anyPaymaster) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SPONSORSHIP_PAYMASTER_ADDRESS'],
          message: 'SPONSORSHIP_ENABLED=true but no configured chain resolves a sponsorship paymaster (descriptor field or contracts registry)',
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
  })
  .transform((env) => {
    const toResolved = (descriptor: BackendChainDescriptor): ResolvedChain => {
      const registry = gianoAddresses[descriptor.chainId];
      return {
        chainId: descriptor.chainId,
        name: descriptor.name,
        rpcUrl: descriptor.rpcUrl,
        bundlerUrl: descriptor.bundlerUrl,
        entryPoint: (descriptor.entryPoint ?? registry!.entryPoint) as `0x${string}`,
        factory: (descriptor.factory ?? registry!.factory) as `0x${string}`,
        sponsorshipPaymaster: (descriptor.sponsorshipPaymaster ?? registry?.sponsorshipPaymaster) as `0x${string}` | undefined,
        policy: {
          maxCallGas: descriptor.policy?.maxCallGas ? BigInt(descriptor.policy.maxCallGas) : undefined,
          maxVerificationGas: descriptor.policy?.maxVerificationGas ? BigInt(descriptor.policy.maxVerificationGas) : undefined,
          maxFeePerGas: descriptor.policy?.maxFeePerGas ? BigInt(descriptor.policy.maxFeePerGas) : undefined,
          maxPriorityFeePerGas: descriptor.policy?.maxPriorityFeePerGas ? BigInt(descriptor.policy.maxPriorityFeePerGas) : undefined,
          allowedTargets: (descriptor.policy?.allowedTargets ?? []).map((a) => a.toLowerCase()),
          allowedPaymasters: (descriptor.policy?.allowedPaymasters ?? []).map((a) => a.toLowerCase()),
        },
      };
    };

    // Single-chain scalars normalise into a one-entry list (MC-132): single-chain is the
    // degenerate case of N, not a separate mode.
    const CHAINS: ResolvedChain[] = env.GIANO_CHAINS
      ? env.GIANO_CHAINS.map(toResolved)
      : [
          toResolved({
            chainId: env.CHAIN_ID!,
            name: defaultChainName(env.CHAIN_ID!),
            rpcUrl: env.RPC_URL!,
            bundlerUrl: env.BUNDLER_URL!,
            entryPoint: env.ENTRYPOINT_ADDRESS as `0x${string}` | undefined,
            factory: env.FACTORY_ADDRESS as `0x${string}` | undefined,
            sponsorshipPaymaster: env.SPONSORSHIP_PAYMASTER_ADDRESS as `0x${string}` | undefined,
            policy: {
              allowedTargets: env.USEROP_ALLOWED_TARGETS as `0x${string}`[],
              allowedPaymasters: env.USEROP_ALLOWED_PAYMASTERS as `0x${string}`[],
            },
          }),
        ];

    return { ...env, CHAINS };
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
