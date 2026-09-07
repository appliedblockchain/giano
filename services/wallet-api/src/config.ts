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
