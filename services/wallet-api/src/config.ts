import { gianoAddresses } from '@appliedblockchain/giano-contracts';
import { z } from 'zod';

const addressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/, 'must be a 0x-prefixed 20-byte hex address');

const csv = (value: string) =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

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

    /** WebAuthn Relying Party ID — the registrable domain the passkeys are bound to. Irreversible per deployment. */
    RP_ID: z.string().min(1),
    RP_NAME: z.string().min(1).default('Giano Wallet'),
    /** Comma-separated web origins accepted in ceremony verification, e.g. https://wallet.example.com */
    EXPECTED_ORIGINS: z.string().min(1).transform(csv),

    CHAIN_ID: z.coerce.number().int().positive(),
    RPC_URL: z.string().url(),
    BUNDLER_URL: z.string().url(),
    /** Defaulted from the contracts address registry for CHAIN_ID when unset. */
    ENTRYPOINT_ADDRESS: addressSchema.optional(),
    FACTORY_ADDRESS: addressSchema.optional(),

    CHALLENGE_TTL_SECONDS: z.coerce.number().int().positive().default(300),
    SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(86400),

    /** UserOp policy caps. Gas values are plain integers (wei for fees). */
    USEROP_MAX_CALL_GAS: z.coerce.bigint().positive().default(5_000_000n),
    USEROP_MAX_VERIFICATION_GAS: z.coerce.bigint().positive().default(5_000_000n),
    USEROP_MAX_FEE_PER_GAS: z.coerce.bigint().positive().default(500_000_000_000n),
    USEROP_MAX_PRIORITY_FEE_PER_GAS: z.coerce.bigint().positive().default(500_000_000_000n),
    /** Comma-separated addresses; empty/unset = any target allowed. */
    USEROP_ALLOWED_TARGETS: z.string().optional().transform((v) => (v ? csv(v).map((a) => a.toLowerCase()) : [])),
    /** Comma-separated addresses; empty/unset = any paymaster allowed. */
    USEROP_ALLOWED_PAYMASTERS: z.string().optional().transform((v) => (v ? csv(v).map((a) => a.toLowerCase()) : [])),

    /**
     * When false (default), /v1/webauthn/options for unknown users requires an admin key —
     * production binds registration to the client project's own auth (server-to-server).
     * True is for demos only.
     */
    OPEN_REGISTRATION: z
      .enum(['true', 'false'])
      .default('false')
      .transform((v) => v === 'true'),
    /** Comma-separated bearer keys accepted on admin endpoints. */
    ADMIN_API_KEYS: z.string().optional().transform((v) => (v ? csv(v) : [])),

    /** Comma-separated origins allowed by CORS (the wallet-web/demo origins). */
    CORS_ORIGINS: z.string().optional().transform((v) => (v ? csv(v) : [])),

    /** Rate limit for ceremony endpoints, requests per minute per IP. */
    CEREMONY_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().positive().default(30),
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
    if (!env.OPEN_REGISTRATION && env.ADMIN_API_KEYS.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ADMIN_API_KEYS'],
        message: 'required unless OPEN_REGISTRATION=true: registration options are admin-gated',
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
