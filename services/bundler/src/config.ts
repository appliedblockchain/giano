import { getAddress, isAddress, isHex, type Address, type Hex } from 'viem';
import { privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import { z } from 'zod';

/** The well-known Anvil account 0 key — never legitimate outside a devnet. */
export const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
export const DEFAULT_ENTRYPOINT: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

export class ConfigError extends Error {}

export type ChainType = 'default' | 'op-stack';

export type BundlerConfig = {
  rpcUrl: string;
  entryPoint: Address;
  executors: PrivateKeyAccount[];
  port: number;
  host: string;
  /** Where to look for an operation's UserOperationEvent when this process did not submit it. */
  maxBlockRange: bigint;
  /** 'auto' resolves at boot: OP-stack when the GasPriceOracle predeploy has code. */
  chainType: ChainType | 'auto';
  /** How long a submission may sit unmined before it is re-priced. */
  resubmitTimeoutMs: number;
  /** Re-pricings before the nonce is cancelled and the operation given up. */
  maxReplacements: number;
  pollIntervalMs: number;
  logLevel: string;
  warnings: string[];
};

/**
 * The Alto variable each setting used to be read from. Accepted so a deployment that still
 * carries them (an existing k8s secret, an ECS task definition mid-rollout) boots unchanged;
 * the BUNDLER_* name wins when both are set.
 */
const ALIASES = {
  BUNDLER_RPC_URL: 'ALTO_RPC_URL',
  BUNDLER_EXECUTOR_PRIVATE_KEYS: 'ALTO_EXECUTOR_PRIVATE_KEYS',
  BUNDLER_ENTRYPOINT: 'ALTO_ENTRYPOINTS',
  BUNDLER_PORT: 'ALTO_PORT',
} as const;

/** Alto options with no counterpart here: ignored, with a warning, rather than refused. */
const IGNORED = {
  ALTO_SAFE_MODE: 'there is no ERC-7562 tracer; every operation is simulated against the EntryPoint before it is sent',
  ALTO_UTILITY_PRIVATE_KEY: 'nothing is deployed at boot and executors are not refilled, so there is no utility account',
} as const;

const positiveInt = (name: string) =>
  z.coerce.number({ invalid_type_error: `${name} must be a number` }).int().positive(`${name} must be a positive integer`);

const schema = z.object({
  BUNDLER_RPC_URL: z.string({ required_error: 'BUNDLER_RPC_URL is required' }).url('BUNDLER_RPC_URL must be a URL'),
  BUNDLER_EXECUTOR_PRIVATE_KEYS: z.string({
    required_error: 'BUNDLER_EXECUTOR_PRIVATE_KEYS is required (executor keys sign the handleOps transactions)',
  }),
  BUNDLER_ENTRYPOINT: z.string().optional(),
  BUNDLER_PORT: positiveInt('BUNDLER_PORT').default(4337),
  BUNDLER_HOST: z.string().default('0.0.0.0'),
  BUNDLER_MAX_BLOCK_RANGE: positiveInt('BUNDLER_MAX_BLOCK_RANGE').default(2000),
  BUNDLER_CHAIN_TYPE: z.enum(['auto', 'default', 'op-stack']).default('auto'),
  BUNDLER_RESUBMIT_TIMEOUT_SECONDS: positiveInt('BUNDLER_RESUBMIT_TIMEOUT_SECONDS').default(30),
  BUNDLER_MAX_REPLACEMENTS: z.coerce.number().int().min(0).default(3),
  BUNDLER_POLL_INTERVAL_MS: positiveInt('BUNDLER_POLL_INTERVAL_MS').default(1000),
  BUNDLER_LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  GIANO_DEV_MODE: z.string().default('false'),
});

export function loadConfig(env: Record<string, string | undefined> = process.env): BundlerConfig {
  const warnings: string[] = [];
  const resolved: Record<string, string | undefined> = { ...env };
  for (const [name, legacy] of Object.entries(ALIASES)) {
    if (resolved[name] === undefined && env[legacy] !== undefined) {
      resolved[name] = env[legacy];
      warnings.push(`${legacy} is deprecated, read as ${name}`);
    }
  }
  for (const [name, why] of Object.entries(IGNORED)) {
    if (env[name] !== undefined) warnings.push(`${name} is ignored: ${why}`);
  }
  // Empty strings are what an unset compose/helm interpolation produces: treat them as unset.
  for (const key of Object.keys(resolved)) if (resolved[key] === '') delete resolved[key];

  const parsed = schema.safeParse(resolved);
  if (!parsed.success) {
    throw new ConfigError(`FATAL: ${parsed.error.issues.map((issue) => issue.message).join('; ')}`);
  }
  const values = parsed.data;

  const keys = values.BUNDLER_EXECUTOR_PRIVATE_KEYS.split(',').map((key) => key.trim()).filter(Boolean);
  if (keys.length === 0) throw new ConfigError('FATAL: BUNDLER_EXECUTOR_PRIVATE_KEYS is empty');
  for (const key of keys) {
    if (!isHex(key) || key.length !== 66) throw new ConfigError('FATAL: every executor key must be a 32-byte 0x-prefixed hex string');
  }
  if (new Set(keys.map((key) => key.toLowerCase())).size !== keys.length) {
    throw new ConfigError('FATAL: BUNDLER_EXECUTOR_PRIVATE_KEYS lists the same key twice');
  }

  if (keys.some((key) => key.toLowerCase() === ANVIL_KEY)) {
    if (values.GIANO_DEV_MODE !== 'true') {
      throw new ConfigError(
        'FATAL: refusing to start with the well-known Anvil key outside dev mode (set GIANO_DEV_MODE=true for local devnets only)',
      );
    }
    warnings.push('running with the well-known Anvil key (GIANO_DEV_MODE=true) — never do this against a real chain');
  }

  return {
    rpcUrl: values.BUNDLER_RPC_URL,
    entryPoint: parseEntryPoint(values.BUNDLER_ENTRYPOINT),
    executors: keys.map((key) => privateKeyToAccount(key as Hex)),
    port: values.BUNDLER_PORT,
    host: values.BUNDLER_HOST,
    maxBlockRange: BigInt(values.BUNDLER_MAX_BLOCK_RANGE),
    chainType: values.BUNDLER_CHAIN_TYPE,
    resubmitTimeoutMs: values.BUNDLER_RESUBMIT_TIMEOUT_SECONDS * 1000,
    maxReplacements: values.BUNDLER_MAX_REPLACEMENTS,
    pollIntervalMs: values.BUNDLER_POLL_INTERVAL_MS,
    logLevel: values.BUNDLER_LOG_LEVEL,
    warnings,
  };
}

/** One EntryPoint, v0.7. Alto took a comma-separated list; a list of one is still accepted. */
function parseEntryPoint(value: string | undefined): Address {
  if (value === undefined) return DEFAULT_ENTRYPOINT;
  const entries = value.split(',').map((entry) => entry.trim()).filter(Boolean);
  if (entries.length !== 1) throw new ConfigError('FATAL: BUNDLER_ENTRYPOINT takes exactly one EntryPoint v0.7 address');
  if (!isAddress(entries[0], { strict: false })) throw new ConfigError(`FATAL: BUNDLER_ENTRYPOINT is not an address: ${entries[0]}`);
  return getAddress(entries[0]);
}
