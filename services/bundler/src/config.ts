import { bundlerChainSchema, gianoAddresses, validateChainList } from '@appliedblockchain/giano-contracts';
import { getAddress, isHex, type Address, type Hex } from 'viem';
import { privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import { z } from 'zod';

/** The well-known Anvil account 0 key — never legitimate outside a devnet. */
export const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
export const DEFAULT_ENTRYPOINT: Address = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

export class ConfigError extends Error {}

export type ChainType = 'default' | 'op-stack';

/** One chain this process serves, resolved from its GIANO_CHAINS entry. */
export type ChainConfig = {
  chainId: number;
  name: string;
  /** The entry's `bundler.rpcUrl`, else its shared `rpcUrl`. */
  rpcUrl: string;
  entryPoint: Address;
  /** 'auto' resolves when the chain connects: OP-stack when the GasPriceOracle predeploy has code. */
  chainType: ChainType | 'auto';
  /** Where to look for an operation's UserOperationEvent when this process did not submit it. */
  maxBlockRange: bigint;
};

export type BundlerConfig = {
  chains: ChainConfig[];
  /** One lane per key on every chain: nonces are per chain, so a key is safely shared across them. */
  executors: PrivateKeyAccount[];
  port: number;
  host: string;
  /** How long a submission may sit unmined before it is re-priced. */
  resubmitTimeoutMs: number;
  /** Re-pricings before the nonce is cancelled and the operation given up. */
  maxReplacements: number;
  pollIntervalMs: number;
  logLevel: string;
  warnings: string[];
};

/**
 * Single-chain settings from before GIANO_CHAINS. Refused rather than ignored: a deployment still
 * carrying them was configured for a bundler that no longer exists, and should say so at boot.
 */
const RETIRED = [
  'BUNDLER_RPC_URL',
  'BUNDLER_ENTRYPOINT',
  'BUNDLER_CHAIN_TYPE',
  'BUNDLER_MAX_BLOCK_RANGE',
  'ALTO_RPC_URL',
  'ALTO_EXECUTOR_PRIVATE_KEYS',
  'ALTO_ENTRYPOINTS',
  'ALTO_PORT',
  'ALTO_SAFE_MODE',
  'ALTO_UTILITY_PRIVATE_KEY',
] as const;

const positiveInt = (name: string) =>
  z.coerce.number({ invalid_type_error: `${name} must be a number` }).int().positive(`${name} must be a positive integer`);

const schema = z.object({
  GIANO_CHAINS: z.string({
    required_error: 'GIANO_CHAINS is required (the backend chain document wallet-api reads too, see packages/contracts/chains.ts)',
  }),
  BUNDLER_EXECUTOR_PRIVATE_KEYS: z.string({
    required_error: 'BUNDLER_EXECUTOR_PRIVATE_KEYS is required (executor keys sign the handleOps transactions)',
  }),
  BUNDLER_PORT: positiveInt('BUNDLER_PORT').default(4337),
  BUNDLER_HOST: z.string().default('0.0.0.0'),
  BUNDLER_RESUBMIT_TIMEOUT_SECONDS: positiveInt('BUNDLER_RESUBMIT_TIMEOUT_SECONDS').default(30),
  BUNDLER_MAX_REPLACEMENTS: z.coerce.number().int().min(0).default(3),
  BUNDLER_POLL_INTERVAL_MS: positiveInt('BUNDLER_POLL_INTERVAL_MS').default(1000),
  BUNDLER_LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  GIANO_DEV_MODE: z.string().default('false'),
});

export function loadConfig(env: Record<string, string | undefined> = process.env): BundlerConfig {
  const warnings: string[] = [];
  const resolved: Record<string, string | undefined> = { ...env };
  // Empty strings are what an unset compose/helm interpolation produces: treat them as unset.
  for (const key of Object.keys(resolved)) if (resolved[key] === '') delete resolved[key];

  const retired = RETIRED.filter((name) => resolved[name] !== undefined);
  if (retired.length > 0) {
    throw new ConfigError(
      `FATAL: no longer read: ${retired.join(', ')} — chains are configured by GIANO_CHAINS and executors by BUNDLER_EXECUTOR_PRIVATE_KEYS`,
    );
  }

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
    chains: parseChains(values.GIANO_CHAINS),
    executors: keys.map((key) => privateKeyToAccount(key as Hex)),
    port: values.BUNDLER_PORT,
    host: values.BUNDLER_HOST,
    resubmitTimeoutMs: values.BUNDLER_RESUBMIT_TIMEOUT_SECONDS * 1000,
    maxReplacements: values.BUNDLER_MAX_REPLACEMENTS,
    pollIntervalMs: values.BUNDLER_POLL_INTERVAL_MS,
    logLevel: values.BUNDLER_LOG_LEVEL,
    warnings,
  };
}

/** The chains to serve: every GIANO_CHAINS entry whose `bundler.enabled` is not false. */
function parseChains(raw: string): ChainConfig[] {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (error) {
    throw new ConfigError(`FATAL: GIANO_CHAINS is not valid JSON: ${(error as Error).message}`);
  }
  const parsed = z.array(bundlerChainSchema).safeParse(json);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`);
    throw new ConfigError(`FATAL: GIANO_CHAINS: ${issues.join('; ')}`);
  }
  const { errors } = validateChainList(parsed.data);
  if (errors.length > 0) throw new ConfigError(`FATAL: GIANO_CHAINS: ${errors.join('; ')}`);

  const chains = parsed.data
    .filter((entry) => entry.bundler.enabled)
    .map((entry) => ({
      chainId: entry.chainId,
      name: entry.name,
      rpcUrl: entry.bundler.rpcUrl ?? entry.rpcUrl,
      entryPoint: getAddress(entry.entryPoint ?? gianoAddresses[entry.chainId]?.entryPoint ?? DEFAULT_ENTRYPOINT),
      chainType: entry.bundler.chainType,
      maxBlockRange: BigInt(entry.bundler.maxBlockRange),
    }));
  if (chains.length === 0) throw new ConfigError('FATAL: GIANO_CHAINS enables no chain for this bundler (every entry has bundler.enabled false)');
  return chains;
}
