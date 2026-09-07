import { gianoAddresses } from '@appliedblockchain/giano-contracts';

/** One chain this wallet origin serves — everything needed to serve it (MC-40). */
export type WalletChainConfig = {
  chainId: number;
  /** Human-readable — consent screens name the chain, never a bare id (MC-80, MC-81). */
  name: string;
  rpcUrl: string;
  bundlerUrl: string;
  factoryAddress: `0x${string}`;
  /**
   * How gas is sponsored on this chain:
   *   'service'        — the production paymaster, through the ERC-7677 sponsorship service
   *   'test-paymaster' — the permissive paymaster (local development and tests only)
   *   'off'            — no sponsorship; the wallet behaves exactly as the unsponsored path does
   */
  sponsorship: 'service' | 'test-paymaster' | 'off';
  /** ERC-7677 sponsorship service; defaults to `${walletApiUrl}/v1/paymaster`. */
  paymasterServiceUrl: string;
  /** Permissive testing paymaster. Only ever used when `sponsorship` is 'test-paymaster'. */
  testPaymasterAddress?: `0x${string}`;
};

export type WalletConfig = {
  /** The closed list of chains this wallet origin serves (MC-39). Never empty. */
  chains: WalletChainConfig[];
  /** Base URL of the wallet-api; '/api' when proxied same-origin. */
  walletApiUrl: string;
  /** dApp origins allowed to connect; empty = NONE (fail closed). Use ["*"] for local dev only. */
  allowedDappOrigins: string[];
  /** The WebAuthn relying-party id — the wallet origin's hostname. */
  rpId: string;
  branding: { name: string; logoUrl?: string };
};

/** Raw config: either a `chains` array, or the single-chain top-level shorthand. */
export type RawChainEntry = {
  chainId?: number;
  name?: string;
  rpcUrl?: string;
  bundlerUrl?: string;
  factoryAddress?: `0x${string}`;
  sponsorship?: unknown;
  paymasterServiceUrl?: string;
  testPaymasterAddress?: `0x${string}`;
};

export type RawWalletConfig = RawChainEntry & {
  chains?: RawChainEntry[];
  walletApiUrl?: string;
  allowedDappOrigins?: string[];
  rpId?: string;
  branding?: { name: string; logoUrl?: string };
  allowTestPaymaster?: boolean;
};

export type ResolveWalletConfigOptions = {
  raw: RawWalletConfig;
  /**
   * Whether this is a production build. The kit cannot know (it is bundler-agnostic), so the
   * host says — the stock wallet passes `import.meta.env.PROD`. When true, selecting the
   * permissive test paymaster is a fatal configuration error unless the raw config opts in
   * with `allowTestPaymaster: true` (WK-05, R-29).
   */
  production?: boolean;
  /** Default rpId when the raw config names none; defaults to the current hostname. */
  defaultRpId?: string;
};

const KNOWN_CHAIN_NAMES: Record<number, string> = {
  1: 'Ethereum',
  10: 'OP Mainnet',
  8453: 'Base',
  84532: 'Base Sepolia',
  11155111: 'Sepolia',
  31337: 'Local devnet A',
  31338: 'Local devnet B',
};

/**
 * Validates and normalises a raw wallet configuration (WK-06): failures are fatal and name
 * the chain and the field (MC-42). Both the multi-chain `chains` list and the single-chain
 * top-level shorthand are accepted (MC-88); supplying both is an error, not a merge.
 */
export function resolveWalletConfig({ raw, production = false, defaultRpId }: ResolveWalletConfigOptions): WalletConfig {
  const hasScalar = raw.chainId !== undefined || raw.rpcUrl !== undefined || raw.bundlerUrl !== undefined;
  if (raw.chains && hasScalar) {
    throw new Error('wallet config: `chains` and the top-level chainId/rpcUrl/bundlerUrl shorthand are mutually exclusive');
  }
  const rawChains: RawChainEntry[] = raw.chains ?? [raw];
  if (rawChains.length === 0) {
    throw new Error('wallet config: `chains` must list at least one chain');
  }

  const walletApiUrl = raw.walletApiUrl || '/api';
  const seenIds = new Set<number>();
  const chains = rawChains.map((entry) => resolveChain(entry, raw, walletApiUrl, seenIds, production));

  return {
    chains,
    walletApiUrl,
    allowedDappOrigins: raw.allowedDappOrigins ?? [],
    rpId: raw.rpId || defaultRpId || globalThis.location?.hostname || '',
    branding: raw.branding ?? { name: 'Giano Wallet' },
  };
}

/** Validates one chain entry; failures are fatal and name the chain and the field (MC-42). */
function resolveChain(entry: RawChainEntry, raw: RawWalletConfig, walletApiUrl: string, seenIds: Set<number>, production: boolean): WalletChainConfig {
  if (!entry.chainId || !entry.rpcUrl || !entry.bundlerUrl) {
    throw new Error(`wallet config: every chain must set chainId, rpcUrl and bundlerUrl (chain ${entry.chainId ?? '?'})`);
  }
  if (seenIds.has(entry.chainId)) {
    throw new Error(`wallet config: duplicate chainId ${entry.chainId}`);
  }
  seenIds.add(entry.chainId);

  const registry = gianoAddresses[entry.chainId];
  const factoryAddress = entry.factoryAddress || registry?.factory;
  if (!factoryAddress) {
    throw new Error(`wallet config: factoryAddress required — chain ${entry.chainId} is not in the contracts registry`);
  }
  const testPaymasterAddress = entry.testPaymasterAddress || registry?.testPaymaster;
  const sponsorship = resolveSponsorshipMode(entry, testPaymasterAddress);

  // R-29 layer 3, applied PER CHAIN: the permissive paymaster approves everything; one
  // misconfigured chain in a list is exactly the case the guard exists for. A production
  // build that quietly picked it up would sponsor without rules, without a balance and
  // without a fee. Refusing to load is the only behaviour that cannot be mistaken for
  // working (WK-05).
  if (sponsorship === 'test-paymaster' && production && !raw.allowTestPaymaster) {
    throw new Error(
      `wallet config selects the permissive test paymaster for chain ${entry.chainId} in a production build. ` +
        'Set sponsorship to "service" or "off", or set allowTestPaymaster: true if this really is a demo build.',
    );
  }
  if (sponsorship === 'test-paymaster' && !testPaymasterAddress) {
    throw new Error(`wallet config: chain ${entry.chainId} selects 'test-paymaster' but no testPaymasterAddress is configured`);
  }

  return {
    chainId: entry.chainId,
    name: entry.name || KNOWN_CHAIN_NAMES[entry.chainId] || `chain ${entry.chainId}`,
    rpcUrl: entry.rpcUrl,
    bundlerUrl: entry.bundlerUrl,
    factoryAddress,
    sponsorship,
    paymasterServiceUrl: entry.paymasterServiceUrl || `${walletApiUrl}/v1/paymaster`,
    testPaymasterAddress,
  };
}

/**
 * An explicit `sponsorship` wins. Absent one, a configured test paymaster means the dev path and
 * anything else means the service — so an existing devnet config keeps working, and a deployment
 * that has neither falls back cleanly to the unsponsored path rather than to an error (R-09).
 */
function resolveSponsorshipMode(entry: RawChainEntry, testPaymasterAddress?: string): WalletChainConfig['sponsorship'] {
  if (entry.sponsorship === 'service' || entry.sponsorship === 'test-paymaster' || entry.sponsorship === 'off') {
    return entry.sponsorship;
  }
  if (entry.sponsorship !== undefined) {
    throw new Error(`wallet config: sponsorship must be 'service', 'test-paymaster' or 'off' (got: ${String(entry.sponsorship)})`);
  }
  return testPaymasterAddress ? 'test-paymaster' : 'service';
}

export type LoadWalletConfigOptions = {
  /** Where the config lives; defaults to the stock `/config.json` (WK-07: a convenience, not a requirement). */
  url?: string;
  production?: boolean;
  fetch?: typeof fetch;
};

/**
 * Convenience loader for the stock `/config.json` shape (WK-07): fetches, validates and
 * caches per URL. A tenant whose config lives elsewhere constructs a `WalletConfig`
 * directly, or calls `resolveWalletConfig` on its own raw shape.
 */
const loaded = new Map<string, WalletConfig>();

export async function loadWalletConfig(options: LoadWalletConfigOptions = {}): Promise<WalletConfig> {
  const url = options.url ?? '/config.json';
  const cached = loaded.get(url);
  if (cached) return cached;
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const response = await fetchImpl(url, { cache: 'no-store' });
  if (!response.ok) throw new Error(`failed to load ${url}: ${response.status}`);
  const raw = (await response.json()) as RawWalletConfig;
  const config = resolveWalletConfig({ raw, production: options.production });
  loaded.set(url, config);
  return config;
}
