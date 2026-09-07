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
  /** Base URL of the wallet-api; '/api' when proxied same-origin by nginx. */
  walletApiUrl: string;
  /** dApp origins allowed to connect; empty = NONE (fail closed). Use ["*"] for local dev only. */
  allowedDappOrigins: string[];
  rpId: string;
  branding: { name: string; logoUrl?: string };
};

/** Raw config.json: either a `chains` array, or the single-chain top-level shorthand. */
type RawChainEntry = {
  chainId?: number;
  name?: string;
  rpcUrl?: string;
  bundlerUrl?: string;
  factoryAddress?: `0x${string}`;
  sponsorship?: unknown;
  paymasterServiceUrl?: string;
  testPaymasterAddress?: `0x${string}`;
};
type RawWalletConfig = RawChainEntry & {
  chains?: RawChainEntry[];
  walletApiUrl?: string;
  allowedDappOrigins?: string[];
  rpId?: string;
  branding?: { name: string; logoUrl?: string };
  allowTestPaymaster?: boolean;
};

let config: WalletConfig | null = null;

const KNOWN_CHAIN_NAMES: Record<number, string> = {
  1: 'Ethereum',
  10: 'OP Mainnet',
  8453: 'Base',
  84532: 'Base Sepolia',
  11155111: 'Sepolia',
  31337: 'Local devnet A',
  31338: 'Local devnet B',
};

/** Runtime config: fetched from /config.json (rendered in the container at boot, MC-41). */
export async function loadWalletConfig(): Promise<WalletConfig> {
  if (config) return config;
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error(`failed to load /config.json: ${response.status}`);
  const raw = (await response.json()) as RawWalletConfig;

  // Single-chain top-level keys normalise into a one-entry list (MC-88): the shorthand is a
  // complete configuration in its own right. Supplying BOTH is an error, not a merge.
  const hasScalar = raw.chainId !== undefined || raw.rpcUrl !== undefined || raw.bundlerUrl !== undefined;
  if (raw.chains && hasScalar) {
    throw new Error('config.json: `chains` and the top-level chainId/rpcUrl/bundlerUrl shorthand are mutually exclusive');
  }
  const rawChains: RawChainEntry[] = raw.chains ?? [raw];
  if (rawChains.length === 0) {
    throw new Error('config.json: `chains` must list at least one chain');
  }

  const walletApiUrl = raw.walletApiUrl || '/api';
  const seenIds = new Set<number>();
  const chains = rawChains.map((entry) => resolveChain(entry, raw, walletApiUrl, seenIds));

  config = {
    chains,
    walletApiUrl,
    allowedDappOrigins: raw.allowedDappOrigins ?? [],
    rpId: raw.rpId || window.location.hostname,
    branding: raw.branding ?? { name: 'Giano Wallet' },
  };
  return config;
}

/** Validates one chain entry; failures are fatal and name the chain and the field (MC-42). */
function resolveChain(entry: RawChainEntry, raw: RawWalletConfig, walletApiUrl: string, seenIds: Set<number>): WalletChainConfig {
  if (!entry.chainId || !entry.rpcUrl || !entry.bundlerUrl) {
    throw new Error(`config.json: every chain must set chainId, rpcUrl and bundlerUrl (chain ${entry.chainId ?? '?'})`);
  }
  if (seenIds.has(entry.chainId)) {
    throw new Error(`config.json: duplicate chainId ${entry.chainId}`);
  }
  seenIds.add(entry.chainId);

  const registry = gianoAddresses[entry.chainId];
  const factoryAddress = entry.factoryAddress || registry?.factory;
  if (!factoryAddress) {
    throw new Error(`config.json: factoryAddress required — chain ${entry.chainId} is not in the contracts registry`);
  }
  const testPaymasterAddress = entry.testPaymasterAddress || registry?.testPaymaster;
  const sponsorship = resolveSponsorshipMode(entry, testPaymasterAddress);

  // R-29 layer 3, applied PER CHAIN: the permissive paymaster approves everything; one
  // misconfigured chain in a list is exactly the case the guard exists for (§3.3). A
  // production build that quietly picked it up would sponsor without rules, without a
  // balance and without a fee. Refusing to load is the only behaviour that cannot be
  // mistaken for working.
  if (sponsorship === 'test-paymaster' && import.meta.env.PROD && !raw.allowTestPaymaster) {
    throw new Error(
      `config.json selects the permissive test paymaster for chain ${entry.chainId} in a production build. ` +
        'Set sponsorship to "service" or "off", or set allowTestPaymaster: true if this really is a demo build.',
    );
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
    throw new Error(`config.json: sponsorship must be 'service', 'test-paymaster' or 'off' (got: ${String(entry.sponsorship)})`);
  }
  return testPaymasterAddress ? 'test-paymaster' : 'service';
}

export function getWalletConfig(): WalletConfig {
  if (!config) throw new Error('wallet config not loaded yet');
  return config;
}
