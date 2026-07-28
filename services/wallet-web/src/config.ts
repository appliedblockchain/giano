import { gianoAddresses } from '@appliedblockchain/giano-contracts';

export type WalletConfig = {
  chainId: number;
  rpcUrl: string;
  bundlerUrl: string;
  /** Base URL of the wallet-api; '/api' when proxied same-origin by nginx. */
  walletApiUrl: string;
  factoryAddress: `0x${string}`;
  /** Optional paymaster to sponsor gas (devnet uses the permissive testing paymaster). */
  paymasterAddress?: `0x${string}`;
  /** dApp origins allowed to connect; empty = NONE (fail closed). Use ["*"] for local dev only. */
  allowedDappOrigins: string[];
  rpId: string;
  branding: { name: string; logoUrl?: string };
};

let config: WalletConfig | null = null;

/** Runtime config: fetched from /config.json (envsubst-rendered in the container). */
export async function loadWalletConfig(): Promise<WalletConfig> {
  if (config) return config;
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error(`failed to load /config.json: ${response.status}`);
  const raw = (await response.json()) as Partial<WalletConfig>;
  if (!raw.chainId || !raw.rpcUrl || !raw.bundlerUrl) {
    throw new Error('config.json must set chainId, rpcUrl and bundlerUrl');
  }
  const registry = gianoAddresses[raw.chainId];
  const factoryAddress = (raw.factoryAddress || registry?.factory) as `0x${string}` | undefined;
  if (!factoryAddress) {
    throw new Error(`config.json: factoryAddress required — chain ${raw.chainId} is not in the contracts registry`);
  }
  config = {
    chainId: raw.chainId,
    rpcUrl: raw.rpcUrl,
    bundlerUrl: raw.bundlerUrl,
    walletApiUrl: raw.walletApiUrl || '/api',
    factoryAddress,
    paymasterAddress: (raw.paymasterAddress || registry?.paymaster) as `0x${string}` | undefined,
    allowedDappOrigins: raw.allowedDappOrigins ?? [],
    rpId: raw.rpId || window.location.hostname,
    branding: raw.branding ?? { name: 'Giano Wallet' },
  };
  return config;
}

export function getWalletConfig(): WalletConfig {
  if (!config) throw new Error('wallet config not loaded yet');
  return config;
}
