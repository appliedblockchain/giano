import { gianoAddresses } from '@appliedblockchain/giano-contracts';

/** Extra keys accepted in config.json that are not part of the resolved config. */
type RawWalletConfig = Partial<WalletConfig> & { allowTestPaymaster?: boolean };

export type WalletConfig = {
  chainId: number;
  rpcUrl: string;
  bundlerUrl: string;
  /** Base URL of the wallet-api; '/api' when proxied same-origin by nginx. */
  walletApiUrl: string;
  factoryAddress: `0x${string}`;
  /**
   * How gas is sponsored:
   *   'service'        — the production paymaster, through the ERC-7677 sponsorship service
   *   'test-paymaster' — the permissive paymaster (local development and tests only)
   *   'off'            — no sponsorship; the wallet behaves exactly as the unsponsored path does
   */
  sponsorship: 'service' | 'test-paymaster' | 'off';
  /** ERC-7677 sponsorship service; defaults to `${walletApiUrl}/v1/paymaster`. */
  paymasterServiceUrl: string;
  /** Permissive testing paymaster. Only ever used when `sponsorship` is 'test-paymaster'. */
  testPaymasterAddress?: `0x${string}`;
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
  const raw = (await response.json()) as RawWalletConfig;
  if (!raw.chainId || !raw.rpcUrl || !raw.bundlerUrl) {
    throw new Error('config.json must set chainId, rpcUrl and bundlerUrl');
  }
  const registry = gianoAddresses[raw.chainId];
  const factoryAddress = (raw.factoryAddress || registry?.factory) as `0x${string}` | undefined;
  if (!factoryAddress) {
    throw new Error(`config.json: factoryAddress required — chain ${raw.chainId} is not in the contracts registry`);
  }
  const walletApiUrl = raw.walletApiUrl || '/api';
  const testPaymasterAddress = (raw.testPaymasterAddress || registry?.testPaymaster) as `0x${string}` | undefined;
  const sponsorship = resolveSponsorshipMode(raw, testPaymasterAddress);

  // R-29 layer 3. The permissive paymaster approves everything; a production build that quietly
  // picked it up would sponsor without rules, without a balance and without a fee. Refusing to
  // load is the only behaviour that cannot be mistaken for working.
  if (sponsorship === 'test-paymaster' && import.meta.env.PROD && !raw.allowTestPaymaster) {
    throw new Error(
      'config.json selects the permissive test paymaster in a production build. ' +
        'Set sponsorship to "service" or "off", or set allowTestPaymaster: true if this really is a demo build.',
    );
  }

  config = {
    chainId: raw.chainId,
    rpcUrl: raw.rpcUrl,
    bundlerUrl: raw.bundlerUrl,
    walletApiUrl,
    factoryAddress,
    sponsorship,
    paymasterServiceUrl: raw.paymasterServiceUrl || `${walletApiUrl}/v1/paymaster`,
    testPaymasterAddress,
    allowedDappOrigins: raw.allowedDappOrigins ?? [],
    rpId: raw.rpId || window.location.hostname,
    branding: raw.branding ?? { name: 'Giano Wallet' },
  };
  return config;
}

/**
 * An explicit `sponsorship` wins. Absent one, a configured test paymaster means the dev path and
 * anything else means the service — so an existing devnet config keeps working, and a deployment
 * that has neither falls back cleanly to the unsponsored path rather than to an error (R-09).
 */
function resolveSponsorshipMode(raw: RawWalletConfig, testPaymasterAddress?: string): WalletConfig['sponsorship'] {
  if (raw.sponsorship === 'service' || raw.sponsorship === 'test-paymaster' || raw.sponsorship === 'off') {
    return raw.sponsorship;
  }
  if (raw.sponsorship !== undefined) {
    throw new Error(`config.json: sponsorship must be 'service', 'test-paymaster' or 'off' (got: ${String(raw.sponsorship)})`);
  }
  return testPaymasterAddress ? 'test-paymaster' : 'service';
}

export function getWalletConfig(): WalletConfig {
  if (!config) throw new Error('wallet config not loaded yet');
  return config;
}
