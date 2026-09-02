import type { WalletConfig } from '@appliedblockchain/giano-wallet-kit';

/**
 * BYO-wallet config: baked in at bundle time via esbuild `define` (see serve.mjs) —
 * a tenant-built wallet needs none of Giano's /config.json machinery (WK-07: the config
 * is the host's to supply). The rpc/bundler/api endpoints are same-origin proxies served
 * by serve.mjs, so the URLs are resolved against the page origin at startup.
 */

const SPONSORSHIP = (process.env.SPONSORSHIP_MODE || (process.env.PAYMASTER_ADDRESS ? 'test-paymaster' : 'off')) as
  | 'service'
  | 'test-paymaster'
  | 'off';

export const BRAND_NAME = 'BYO Wallet';

/**
 * The kit's `WalletConfig`, constructed directly rather than loaded from /config.json.
 * The chains list mirrors the stock wallet's (MC-45); both chains carry the canonical
 * contracts at identical addresses (MC-19).
 */
export function walletConfig(): WalletConfig {
  const origin = window.location.origin;
  const chain = (chainId: number, name: string, rpcPath: string, bundlerPath: string) => ({
    chainId,
    name,
    rpcUrl: `${origin}${rpcPath}`,
    bundlerUrl: `${origin}${bundlerPath}`,
    factoryAddress: process.env.FACTORY_ADDRESS as `0x${string}`,
    sponsorship: SPONSORSHIP,
    /** Same-origin, through the `/api` proxy — no tenant onboarding change is needed for this. */
    paymasterServiceUrl: '/api/v1/paymaster',
    testPaymasterAddress: (process.env.PAYMASTER_ADDRESS || undefined) as `0x${string}` | undefined,
  });

  return {
    chains: [
      chain(Number(process.env.CHAIN_ID), 'Devnet A', '/rpc', '/bundler'),
      chain(Number(process.env.CHAIN_B_ID), 'Devnet B', '/rpc-b', '/bundler-b'),
    ],
    walletApiUrl: '/api',
    /** fail closed: only the tenant's own dApp origins may drive this wallet */
    allowedDappOrigins: JSON.parse(process.env.ALLOWED_DAPP_ORIGINS as string) as string[],
    rpId: window.location.hostname,
    branding: { name: BRAND_NAME },
  };
}
