import type { WalletConfig } from '@appliedblockchain/giano-wallet-kit';

/**
 * BYO-wallet config: baked in at bundle time via esbuild `define` (see serve.mjs) — a
 * tenant-built wallet needs none of Giano's /config.json machinery (WK-07: the config is the
 * host's to supply). Every chain endpoint is wallet-api's, same-origin under /api: reads
 * through /api/v1/rpc/<chainId>, the bundler through /api/v1/bundler/<chainId>. A wallet
 * origin therefore holds no node or bundler URL at all.
 */

const SPONSORSHIP = (process.env.SPONSORSHIP_MODE || (process.env.PAYMASTER_ADDRESS ? 'test-paymaster' : 'off')) as
  | 'service'
  | 'test-paymaster'
  | 'off';

/**
 * 0 when there is no second chain. serve.mjs defines this as '' for a single-chain
 * deployment, and the chain falls away below rather than being advertised as a fiction (§16.5).
 */
const CHAIN_B_ID = Number(process.env.CHAIN_B_ID || '0');

export const BRAND_NAME = 'BYO Wallet';

/**
 * The kit's `WalletConfig`, constructed directly rather than loaded from /config.json.
 * The chains list mirrors the stock wallet's (MC-45); both chains carry the canonical
 * contracts at identical addresses (MC-19).
 *
 * Names come from the environment: a deployment on a real chain calling it 'Devnet A' is
 * worse than no name at all, and consent screens name the chain (MC-80, MC-81).
 */
export function walletConfig(): WalletConfig {
  const chain = (chainId: number, name: string) => ({
    chainId,
    name,
    rpcUrl: `/api/v1/rpc/${chainId}`,
    bundlerUrl: `/api/v1/bundler/${chainId}`,
    factoryAddress: process.env.FACTORY_ADDRESS as `0x${string}`,
    sponsorship: SPONSORSHIP,
    paymasterServiceUrl: '/api/v1/paymaster',
    testPaymasterAddress: (process.env.PAYMASTER_ADDRESS || undefined) as `0x${string}` | undefined,
  });

  return {
    chains: [
      chain(Number(process.env.CHAIN_ID), process.env.CHAIN_NAME as string),
      ...(CHAIN_B_ID > 0 ? [chain(CHAIN_B_ID, process.env.CHAIN_B_NAME as string)] : []),
    ],
    walletApiUrl: '/api',
    /** fail closed: only the tenant's own dApp origins may drive this wallet */
    allowedDappOrigins: JSON.parse(process.env.ALLOWED_DAPP_ORIGINS as string) as string[],
    rpId: window.location.hostname,
    branding: { name: BRAND_NAME },
  };
}
