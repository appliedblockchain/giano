/**
 * BYO-wallet config: baked in at bundle time via esbuild `define` (see serve.mjs) —
 * a tenant-built wallet needs none of Giano's /config.json machinery. The rpc/bundler/
 * api endpoints are same-origin proxies served by serve.mjs.
 */
export const CONFIG = {
  chainId: Number(process.env.CHAIN_ID),
  factoryAddress: process.env.FACTORY_ADDRESS as `0x${string}`,
  paymasterAddress: (process.env.PAYMASTER_ADDRESS || undefined) as `0x${string}` | undefined,
  allowedDappOrigins: JSON.parse(process.env.ALLOWED_DAPP_ORIGINS as string) as string[],
  brandName: 'BYO Wallet',
  get rpcUrl() {
    return `${window.location.origin}/rpc`;
  },
  get bundlerUrl() {
    return `${window.location.origin}/bundler`;
  },
  walletApiUrl: '/api',
};
