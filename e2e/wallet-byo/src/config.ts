/**
 * BYO-wallet config: baked in at bundle time via esbuild `define` (see serve.mjs) —
 * a tenant-built wallet needs none of Giano's /config.json machinery. The rpc/bundler/
 * api endpoints are same-origin proxies served by serve.mjs.
 */
export const CONFIG = {
  chainId: Number(process.env.CHAIN_ID),
  factoryAddress: process.env.FACTORY_ADDRESS as `0x${string}`,
  /**
   * How gas is sponsored. A BYO tenant chooses this exactly as the stock wallet does:
   * 'service' talks ERC-7677 to the sponsorship service, 'test-paymaster' uses the permissive
   * fixture, 'off' means the user pays.
   */
  sponsorship: (process.env.SPONSORSHIP_MODE || (process.env.PAYMASTER_ADDRESS ? 'test-paymaster' : 'off')) as
    | 'service'
    | 'test-paymaster'
    | 'off',
  testPaymasterAddress: (process.env.PAYMASTER_ADDRESS || undefined) as `0x${string}` | undefined,
  allowedDappOrigins: JSON.parse(process.env.ALLOWED_DAPP_ORIGINS as string) as string[],
  brandName: 'BYO Wallet',
  get rpcUrl() {
    return `${window.location.origin}/rpc`;
  },
  get bundlerUrl() {
    return `${window.location.origin}/bundler`;
  },
  walletApiUrl: '/api',
  /** Same-origin, through the `/api` proxy — no tenant onboarding change is needed for this. */
  get paymasterServiceUrl() {
    return '/api/v1/paymaster';
  },
};
