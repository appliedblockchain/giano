/**
 * BYO-wallet config: baked in at bundle time via esbuild `define` (see serve.mjs) —
 * a tenant-built wallet needs none of Giano's /config.json machinery. The rpc/bundler/
 * api endpoints are same-origin proxies served by serve.mjs.
 */
export type ByoChainConfig = {
  chainId: number;
  name: string;
  rpcPath: string;
  bundlerPath: string;
};

export const CONFIG = {
  chainId: Number(process.env.CHAIN_ID),
  /**
   * The chains this wallet origin serves (MC-39). Its shape is effectively public API —
   * tenants copy this reference — so it mirrors the stock wallet's `chains` list (MC-45).
   * Both chains carry the canonical contracts at identical addresses (MC-19).
   */
  chains: [
    { chainId: Number(process.env.CHAIN_ID), name: 'Devnet A', rpcPath: '/rpc', bundlerPath: '/bundler' },
    { chainId: Number(process.env.CHAIN_B_ID), name: 'Devnet B', rpcPath: '/rpc-b', bundlerPath: '/bundler-b' },
  ] as ByoChainConfig[],
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
