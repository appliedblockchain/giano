import { defineChain, type Chain } from 'viem';

/**
 * Runtime config, injected by the container at start as `window.__GIANO_CONFIG__`
 * (docker/config.js.template, rendered by docker/entrypoint.sh from GIANO_* environment
 * variables). One published image therefore serves every deployment and both demo tenants —
 * §16.1 of specs/INFRASTRUCTURE.md.
 *
 * The `VITE_*` variables below survive as BUILD-time fallbacks for `pnpm dev` and
 * `pnpm preview`, where there is no container to render a config. Under `pnpm dev`
 * public/config.js sets the runtime config to null and every value falls through to them.
 *
 * Read synchronously rather than fetched, deliberately: `chain`, `chainB` and `demoChains`
 * below are module-level constants, and src/giano.ts builds its provider and public client at
 * module level from them. index.html loads /config.js ahead of the bundle so this is already
 * populated by the time the module graph evaluates. See the comment in config.js.template.
 */
type RuntimeConfig = {
  chainId?: number;
  chainName?: string;
  rpcUrl?: string;
  chainBId?: number;
  chainBName?: string;
  rpcBUrl?: string;
  walletUrl?: string;
  appLabel?: string;
  testErc20?: string;
};

declare global {
  interface Window {
    __GIANO_CONFIG__?: RuntimeConfig | null;
  }
}

const runtime: RuntimeConfig = (typeof window !== 'undefined' && window.__GIANO_CONFIG__) || {};

/** envsubst renders an unset variable as an empty string, which means "unset", not "". */
const str = (value: string | undefined): string | undefined => {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
};

// Defaults target the local e2e stack (deploy/docker-compose.e2e.yml), addressed by the names
// portless serves rather than by port (see e2e/origins.mjs):
// - wallet origin (wallet-web) on http://wallet.localhost
// - anvil devnet RPC on http://rpc.localhost (chain A, 31337) and http://rpc-b.localhost (chain B, 31338)
// - devnet PrivateERC20 baked into the devnet state, used to prefill the ERC-20 panel
// Deployments override these with GIANO_* on the container; `pnpm dev` with VITE_* at build.
const RPC_URL = str(runtime.rpcUrl) ?? str(import.meta.env.VITE_RPC_URL) ?? 'http://rpc.localhost';
const CHAIN_ID = Number(runtime.chainId ?? import.meta.env.VITE_CHAIN_ID ?? '31337');
const CHAIN_NAME = str(runtime.chainName) ?? str(import.meta.env.VITE_CHAIN_NAME) ?? 'Devnet A';
const RPC_B_URL = str(runtime.rpcBUrl) ?? str(import.meta.env.VITE_RPC_B_URL) ?? 'http://rpc-b.localhost';
const CHAIN_B_ID = Number(runtime.chainBId ?? import.meta.env.VITE_CHAIN_B_ID ?? '31338');
const CHAIN_B_NAME = str(runtime.chainBName) ?? str(import.meta.env.VITE_CHAIN_B_NAME) ?? 'Devnet B';
const WALLET_URL = str(runtime.walletUrl) ?? str(import.meta.env.VITE_WALLET_URL) ?? 'http://wallet.localhost';
const DEFAULT_TOKEN = (str(runtime.testErc20) ?? str(import.meta.env.VITE_TEST_ERC20) ?? '0x9967bDf929856643e92EF65eefdE1fF8250774D8') as `0x${string}`;
// Optional free-text tag shown next to the demo's title. Useful when several instances of
// this dApp run side by side against different wallet origins (e.g. one per tenant in the
// two-tenant e2e topology, or custom-example / custom-example-byoui) and are otherwise
// visually identical.
const APP_LABEL = str(runtime.appLabel) ?? str(import.meta.env.VITE_APP_LABEL);

export const chain = defineChain({
  id: CHAIN_ID,
  name: CHAIN_NAME,
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
});

export const chainB = defineChain({
  id: CHAIN_B_ID,
  name: CHAIN_B_NAME,
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [RPC_B_URL] } },
});

export type DemoChain = { chain: Chain; chainId: number; name: string; rpcUrl: string };

/**
 * The chains the demo can submit to. One passkey controls the SAME account address on
 * every one of them (MC-16); the cross-chain panel makes that visible (MC-124, MC-125).
 * Set GIANO_CHAIN_B_ID (or VITE_CHAIN_B_ID) to 0 to run the demo single-chain, which is what
 * a single-chain deployment does.
 */
export const demoChains: DemoChain[] = [
  { chain, chainId: CHAIN_ID, name: CHAIN_NAME, rpcUrl: RPC_URL },
  ...(CHAIN_B_ID > 0 ? [{ chain: chainB, chainId: CHAIN_B_ID, name: CHAIN_B_NAME, rpcUrl: RPC_B_URL }] : []),
];

export const config = {
  walletUrl: WALLET_URL,
  rpcUrl: RPC_URL,
  chainId: CHAIN_ID,
  defaultTokenAddress: DEFAULT_TOKEN,
  appLabel: APP_LABEL,
};
