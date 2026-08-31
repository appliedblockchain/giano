import { defineChain, type Chain } from 'viem';

// Defaults target the local e2e stack (deploy/docker-compose.e2e.yml), addressed by the names
// portless serves rather than by port (see e2e/origins.mjs):
// - wallet origin (wallet-web) on http://wallet.localhost
// - anvil devnet RPC on http://rpc.localhost (chain A, 31337) and http://rpc-b.localhost (chain B, 31338)
// - devnet PrivateERC20 baked into the devnet state, used to prefill the ERC-20 panel
// Override any of these with VITE_* env vars for other networks.
const RPC_URL = import.meta.env.VITE_RPC_URL ?? 'http://rpc.localhost';
const CHAIN_ID = Number(import.meta.env.VITE_CHAIN_ID ?? '31337');
const CHAIN_NAME = import.meta.env.VITE_CHAIN_NAME ?? 'Devnet A';
const RPC_B_URL = import.meta.env.VITE_RPC_B_URL ?? 'http://rpc-b.localhost';
const CHAIN_B_ID = Number(import.meta.env.VITE_CHAIN_B_ID ?? '31338');
const CHAIN_B_NAME = import.meta.env.VITE_CHAIN_B_NAME ?? 'Devnet B';
const WALLET_URL = import.meta.env.VITE_WALLET_URL ?? 'http://wallet.localhost';
const DEFAULT_TOKEN = (import.meta.env.VITE_TEST_ERC20 ?? '0x9967bDf929856643e92EF65eefdE1fF8250774D8') as `0x${string}`;
// Optional free-text tag shown next to the demo's title. Useful when several instances of
// this dApp run side by side against different wallet origins (e.g. one per tenant in the
// two-tenant e2e topology) and are otherwise visually identical.
const APP_LABEL = import.meta.env.VITE_APP_LABEL?.trim() || undefined;

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
 * Set VITE_CHAIN_B_ID to 0 to run the demo single-chain.
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
