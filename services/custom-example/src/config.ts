import { defineChain } from 'viem';

// Defaults target the local e2e stack (deploy/docker-compose.e2e.yml), addressed by the names
// portless serves rather than by port (see e2e/origins.mjs):
// - wallet origin (wallet-web) on http://wallet.localhost
// - anvil devnet RPC on http://rpc.localhost (chain 31337)
// - devnet TestERC20 (a trivial mint/burn faucet token) baked into the devnet state, used to
//   prefill the ERC-20 panel
// Override any of these with VITE_* env vars for other networks.
const RPC_URL = import.meta.env.VITE_RPC_URL ?? 'http://rpc.localhost';
const CHAIN_ID = Number(import.meta.env.VITE_CHAIN_ID ?? '31337');
const WALLET_URL = import.meta.env.VITE_WALLET_URL ?? 'http://wallet.localhost';
// Baked TestERC20 address for the local e2e devnet (e2e/devnet/addresses.json). Regenerating the
// devnet state changes it — keep the two in step.
const DEFAULT_TOKEN = (import.meta.env.VITE_TEST_ERC20 ?? '0xB1B44149690b0cEd02bC6cA3f95F3D554b1ee72F') as `0x${string}`;
// Optional free-text tag shown next to the demo's title. Useful when several instances of
// this dApp run side by side against different wallet origins (e.g. one per tenant in the
// two-tenant e2e topology) and are otherwise visually identical.
const APP_LABEL = import.meta.env.VITE_APP_LABEL?.trim() || undefined;

export const chain = defineChain({
  id: CHAIN_ID,
  name: 'Giano Demo',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
});

export const config = {
  walletUrl: WALLET_URL,
  rpcUrl: RPC_URL,
  chainId: CHAIN_ID,
  defaultTokenAddress: DEFAULT_TOKEN,
  appLabel: APP_LABEL,
};
