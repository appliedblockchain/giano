import { defineConfig } from "@playwright/test";

/**
 * The browser half of the deployment rehearsal (pnpm contracts:rehearse --platform): the stock wallet
 * of deploy/docker-compose.chain.yml, serving a fork of a public testnet whose contracts the rehearsal
 * deployed, provisioned and handed to the timelock the way a real adoption does.
 *
 * Separate from playwright.config.ts on purpose: that suite owns the two-devnet e2e stack and its
 * portless names, while this stack is the external-chain demo with its own ports. Run only one of the
 * two stacks at a time; they share host ports.
 *
 *   pnpm -F @appliedblockchain/giano-e2e test:rehearsal
 */
const CHAIN_ID = process.env.REHEARSAL_CHAIN_ID ?? "84532";
const FORK_RPC = process.env.REHEARSAL_FORK_RPC ?? "http://127.0.0.1:18545";
const WALLET_URL = "http://wallet.localhost:8081";
const DAPP_URL = "http://app.localhost:4400";

// The shared helpers read the stock tenant's origins from here.
process.env.WALLET_URL = WALLET_URL;
process.env.DAPP_URL = DAPP_URL;

export default defineConfig({
	testDir: "./rehearsal",
	timeout: 180_000,
	workers: 1,
	use: {
		baseURL: DAPP_URL,
		browserName: "chromium",
		trace: "retain-on-failure",
	},
	webServer: [
		{
			command: "node dapp/serve.mjs",
			env: {
				DAPP_PORT: "4400",
				WALLET_URL,
				CHAIN_ID,
				RPC_URL: FORK_RPC,
				// The fixture always builds a second provider; on a one-chain stack it points at the same one.
				CHAIN_B_ID: CHAIN_ID,
				RPC_B_URL: FORK_RPC,
			},
			url: "http://127.0.0.1:4400",
			reuseExistingServer: false,
		},
	],
});
