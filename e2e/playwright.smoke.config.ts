import { defineConfig } from "@playwright/test";

/**
 * The smoke test of a deployed environment (smoke/run.mjs): drives a deployed reference dApp in
 * Chromium, with a virtual authenticator for the passkeys. It starts no server and reads no secret;
 * the targets come from SMOKE_TARGETS, which run.mjs sets from its --target arguments.
 *
 * Separate from playwright.config.ts, which owns the local two-devnet stack.
 *
 *   pnpm -F @appliedblockchain/giano-e2e smoke --target <dApp URL>
 */
export default defineConfig({
	testDir: "./smoke",
	// Per target: one passkey account and one sponsored transaction per chain, each waiting for a
	// bundler to include it on a public testnet.
	timeout: 600_000,
	expect: { timeout: 30_000 },
	workers: 1,
	retries: 0,
	reporter: [["list"]],
	use: {
		browserName: "chromium",
		trace: "retain-on-failure",
	},
});
