#!/usr/bin/env node
/**
 * Smoke test of a deployed environment, through its reference dApp.
 *
 *   pnpm -F @appliedblockchain/giano-e2e smoke --target https://example.dev.giano.appliedblockchain.dev
 *   pnpm -F @appliedblockchain/giano-e2e smoke --target <dApp URL> --target <dApp URL> [--chain <id>]… [--headed]
 *
 * A target is the URL of a deployed reference dApp (services/custom-example). Everything else comes
 * from that dApp's own runtime config (/config.js): its wallet origin, its chains and their default
 * token. Nothing about any one environment is written here, so the same command checks dev, stg or
 * a local stack by changing only the URL.
 *
 * For each target, on each of its chains: create a passkey account (a Chromium virtual authenticator,
 * so no person has to touch a passkey), send one sponsored transaction (a mint of the default token,
 * or a zero-value self-call where the dApp has none), wait for it to confirm, and check on chain that
 * the account has code and the transaction succeeded with a paymaster. Then check the account address
 * is the same on every chain. It prints one line per chain with the account and the hashes.
 *
 * It holds no secret and calls only public pages. Each run creates a user on the target tenant and
 * spends a little of its sponsorship balance. It refuses any chain that is not a known testnet unless
 * --allow-production is given.
 */
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const USAGE =
	"usage: pnpm -F @appliedblockchain/giano-e2e smoke --target <dApp URL> [--target <dApp URL>]… " +
	"[--chain <chainId>]… [--allow-production] [--headed]";

const targets = [];
const chains = [];
let allowProduction = false;
let headed = false;

const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
	const arg = args[i];
	if (arg === "--") continue;
	if (arg === "--target" || arg === "--chain") {
		const value = args[++i];
		if (!value || value.startsWith("--")) fail(`${arg} needs a value`);
		(arg === "--target" ? targets : chains).push(value);
	} else if (arg === "--allow-production") allowProduction = true;
	else if (arg === "--headed") headed = true;
	else if (arg === "--help" || arg === "-h") {
		console.log(USAGE);
		process.exit(0);
	} else fail(`unknown argument: ${arg}`);
}
if (targets.length === 0) fail("give at least one --target");

const origins = targets.map((target) => {
	let url;
	try {
		url = new URL(target);
	} catch {
		fail(`--target ${target} is not a URL`);
	}
	const local =
		["localhost", "127.0.0.1"].includes(url.hostname) ||
		url.hostname.endsWith(".localhost");
	if (url.protocol !== "https:" && !(local && url.protocol === "http:"))
		fail(`--target ${target}: use https (http only for a local stack)`);
	return url.origin;
});
for (const chain of chains)
	if (!/^[1-9][0-9]*$/.test(chain)) fail(`--chain ${chain} is not a chain ID`);

const dir = dirname(fileURLToPath(import.meta.url));
const result = spawnSync(
	"pnpm",
	[
		"exec",
		"playwright",
		"test",
		"--config",
		"playwright.smoke.config.ts",
		...(headed ? ["--headed"] : []),
	],
	{
		cwd: resolve(dir, ".."),
		stdio: "inherit",
		env: {
			...process.env,
			SMOKE_TARGETS: JSON.stringify(origins),
			SMOKE_CHAINS: chains.join(","),
			SMOKE_ALLOW_PRODUCTION: allowProduction ? "1" : "",
		},
	},
);
process.exit(result.status ?? 1);

function fail(message) {
	console.error(`${message}\n${USAGE}`);
	process.exit(2);
}
