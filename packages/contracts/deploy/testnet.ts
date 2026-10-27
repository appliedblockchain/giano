/** Guided public-testnet deployment. No secret is read from a prompt or written to disk. */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import {
	createPublicClient,
	createWalletClient,
	defineChain,
	getAddress,
	type Hex,
	http,
	keccak256,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
	CANONICAL_DEPLOYER,
	DEPLOYER_IS_PLACEHOLDER,
	ENTRY_POINT_V07,
	LABELS,
} from "./config";
import { create3Address } from "./create3";
import { deployCore } from "./deploy";
import { readRecord, writeRecord } from "./records";
import { latestRelease, loadRelease } from "./release";
import {
	CORE_KEYS,
	expectedCodehash,
	inspectTestnet,
	networkFor,
	PAYMASTER_DEFAULTS,
	roleAdmin,
	TESTNETS,
	verifyCoreState,
} from "./testnet-checks";

class GuidanceError extends Error {}

async function main() {
	const { values } = parseArgs({
		options: {
			network: { type: "string" },
			rpc: { type: "string" },
			"role-admin": { type: "string" },
			release: { type: "string" },
			plan: { type: "boolean" },
			help: { type: "boolean" },
		},
	});
	if (values.help) {
		console.log(
			"pnpm testnet:deploy [--network base-sepolia|ethereum-sepolia] [--rpc URL] [--role-admin ADDRESS] [--release v1] [--plan]\nInteractive by default; --plan is read-only and works without a signing key.\nSet CANONICAL_DEPLOYER_PRIVATE_KEY securely in the environment to deploy. Never paste keys into arguments.\nBootstrap: Node 24+, corepack pnpm install --frozen-lockfile. See deploy/testnet/README.md.",
		);
		return;
	}
	const interactive = Boolean(
		process.stdin.isTTY && process.stdout.isTTY && !values.plan,
	);
	const rl = interactive
		? createInterface({ input: process.stdin, output: process.stdout })
		: undefined;
	const ask = async (label: string, fallback = "") => {
		if (!rl) return fallback;
		return (
			(
				await rl.question(`${label}${fallback ? ` [${fallback}]` : ""}: `)
			).trim() || fallback
		);
	};
	try {
		let network: ReturnType<typeof networkFor>;
		try {
			network = networkFor(
				values.network ??
					(await ask(
						"Network: base-sepolia or ethereum-sepolia",
						"base-sepolia",
					)),
			);
		} catch {
			throw new GuidanceError(
				"Choose --network base-sepolia or ethereum-sepolia, or run interactively.",
			);
		}
		const rpc =
			values.rpc ??
			process.env.DEPLOY_RPC_URL ??
			(await ask(
				"RPC URL (provider key stays in memory)",
				TESTNETS[network].rpc,
			));
		try {
			const url = new URL(rpc);
			if (!["https:", "http:"].includes(url.protocol)) throw new Error();
		} catch {
			throw new GuidanceError(
				"Provide an HTTP(S) RPC URL with --rpc or DEPLOY_RPC_URL.",
			);
		}
		let admin: ReturnType<typeof roleAdmin>;
		try {
			admin = roleAdmin(
				values["role-admin"] ??
					process.env.PAYMASTER_ROLE_ADMIN ??
					(await ask(
						"Paymaster ROLE_ADMIN address (operator address, not its private key)",
					)),
			);
		} catch {
			throw new GuidanceError(
				"Provide a nonzero paymaster ROLE_ADMIN address with --role-admin or PAYMASTER_ROLE_ADMIN.",
			);
		}
		const version = values.release ?? latestRelease();
		if (version === "dev")
			throw new GuidanceError(
				"Public testnets require a committed release, not dev.",
			);
		let release: ReturnType<typeof loadRelease>;
		try {
			release = loadRelease(version);
		} catch {
			throw new GuidanceError(
				"Release not found or unreadable. Use --release v1 or another committed release under packages/contracts/releases/.",
			);
		}
		console.log(
			`\n${TESTNETS[network].name} (${TESTNETS[network].id}) / release ${version}\nCanonical deployer: ${CANONICAL_DEPLOYER}\nPaymaster ROLE_ADMIN: ${admin}\nFee: 0.0001 ETH; post-op allowance: 40000 gas; penalty: 1000 bps.\nNo test ERC-20 or permissive paymaster will be deployed (R-29).`,
		);
		const transport = http(rpc, { timeout: 15000, retryCount: 1 });
		const chain = defineChain({
			id: TESTNETS[network].id,
			name: TESTNETS[network].name,
			nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
			rpcUrls: { default: { http: [rpc] } },
		});
		const client = createPublicClient({ chain, transport });
		const blockers: string[] = [];
		if (DEPLOYER_IS_PLACEHOLDER)
			blockers.push(
				"Canonical deployer is still the placeholder. Choose the permanent deployer address in deploy/config.ts; regenerate canonical.ts and devnet state, review and commit them before either testnet. Do not fund the placeholder.",
			);
		let account: ReturnType<typeof privateKeyToAccount> | undefined;
		const key = process.env.CANONICAL_DEPLOYER_PRIVATE_KEY;
		if (key) {
			try {
				account = privateKeyToAccount(key as Hex);
			} catch {
				blockers.push(
					"CANONICAL_DEPLOYER_PRIVATE_KEY is invalid; provide a 32-byte hex private key securely through the environment.",
				);
			}
			if (
				account &&
				getAddress(account.address) !== getAddress(CANONICAL_DEPLOYER)
			)
				blockers.push(
					"Signing key does not match CANONICAL_DEPLOYER. Obtain the canonical deployer key from its custodian.",
				);
		} else
			console.log(
				"INFO: No signing key supplied. For execution, export CANONICAL_DEPLOYER_PRIVATE_KEY securely and rerun; plans do not need it.",
			);
		// Validate record ownership before sending anything; never silently replace an older record.
		let record: ReturnType<typeof readRecord>;
		try {
			record = readRecord(chain.id, CANONICAL_DEPLOYER);
		} catch {
			throw new GuidanceError(
				"Existing deployment record is invalid or belongs to another deployer. Archive and review it before adopting the new address family; do not overwrite it blindly.",
			);
		}
		const checks = await inspectTestnet(client, network, version, admin);
		for (const check of checks)
			console.log(`${check.ok ? "OK" : "BLOCKED"}: ${check.message}`);
		for (const blocker of blockers) console.log(`BLOCKED: ${blocker}`);
		if (blockers.length || checks.some((check) => !check.ok)) {
			process.exitCode = 1;
			return;
		}
		console.log(
			"\nRequirements passed. This is a new address family: existing wallets, balances, tenant funding and sponsorship policies do not migrate automatically. See deploy/testnet/README.md for cutover and recovery.",
		);
		if (!rl || values.plan) {
			console.log(
				"Read-only plan complete. Rerun in a terminal without --plan to deploy.",
			);
			return;
		}
		if (!account)
			throw new GuidanceError(
				"Set CANONICAL_DEPLOYER_PRIVATE_KEY securely in the environment and rerun. No transactions sent.",
			);
		const confirmation = `deploy ${network} ${version}`;
		if (
			(await ask(
				`Type '${confirmation}' to send transactions (anything else cancels)`,
			)) !== confirmation
		) {
			console.log("Cancelled. No transactions sent.");
			return;
		}
		// Recheck after the operator has reviewed the plan; balances/code may have changed.
		const fresh = await inspectTestnet(client, network, version, admin);
		if (fresh.some((check) => !check.ok))
			throw new GuidanceError(
				"Requirements changed during review. Rerun the plan. No transactions sent.",
			);
		const walletClient = createWalletClient({ chain, transport, account });
		await deployCore(
			{
				publicClient: client,
				walletClient,
				deployer: CANONICAL_DEPLOYER,
				record,
				log: console.log,
				onRecord: () => writeRecord(record),
			},
			release,
			{ entryPoint: ENTRY_POINT_V07, roleAdmin: admin, ...PAYMASTER_DEFAULTS },
		);
		for (const key of CORE_KEYS) {
			const code = await client.getCode({
				address: create3Address(CANONICAL_DEPLOYER, LABELS[key]),
			});
			if (!code || keccak256(code) !== expectedCodehash(key, version))
				throw new GuidanceError(
					`Post-deployment code verification failed for ${key}. Do not serve this chain.`,
				);
		}
		await verifyCoreState(client, admin);
		writeRecord(record);
		const addressEnv = new URL(
			`../../../deploy/testnet/${chain.id}.addresses.env`,
			import.meta.url,
		);
		writeFileSync(
			addressEnv,
			`# Public addresses only; source after the environment configuration.\nCHAIN_ID=${chain.id}\nDEPLOY_CHAIN_ID=${chain.id}\nFACTORY_ADDRESS=${record.contracts.factory?.address}\nSPONSORSHIP_PAYMASTER_ADDRESS=${record.contracts.paymasterProxy?.address}\nTEST_PAYMASTER_ADDRESS=\nTEST_ERC20_ADDRESS=\n`,
		);
		execFileSync(
			process.execPath,
			["--import", "tsx", "scripts/generate-addresses.ts"],
			{ cwd: new URL("..", import.meta.url), stdio: "inherit" },
		);
		console.log(
			`\nCore deployment verified; registry regenerated. Public address configuration: deploy/testnet/${chain.id}.addresses.env. Commit deployments/${chain.id}.json and addresses.ts.\nNext: provision the new paymaster with the existing tenant UUIDs and sponsorship signer; fund operator/executor on this chain; run doctor --require-paymaster; update GIANO_CHAINS and all address overrides; roll the services; verify a sponsored transaction.\nCore deployment alone is NOT a ready-to-serve chain. Follow deploy/testnet/README.md.`,
		);
	} finally {
		rl?.close();
	}
}
main().catch((error: unknown) => {
	if (error instanceof GuidanceError) {
		console.error(error.message);
		process.exitCode = 1;
		return;
	}
	// Avoid leaking a provider URL or private key through a viem error or argument dump.
	console.error(
		"Deployment stopped. Check network/RPC access, address inputs and committed release/record files. No further transactions will be sent. Inspect transaction receipts and rerun the same network/release to recover; see deploy/testnet/README.md. Provider error details are suppressed to protect credentials.",
	);
	process.exitCode = 1;
});
