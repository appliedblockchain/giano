/** Guided profile-driven deployment. No secret is read from a prompt or written to disk. */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
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
	ENTRY_POINT_V09,
	LABELS,
} from "./config";
import { create3Address } from "./create3";
import { deployCore } from "./deploy";
import {
	CORE_KEYS,
	expectedCodehash,
	inspectDeployment,
	roleAdmin,
	verifyCoreState,
} from "./preflight";
import {
	listProfiles,
	loadProfile,
	paymasterParams,
	REPO_ROOT,
	savePublicChoices,
} from "./profiles";
import { readRecord, writeRecord } from "./records";
import { loadRelease } from "./release";

class GuidanceError extends Error {}

async function main() {
	const { values } = parseArgs({
		options: {
			chain: { type: "string" },
			config: { type: "string" },
			"env-file": { type: "string" },
			rpc: { type: "string" },
			"role-admin": { type: "string" },
			release: { type: "string" },
			plan: { type: "boolean" },
			help: { type: "boolean" },
		},
	});
	if (values.help) {
		console.log(
			"pnpm contracts:deploy [--chain <profile> | --config <file>] [--env-file <file>] [--role-admin ADDRESS] [--release v1] [--plan]\nProfiles are persisted under deploy/chains/. Interactive runs can save public admin/release choices; --plan never writes or signs.\nProvide keys and credential-bearing RPC URLs through the environment; profiles store only public values and environment references.\nSee deploy/contracts/README.md.",
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
		let selected: ReturnType<typeof loadProfile>;
		try {
			selected = loadProfile(
				values.chain || values.config
					? { chain: values.chain, config: values.config }
					: {
							chain: await ask(`Chain profile (${listProfiles().join(", ")})`),
						},
			);
		} catch (error) {
			throw new GuidanceError(
				error instanceof Error
					? error.message
					: "Choose a valid chain profile.",
			);
		}
		const { profile } = selected;
		if (values["env-file"]) {
			try {
				process.loadEnvFile(resolve(REPO_ROOT, values["env-file"]));
			} catch {
				throw new GuidanceError(
					"Cannot load --env-file. Provide a dotenv file with operator credentials; shell commands are not evaluated.",
				);
			}
		}
		for (const field of ["CHAIN_ID", "DEPLOY_CHAIN_ID"]) {
			if (process.env[field] && Number(process.env[field]) !== profile.chainId)
				throw new GuidanceError(
					`${field} in the environment differs from the selected profile. Correct the environment before continuing.`,
				);
		}
		const rpc =
			values.rpc ??
			process.env[profile.rpcUrlEnv] ??
			process.env.DEPLOY_RPC_URL ??
			(await ask(
				`RPC URL (or provide ${profile.rpcUrlEnv} securely)`,
				profile.rpcUrl,
			));
		try {
			const url = new URL(rpc);
			if (!["https:", "http:"].includes(url.protocol)) throw new Error();
		} catch {
			throw new GuidanceError(
				"Provide an HTTP(S) RPC URL through the profile's environment reference or --rpc.",
			);
		}

		let admin: ReturnType<typeof roleAdmin>;
		try {
			admin = roleAdmin(
				values["role-admin"] ??
					process.env.PAYMASTER_ROLE_ADMIN ??
					profile.roleAdmin ??
					(await ask(
						"Paymaster ROLE_ADMIN address (operator address, not its private key)",
					)),
			);
		} catch {
			throw new GuidanceError(
				"Provide a nonzero paymaster ROLE_ADMIN address with --role-admin or PAYMASTER_ROLE_ADMIN.",
			);
		}
		const version =
			values.release ??
			(await ask("Committed contract release", profile.release));
		if (version === "dev")
			throw new GuidanceError(
				"Public chains require a committed release, not dev.",
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
			`\n${profile.name} (${profile.chainId}) / release ${version}\nCanonical deployer: ${CANONICAL_DEPLOYER}\nPaymaster ROLE_ADMIN: ${admin}\nFee: ${profile.paymaster.defaultFeeWei} wei; post-op allowance: ${profile.paymaster.postOpGasAllowance} gas; penalty: ${profile.paymaster.penaltyBps} bps.\nNo test ERC-20 or permissive paymaster will be deployed (R-29).`,
		);
		if (
			rl &&
			(await ask(
				`Save public ROLE_ADMIN and release to ${selected.file}? (yes/no)`,
				"yes",
			)) === "yes"
		) {
			savePublicChoices(selected, admin, version);
			console.log(
				"Saved public configuration. Runtime RPC overrides and keys were not persisted.",
			);
		}
		const transport = http(rpc, { timeout: 15000, retryCount: 1 });
		const chain = defineChain({
			id: profile.chainId,
			name: profile.name,
			nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
			rpcUrls: { default: { http: [rpc] } },
		});
		const client = createPublicClient({ chain, transport });
		const blockers: string[] = [];
		if (DEPLOYER_IS_PLACEHOLDER)
			blockers.push(
				"Canonical deployer is still the placeholder. Choose the permanent deployer address in deploy/config.ts; regenerate canonical.ts and devnet state, review and commit them before public deployment. Do not fund the placeholder.",
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
		const checks = await inspectDeployment(client, profile, version, admin);
		for (const check of checks)
			console.log(`${check.ok ? "OK" : "BLOCKED"}: ${check.message}`);
		for (const blocker of blockers) console.log(`BLOCKED: ${blocker}`);
		if (blockers.length || checks.some((check) => !check.ok)) {
			process.exitCode = 1;
			return;
		}
		console.log(
			"\nRequirements passed. This is a new address family: existing wallets, balances, tenant funding and sponsorship policies do not migrate automatically. See deploy/contracts/README.md for cutover and recovery.",
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
		const confirmation = `deploy ${profile.chainId} ${version}`;
		if (
			(await ask(
				`Type '${confirmation}' to send transactions (anything else cancels)`,
			)) !== confirmation
		) {
			console.log("Cancelled. No transactions sent.");
			return;
		}
		// Recheck after the operator has reviewed the plan; balances/code may have changed.
		const fresh = await inspectDeployment(client, profile, version, admin);
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
			{
				entryPoint: ENTRY_POINT_V09,
				roleAdmin: admin,
				...paymasterParams(profile),
			},
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
		await verifyCoreState(client, admin, profile);
		writeRecord(record);
		const addressEnv = new URL(
			`../../../deploy/contracts/${chain.id}.addresses.env`,
			import.meta.url,
		);
		writeFileSync(
			addressEnv,
			`# Public addresses only; source after the environment configuration.\nCHAIN_ID=${chain.id}\nCHAIN_NAME=${JSON.stringify(profile.name)}\nDEPLOY_CHAIN_ID=${chain.id}\nFACTORY_ADDRESS=${record.contracts.factory?.address}\nSPONSORSHIP_PAYMASTER_ADDRESS=${record.contracts.paymasterProxy?.address}\nTEST_PAYMASTER_ADDRESS=\nTEST_ERC20_ADDRESS=\n`,
		);
		execFileSync(
			process.execPath,
			["--import", "tsx", "scripts/generate-addresses.ts"],
			{ cwd: new URL("..", import.meta.url), stdio: "inherit" },
		);
		console.log(
			`\nCore deployment verified; registry regenerated. Public address configuration: deploy/contracts/${chain.id}.addresses.env. Commit deployments/${chain.id}.json and addresses.ts.\nNext: provision the new paymaster with the existing tenant UUIDs and sponsorship signer; fund operator/executor on this chain; run doctor --require-paymaster; update GIANO_CHAINS and all address overrides; roll the services; verify a sponsored transaction.\nCore deployment alone is NOT a ready-to-serve chain. Follow deploy/contracts/README.md.`,
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
		"Deployment stopped. Check network/RPC access, address inputs and committed release/record files. No further transactions will be sent. Inspect transaction receipts and rerun the same network/release to recover; see deploy/contracts/README.md. Provider error details are suppressed to protect credentials.",
	);
	process.exitCode = 1;
});
