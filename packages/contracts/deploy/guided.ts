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
	type Hex,
	http,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { releaseOf } from "../release-code";
import { CONTRACT_OF, classDeployer, ENTRY_POINT_V09 } from "./config";
import { deployCore } from "./deploy";
import {
	CORE_KEYS,
	deviationGate,
	deviationWarning,
	fixedAddresses,
	type Plan,
	planCore,
} from "./plan";
import {
	inspectDeployment,
	profileCoreConfig,
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
import { readRecord, recordDeviations, writeRecord } from "./records";
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
		const deployer = classDeployer(profile.network);
		console.log(
			`\n${profile.name} (${profile.chainId}, ${profile.network}) / release ${version}\nCanonical ${profile.network} deployer: ${deployer ?? "NOT CONFIGURED"}\nPaymaster ROLE_ADMIN: ${admin}\nFee: ${profile.paymaster.defaultFeeWei} wei; post-op allowance: ${profile.paymaster.postOpGasAllowance} gas; penalty: ${profile.paymaster.penaltyBps} bps.\nNo test ERC-20 or permissive paymaster will be deployed (R-29).`,
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
		} else
			console.log(
				`INFO: No signing key supplied. For execution, load the ${profile.network} canonical deployer key from its 1Password item into CANONICAL_DEPLOYER_PRIVATE_KEY in this shell only, and rerun; plans do not need it.`,
			);
		// Never silently replace a record that cannot be read: it is the chain's deployment history.
		let record: ReturnType<typeof readRecord>;
		try {
			record = readRecord(chain.id);
		} catch (error) {
			throw new GuidanceError(
				`The existing deployment record for chain ${chain.id} is unreadable (${error instanceof Error ? error.message : String(error)}). Archive and review it before deploying; do not overwrite it blindly. No transactions sent.`,
			);
		}
		const signer = account?.address ?? null;
		const { checks, plan } = await inspectDeployment(
			client,
			profile,
			version,
			admin,
			{ signer, record },
		);
		for (const check of checks)
			console.log(`${check.ok ? "OK" : "BLOCKED"}: ${check.message}`);
		for (const blocker of blockers) console.log(`BLOCKED: ${blocker}`);
		if (!plan || blockers.length || checks.some((check) => !check.ok)) {
			process.exitCode = 1;
			return;
		}
		if (plan.deviations.length && profile.network !== "mainnet")
			console.log(
				`\nDeviations from the deterministic ${profile.network} addresses (reported and recorded; a testnet needs no extra confirmation):\n${plan.deviations.map((d) => `  - ${d.key}: expected ${d.expected}, actual ${d.actual} (${d.reason})`).join("\n")}`,
			);
		if (profile.network === "mainnet" && plan.deviations.length)
			for (const line of deviationWarning(plan, profile.name))
				console.log(line);
		// Only a run that goes on to sign confirms; a read-only plan shows the warning above and stops.
		const signs = Boolean(rl && !values.plan);
		const gate = deviationGate(plan, selected.id, {
			interactive: signs,
			signs,
		});
		if (gate.kind === "refuse") {
			console.log(`BLOCKED: ${gate.reason}`);
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
				"Load the canonical deployer key from its 1Password item into CANONICAL_DEPLOYER_PRIVATE_KEY in this shell and rerun. No transactions sent.",
			);
		if (
			gate.kind === "confirm" &&
			(await ask(
				`This deployment deviates on a mainnet. Type '${gate.phrase}' to accept the deviations above (anything else cancels)`,
			)) !== gate.phrase
		) {
			console.log("Cancelled. No transactions sent.");
			return;
		}
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
		const fresh = await inspectDeployment(client, profile, version, admin, {
			signer,
			record,
		});
		if (
			!fresh.plan ||
			fresh.checks.some((check) => !check.ok) ||
			JSON.stringify(fresh.plan.deviations) !== JSON.stringify(plan.deviations)
		)
			throw new GuidanceError(
				"Requirements or deviations changed during review. Rerun the plan. No transactions sent.",
			);
		const walletClient = createWalletClient({ chain, transport, account });
		// The record names the key that deployed; a rerun that finds everything in place leaves it.
		if (plan.contracts.some((c) => c.code.state === "empty"))
			record.deployer = account.address;
		// Before the first transaction: deployCore checkpoints the record after every contract, so an
		// interrupted run still keeps the deviations the operator confirmed, with their reasons.
		recordDeviations(record, plan.deviations, gate.kind === "confirm");
		writeRecord(record);
		await deployCore(
			{
				publicClient: client,
				walletClient,
				deployer: account.address,
				network: profile.network,
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
			fixedAddresses(fresh.plan),
		);
		for (const key of CORE_KEYS) {
			const deployed = record.contracts[key];
			const code = deployed
				? await client.getCode({ address: deployed.address })
				: undefined;
			if (!code || !releaseOf(CONTRACT_OF[key], code, deployed?.address))
				throw new GuidanceError(
					`Post-deployment code verification failed for ${key}. Do not serve this chain.`,
				);
		}
		const after: Plan = await planCore(client, {
			network: profile.network,
			signer,
			overrides: profile.addresses,
			record,
		});
		for (const warning of await verifyCoreState(
			client,
			admin,
			profileCoreConfig(profile),
			after,
		))
			console.warn(`⚠ ${warning}`);
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
