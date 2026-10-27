/** Shared chain-profile launcher for the existing operator workflows. */
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { createPublicClient, getAddress, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
	CANONICAL_DEPLOYER,
	DEPLOYER_IS_PLACEHOLDER,
	ENTRY_POINT_V09,
	LABELS,
} from "./config";
import { create3Address } from "./create3";
import { inspectDeployment } from "./preflight";
import { listProfiles, loadProfile, REPO_ROOT } from "./profiles";

class OperatorError extends Error {}

async function main() {
	const { values, positionals } = parseArgs({
		allowPositionals: true,
		options: {
			chain: { type: "string" },
			config: { type: "string" },
			"env-file": { type: "string" },
			plan: { type: "boolean" },
			help: { type: "boolean" },
		},
	});
	const [command] = positionals;
	if (values.help) {
		console.log(
			"pnpm contracts:funding|contracts:provision|contracts:sponsorship|contracts:doctor --chain <profile> [--env-file <dotenv-file>] [--plan]\n--config <file> selects a custom chain profile. Provisioning/policy writes require interactive confirmation.",
		);
		return;
	}
	if (!["funding", "provision", "sponsorship", "doctor"].includes(command))
		throw new OperatorError(
			"Choose funding, provision, sponsorship or doctor.",
		);
	const rl =
		process.stdin.isTTY && process.stdout.isTTY
			? createInterface({ input: process.stdin, output: process.stdout })
			: undefined;
	try {
		const selected = loadProfile(
			values.chain || values.config
				? { chain: values.chain, config: values.config }
				: {
						chain: await rl?.question(
							`Chain profile (${listProfiles().join(", ")}): `,
						),
					},
		);
		const { profile } = selected;
		if (values["env-file"]) {
			try {
				process.loadEnvFile(resolve(REPO_ROOT, values["env-file"]));
			} catch {
				throw new OperatorError(
					"Cannot load --env-file; supply a dotenv file (shell commands are not evaluated).",
				);
			}
		}
		for (const field of ["CHAIN_ID", "DEPLOY_CHAIN_ID"]) {
			if (process.env[field] && Number(process.env[field]) !== profile.chainId)
				throw new OperatorError(
					`${field} differs from the selected chain profile. Correct the environment before continuing.`,
				);
		}
		const rpc =
			process.env[profile.rpcUrlEnv] ??
			process.env.DEPLOY_RPC_URL ??
			profile.rpcUrl;
		try {
			if (
				(await createPublicClient({
					transport: http(rpc, { timeout: 15000, retryCount: 1 }),
				}).getChainId()) !== profile.chainId
			)
				throw new OperatorError();
		} catch {
			throw new OperatorError(
				"RPC identity/access check failed. Set the profile's RPC environment variable to the correct network and retry. No action was performed.",
			);
		}
		console.log(`${profile.name} (${profile.chainId}): ${command}`);
		if (values.plan) {
			console.log(
				"Read-only plan; no operation invoked. Provide operator credentials through --env-file or the environment. See deploy/contracts/README.md.",
			);
			return;
		}
		if (["provision", "sponsorship"].includes(command)) {
			if (DEPLOYER_IS_PLACEHOLDER)
				throw new OperatorError(
					"The canonical deployer is still the placeholder. Configure it and deploy core before provisioning or enabling sponsorship.",
				);
			if (command === "provision") {
				const admin = process.env.PAYMASTER_ROLE_ADMIN ?? profile.roleAdmin;
				try {
					if (
						!admin ||
						getAddress(
							privateKeyToAccount(
								process.env.DEPLOYER_PRIVATE_KEY as `0x${string}`,
							).address,
						) !== getAddress(admin)
					)
						throw new OperatorError();
				} catch {
					throw new OperatorError(
						"Provide the ROLE_ADMIN operator key as DEPLOYER_PRIVATE_KEY and its public address in the profile (or PAYMASTER_ROLE_ADMIN). This provisioning workflow requires an EOA admin.",
					);
				}
			}
			const needed =
				command === "provision"
					? ["SPONSORSHIP_SIGNER_KEY", "PAYMASTER_TENANTS"]
					: ["ADMIN_API_KEY", "TENANT_SLUG", "WALLET_API_URL"];
			for (const name of needed)
				if (!process.env[name]?.trim())
					throw new OperatorError(
						`Provide ${name} in the selected operator environment before continuing.`,
					);
			const admin = process.env.PAYMASTER_ROLE_ADMIN ?? profile.roleAdmin;
			if (!admin)
				throw new OperatorError(
					"Persist ROLE_ADMIN in the chain profile or provide PAYMASTER_ROLE_ADMIN before operator writes.",
				);
			const checkClient = createPublicClient({ transport: http(rpc) });
			const checks = await inspectDeployment(
				checkClient,
				profile,
				profile.release,
				getAddress(admin),
			);
			if (checks.some((check) => !check.ok))
				throw new OperatorError(
					"Core deployment verification failed; rerun contracts:deploy --plan for the selected profile and resolve its blockers before operator writes.",
				);
			const proxyCode = await checkClient.getCode({
				address: create3Address(CANONICAL_DEPLOYER, LABELS.paymasterProxy),
			});
			if (!proxyCode || proxyCode === "0x")
				throw new OperatorError(
					"Core paymaster is not deployed. Run contracts:deploy for this profile first.",
				);
			console.log(
				command === "provision"
					? "Provisioning sends transactions. Each rerun ADDS the configured tenant funding again; review amounts and existing balances."
					: "This updates tenant sponsorship policies through the configured wallet-api.",
			);
			const confirmation = `${command} ${profile.chainId}`;
			if (!rl)
				throw new OperatorError(
					"Writes require an interactive terminal. Use --plan to inspect the target first.",
				);
			if (
				(await rl.question(`Type '${confirmation}' to continue: `)).trim() !==
				confirmation
			) {
				console.log("Cancelled. No operation invoked.");
				return;
			}
			// Recheck after review, before handing credentials to the write workflow.
			try {
				if (
					(await createPublicClient({ transport: http(rpc) }).getChainId()) !==
					profile.chainId
				)
					throw new OperatorError();
			} catch {
				throw new OperatorError(
					"RPC identity changed during review. No operation invoked.",
				);
			}
		}
		const env = {
			...process.env,
			GIANO_PROFILE_LOADED: "1",
			ENTRYPOINT_ADDRESS: ENTRY_POINT_V09,
			CHAIN_ID: String(profile.chainId),
			CHAIN_NAME: profile.name,
			RPC_URL: rpc,
			DEPLOY_RPC_URL: rpc,
			DEPLOYER_MIN_ETH: profile.minDeployerBalanceEth,
			PAYMASTER_ROLE_ADMIN:
				process.env.PAYMASTER_ROLE_ADMIN ?? profile.roleAdmin ?? "",
			FACTORY_ADDRESS: create3Address(CANONICAL_DEPLOYER, LABELS.factory),
			SPONSORSHIP_PAYMASTER_ADDRESS: create3Address(
				CANONICAL_DEPLOYER,
				LABELS.paymasterProxy,
			),
			TEST_PAYMASTER_ADDRESS: "",
			TEST_ERC20_ADDRESS: "",
		};
		const scripts: Record<string, string> = {
			funding: "print-funding.sh",
			provision: "provision-paymaster.sh",
			sponsorship: "provision-sponsorship.sh",
		};
		const result =
			command === "doctor"
				? spawnSync(
						process.execPath,
						[
							"--import",
							"tsx",
							"scripts/doctor.ts",
							"chain",
							"--require-paymaster",
						],
						{
							cwd: resolve(REPO_ROOT, "packages/contracts"),
							env,
							stdio: "inherit",
						},
					)
				: spawnSync(
						"bash",
						[resolve(REPO_ROOT, "deploy/contracts", scripts[command])],
						{ cwd: REPO_ROOT, env, stdio: "inherit" },
					);
		process.exitCode = result.status ?? 1;
	} finally {
		rl?.close();
	}
}
main().catch((error: unknown) => {
	console.error(
		error instanceof OperatorError
			? error.message
			: "Operation stopped. Check the profile, operator inputs and RPC access. Provider details suppressed to protect credentials.",
	);
	process.exitCode = 1;
});
