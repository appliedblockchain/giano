/** Shared chain-profile launcher for the existing operator workflows. */
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs } from "node:util";
import { createPublicClient, getAddress, http } from "viem";
import {
	delayPolicyProblems,
	formatDuration,
	TIMELOCKED_FUNCTION_NAMES,
	type TimelockDelays,
} from "../timelock";
import { activateRehearsal, classDeployer, ENTRY_POINT_V09 } from "./config";
import {
	operatorInputProblems,
	SIGNED_RPC_COMMANDS,
	timelockCommand,
} from "./operator-commands";
import { type Plan, planCore } from "./plan";
import { inspectDeployment } from "./preflight";
import {
	listProfiles,
	loadProfile,
	type ProfileFile,
	REPO_ROOT,
	saveTimelockAddress,
} from "./profiles";
import { readRecord } from "./records";

class OperatorError extends Error {}

async function main() {
	const { values, positionals } = parseArgs({
		allowPositionals: true,
		options: {
			chain: { type: "string" },
			config: { type: "string" },
			"env-file": { type: "string" },
			plan: { type: "boolean" },
			/** Accept a paymaster implementation read from Upgraded logs (deploy/plan.ts). */
			"accept-unverified-implementation": { type: "boolean" },
			/**
			 * Pass --signed-rpc to the write (provision, timelock, handoff): each request it sends is
			 * signed with the key it sends from (deploy/signed-rpc.ts). This launcher's own checks only
			 * read, so they go unsigned.
			 */
			"signed-rpc": { type: "boolean" },
			help: { type: "boolean" },
		},
	});
	const [command] = positionals;
	if (values.help) {
		console.log(
			"pnpm contracts:funding|contracts:provision|contracts:sponsorship|contracts:doctor|contracts:timelock|contracts:handoff --chain <profile> [--env-file <dotenv-file>] [--plan] [--accept-unverified-implementation] [--signed-rpc]\n--config <file> selects a custom chain profile. Provisioning/policy/timelock writes require interactive confirmation.\n--plan on provision and sponsorship runs every check of a real run and shows what it would send, and sends nothing.\nOn an RPC that refuses eth_getStorageAt, the paymaster implementation can only be read from the proxy's Upgraded logs, which is not verified: provision and sponsorship refuse it unless --accept-unverified-implementation.\nOn an RPC that replaces `from` on unsigned calls (Silent Data), --signed-rpc makes provision, timelock and handoff sign every request with the key they send from.",
		);
		return;
	}
	if (
		![
			"funding",
			"provision",
			"sponsorship",
			"doctor",
			"timelock",
			"handoff",
		].includes(command)
	)
		throw new OperatorError(
			"Choose funding, provision, sponsorship, doctor, timelock or handoff.",
		);
	if (values["signed-rpc"] && !SIGNED_RPC_COMMANDS.includes(command))
		throw new OperatorError(
			`--signed-rpc applies to ${SIGNED_RPC_COMMANDS.join(", ")}: the commands that send transactions. ${command} sends none.`,
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
		// A rehearsal's stand-in deployer is accepted only once the RPC has shown it is an anvil fork.
		let rehearsal: Awaited<ReturnType<typeof activateRehearsal>>;
		try {
			rehearsal = await activateRehearsal(
				createPublicClient({ transport: http(rpc) }),
			);
		} catch (error) {
			throw new OperatorError(
				error instanceof Error ? error.message : String(error),
			);
		}
		if (rehearsal)
			console.log(
				`REHEARSAL on an anvil fork: stand-in deployer ${rehearsal}; confirmations are answered automatically.`,
			);
		const confirm = async (phrase: string): Promise<boolean> => {
			if (rehearsal) {
				console.log(`Type '${phrase}' to continue: ${phrase} (rehearsal)`);
				return true;
			}
			if (!rl)
				throw new OperatorError(
					"Writes require an interactive terminal. Use --plan to inspect the target first.",
				);
			return (
				(await rl.question(`Type '${phrase}' to continue: `)).trim() === phrase
			);
		};
		// provision and sponsorship plan by running every check of a real run, then their workflow in
		// plan mode, which sends nothing (G48 R3). The other commands stop here.
		const writes = command === "provision" || command === "sponsorship";
		if (values.plan && !writes) {
			console.log(
				"Read-only plan; no operation invoked. Provide operator credentials through --env-file or the environment. See deploy/contracts/README.md.",
			);
			return;
		}
		// A blank PAYMASTER_ROLE_ADMIN= line in an operator file means "not set", not "no admin".
		const admin = process.env.PAYMASTER_ROLE_ADMIN?.trim() || profile.roleAdmin;
		if (writes) {
			// Before any chain read, and every missing setting at once.
			const problems = operatorInputProblems(command, process.env, admin);
			if (problems.length)
				throw new OperatorError(
					`Correct the selected operator environment. No action was performed.\n  - ${problems.join("\n  - ")}`,
				);
		}
		if (command === "timelock" || command === "handoff") {
			await timelockWorkflow(
				command,
				selected,
				rpc,
				confirm,
				Boolean(values["signed-rpc"]),
			);
			return;
		}
		// Where this chain's contracts are: the record, the profile's overrides, else the class's
		// deterministic addresses (deploy/plan.ts).
		let plan: Plan;
		try {
			plan = await planCore(createPublicClient({ transport: http(rpc) }), {
				network: profile.network,
				signer: null,
				overrides: profile.addresses,
				record: readRecord(profile.chainId),
			});
		} catch {
			throw new OperatorError(
				"Could not read the chain's planned addresses. Check RPC access and retry. No action was performed.",
			);
		}
		const at = (key: "factory" | "paymasterProxy") =>
			plan.contracts.find((c) => c.key === key)?.actual ?? "";
		if (writes) {
			if (!classDeployer(profile.network))
				throw new OperatorError(
					`The ${profile.network} canonical deployer is not configured. Configure it and deploy core before provisioning or enabling sponsorship.`,
				);
			const checkClient = createPublicClient({ transport: http(rpc) });
			const { checks } = await inspectDeployment(
				checkClient,
				profile,
				profile.release,
				getAddress(admin as string),
				{
					signer: null,
					record: readRecord(profile.chainId),
					acceptUnverifiedImplementation: Boolean(
						values["accept-unverified-implementation"],
					),
				},
			);
			for (const check of checks)
				console.log(`${check.ok ? "OK" : "BLOCKED"}: ${check.message}`);
			if (checks.some((check) => !check.ok))
				throw new OperatorError(
					"Core deployment verification failed; rerun contracts:deploy --plan for the selected profile and resolve its blockers before operator writes.",
				);
			const proxy = at("paymasterProxy");
			const proxyCode = proxy
				? await checkClient.getCode({ address: proxy })
				: undefined;
			if (!proxyCode || proxyCode === "0x")
				throw new OperatorError(
					"Core paymaster is not deployed. Run contracts:deploy for this profile first.",
				);
			console.log(
				command === "provision"
					? "Provisioning sends transactions. Each rerun ADDS the configured tenant funding again; review amounts and existing balances."
					: "This updates tenant sponsorship policies through the configured wallet-api.",
			);
			if (values.plan) {
				console.log(
					"Plan: the checks above passed. The workflow runs its own checks next, and sends nothing.",
				);
			} else {
				if (!(await confirm(`${command} ${profile.chainId}`))) {
					console.log("Cancelled. No operation invoked.");
					return;
				}
				// Recheck after review, before handing credentials to the write workflow.
				try {
					if (
						(await createPublicClient({
							transport: http(rpc),
						}).getChainId()) !== profile.chainId
					)
						throw new OperatorError();
				} catch {
					throw new OperatorError(
						"RPC identity changed during review. No operation invoked.",
					);
				}
			}
		}
		const env = {
			...process.env,
			GIANO_PROFILE_LOADED: "1",
			// The scripts refuse development shortcuts (grant-all, a signer key) on a mainnet.
			GIANO_NETWORK: profile.network,
			ENTRYPOINT_ADDRESS: ENTRY_POINT_V09,
			CHAIN_ID: String(profile.chainId),
			CHAIN_NAME: profile.name,
			RPC_URL: rpc,
			DEPLOY_RPC_URL: rpc,
			DEPLOYER_MIN_ETH: profile.minDeployerBalanceEth,
			PAYMASTER_ROLE_ADMIN: admin ?? "",
			// The published timelock (G9), so doctor asserts the topology and delays (R4).
			PAYMASTER_TIMELOCK:
				process.env.PAYMASTER_TIMELOCK ?? profile.timelock?.address ?? "",
			PAYMASTER_TIMELOCK_DELAYS: profile.timelock
				? Object.entries(profile.timelock.delays)
						.map(([name, seconds]) => `${name}=${seconds}`)
						.join(",")
				: "",
			PAYMASTER_TIMELOCK_PROPOSERS: profile.timelock?.proposers.join(",") ?? "",
			// doctor knows the chain's class and checks mainnet deviations against the record.
			GIANO_PROFILE: selected.file,
			FACTORY_ADDRESS: at("factory"),
			SPONSORSHIP_PAYMASTER_ADDRESS: at("paymasterProxy"),
			TEST_PAYMASTER_ADDRESS: "",
			TEST_ERC20_ADDRESS: "",
			// provision-paymaster.sh passes --signed-rpc on when this is "1"; never taken from the
			// operator environment.
			GIANO_SIGNED_RPC: values["signed-rpc"] ? "1" : "",
			// The workflow checks and lists, and sends nothing, when this is "1" (--plan). Never taken
			// from the operator environment either.
			GIANO_PLAN: values.plan ? "1" : "",
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
/**
 * `timelock` deploys the profile's GianoTimelock (G9) and records its address in the profile;
 * `handoff` gives it every timelocked role and renounces the operator's ROLE_ADMIN. Both sign with
 * the current ROLE_ADMIN key: ROLE_ADMIN_PRIVATE_KEY, or DEPLOYER_PRIVATE_KEY as provisioning uses.
 * With `signedRpc`, deploy:cli signs every request with that key.
 */
async function timelockWorkflow(
	command: "timelock" | "handoff",
	selected: ProfileFile,
	rpc: string,
	confirm: (phrase: string) => Promise<boolean>,
	signedRpc: boolean,
): Promise<void> {
	const { profile } = selected;
	const timelock = profile.timelock;
	if (!timelock)
		throw new OperatorError(
			"Add a timelock section (proposers, executors and delays) to the chain profile first. See docs/PAYMASTER-TIMELOCK-RUNBOOK.md.",
		);
	const delays = timelock.delays as TimelockDelays;
	const problems = delayPolicyProblems(delays);
	if (problems.length)
		throw new OperatorError(
			`The profile's delay policy is unsafe:\n  ${problems.join("\n  ")}`,
		);
	if (command === "timelock" && timelock.proposers.length === 0)
		throw new OperatorError(
			"List the proposer Safe under timelock.proposers in the chain profile.",
		);
	if (command === "handoff" && !timelock.address)
		throw new OperatorError(
			"Deploy the timelock first (contracts:timelock); its address is then saved in the profile.",
		);
	const key =
		process.env.ROLE_ADMIN_PRIVATE_KEY ?? process.env.DEPLOYER_PRIVATE_KEY;
	if (!key)
		throw new OperatorError(
			"Provide the current ROLE_ADMIN operator key as ROLE_ADMIN_PRIVATE_KEY (or DEPLOYER_PRIVATE_KEY).",
		);

	console.log(
		`Delays: ${["minDelay", ...TIMELOCKED_FUNCTION_NAMES].map((name) => `${name} ${formatDuration(delays[name as keyof TimelockDelays])}`).join(", ")}`,
	);
	if (command === "handoff")
		console.log(
			`The hand-off gives ${timelock.address} every timelocked role and renounces your ROLE_ADMIN. Only the timelock can undo it, after the role delay.`,
		);
	if (!(await confirm(`${command} ${profile.chainId}`))) {
		console.log("Cancelled. No operation invoked.");
		return;
	}
	const args = timelockCommand(command, selected, rpc, signedRpc);
	const result = spawnSync(
		process.execPath,
		["--import", "tsx", "deploy/cli.ts", ...args],
		{
			cwd: resolve(REPO_ROOT, "packages/contracts"),
			env: { ...process.env, ROLE_ADMIN_PRIVATE_KEY: key },
			stdio: "inherit",
		},
	);
	if (result.status !== 0) {
		process.exitCode = result.status ?? 1;
		return;
	}
	if (command === "timelock") {
		const record = readRecord(profile.chainId);
		if (!record.timelock)
			throw new OperatorError("The timelock deployment was not recorded.");
		saveTimelockAddress(selected, record.timelock.address);
		console.log(
			`Saved the timelock address ${record.timelock.address} in ${selected.file}. Next: contracts:handoff, then contracts:doctor.`,
		);
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
