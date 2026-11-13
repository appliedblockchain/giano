/**
 * The deployment rehearsal: walks a public testnet's real deployment path on an anvil fork of it,
 * with throwaway anvil keys, and reports each step (deploy/contracts/README.md, "Rehearsal").
 *
 *   pnpm contracts:rehearse [--chain base-sepolia] [--release v3] [--fork-url <rpc>]
 *                           [--fork-block <n>] [--platform] [--keep]
 *
 * Every step is the operator command a real adoption runs, unchanged: the guided wizard, provision,
 * timelock, hand-off, an upgrade proposed to and executed through the timelock, then a plan,
 * provision and doctor run against the upgraded chain. The only difference from a real run is the
 * deployer: GIANO_REHEARSAL_DEPLOYER stands in for the class's canonical deployer, which the
 * tooling accepts only on a fork (deploy/config.ts activateRehearsal). Everything written goes to
 * deploy/rehearsal/ (ignored); deployments/, addresses.ts and deploy/chains/ are never touched.
 *
 * --platform then brings up the external-chain demo stack (docker-compose.chain.yml) against the
 * fork and installs the tenant's sponsorship rules, for the browser smoke test
 * (e2e/playwright.rehearsal.config.ts).
 *
 * Keys: throwaway keys derived from fixed labels (rehearsalKey), funded on the fork. Never real keys.
 */
import { spawnSync } from "node:child_process";
import {
	copyFileSync,
	mkdirSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { join, relative } from "node:path";
import { parseArgs } from "node:util";
import {
	type Address,
	createPublicClient,
	createTestClient,
	createWalletClient,
	defineChain,
	getAddress,
	type Hex,
	http,
	keccak256,
	parseEther,
	toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { forkUrlOf, REHEARSAL_DEPLOYER_ENV } from "../deploy/config";
import { paymasterUpgradeProposal } from "../deploy/deploy";
import { loadProfile, REPO_ROOT } from "../deploy/profiles";
import { REHEARSAL_DIR, readRecord } from "../deploy/records";
import { IMPLEMENTATION_SLOT, implementationFromSlot } from "../erc1967";

/**
 * The rehearsal's own throwaway keys, derived from fixed labels and funded on the fork. Not anvil's
 * development accounts: those keys are public, so on a public testnet they carry state strangers left
 * behind, EIP-7702 delegations included, and a rehearsal must not depend on it.
 */
const rehearsalKey = (role: string): Hex =>
	keccak256(toHex(`giano-rehearsal:${role}`));

/** Who plays which part. Each is a different account, so a wrong-key bug shows up as a failure. */
const KEYS = {
	operator: rehearsalKey("operator"), // bootstrap ROLE_ADMIN, provisioning
	signer: rehearsalKey("signer"), // wallet-api's sponsorship signer
	tenantWithdraw: rehearsalKey("tenant-withdraw"),
	executor: rehearsalKey("executor"), // giano-bundler
	proposer: rehearsalKey("proposer"), // the timelock's proposer (a Safe in a real deployment)
	deployer: rehearsalKey("deployer"), // stands in for the class's canonical deployer
	anyone: rehearsalKey("anyone"), // executes the ready timelock operation (open execution)
} as const satisfies Record<string, Hex>;

/** One holder per immediate paymaster role: the production topology, never every role on one key. */
const ROLE_HOLDERS = [
	"SIGNER_ADMIN",
	"PARAM_ADMIN",
	"PAUSER",
	"STAKE_ADMIN",
	"TENANT_ADMIN",
	"FEE_COLLECTOR",
].map((role) => ({
	variable: `ROLE_HOLDER_${role}`,
	holder: privateKeyToAccount(rehearsalKey(`holder:${role}`)).address,
}));
const address = (key: Hex): Address => privateKeyToAccount(key).address;

const TENANT = {
	slug: "rehearsal",
	id: "33333333-3333-4333-8333-333333333333",
	adminKey: "rehearsal-admin-key-0001",
};

const { values } = parseArgs({
	options: {
		chain: { type: "string", default: "base-sepolia" },
		release: { type: "string" },
		"fork-url": { type: "string" },
		"fork-block": { type: "string" },
		"fork-port": { type: "string", default: "18545" },
		platform: { type: "boolean", default: false },
		keep: { type: "boolean", default: false },
		help: { type: "boolean", default: false },
	},
});
if (values.help) {
	console.log(readFileSync(import.meta.filename, "utf8").split("*/")[0]);
	process.exit(0);
}

const shipped = loadProfile({ chain: values.chain });
const profile = structuredClone(shipped.profile);
if (profile.network !== "testnet")
	throw new Error(
		`the rehearsal walks a testnet's deployment path; ${values.chain} is ${profile.network}`,
	);
const forkUrl =
	values["fork-url"] ?? process.env[profile.rpcUrlEnv] ?? profile.rpcUrl;
const forkRpc = `http://127.0.0.1:${values["fork-port"]}`;
const release = values.release ?? profile.release;
const logsDir = join(REHEARSAL_DIR, "logs");
const profileCopy = join(REHEARSAL_DIR, `${values.chain}.json`);
const operatorEnv = join(REHEARSAL_DIR, "operator.env");
const rel = (file: string) => relative(REPO_ROOT, file);

const chain = defineChain({
	id: profile.chainId,
	name: `${profile.name} (fork)`,
	nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
	rpcUrls: { default: { http: [forkRpc] } },
});
const publicClient = createPublicClient({ chain, transport: http(forkRpc) });
const testClient = createTestClient({
	chain,
	mode: "anvil",
	transport: http(forkRpc),
});

/** The environment every step runs with: the rehearsal on, and nothing else of the caller's. */
const stepEnv: NodeJS.ProcessEnv = Object.fromEntries(
	Object.entries({
		PATH: process.env.PATH,
		HOME: process.env.HOME,
		NODE_OPTIONS: process.env.NODE_OPTIONS,
		DOCKER_HOST: process.env.DOCKER_HOST,
		[REHEARSAL_DEPLOYER_ENV]: address(KEYS.deployer),
		[profile.rpcUrlEnv]: forkRpc,
	}).filter(([, value]) => value !== undefined),
);
const recordsDir = join(REHEARSAL_DIR, "records");

type Outcome = "pass" | "fail" | "skip";
type Step = {
	name: string;
	/** Steps that must have passed for this one to run. */
	needs: string[];
	run: () => Promise<void> | void;
	outcome?: Outcome;
	detail?: string;
};

let stepNumber = 0;
/** Runs a repository command as an operator would, from the repository root, logging its output. */
function command(
	name: string,
	args: string[],
	env: NodeJS.ProcessEnv = {},
): void {
	stepNumber += 1;
	const log = join(
		logsDir,
		`${String(stepNumber).padStart(2, "0")}-${name}.log`,
	);
	const result = spawnSync(args[0], args.slice(1), {
		cwd: REPO_ROOT,
		env: { ...stepEnv, ...env },
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
	});
	const output = `$ ${args.join(" ")}\n${result.stdout ?? ""}${result.stderr ?? ""}`;
	writeFileSync(log, output);
	if (result.status !== 0) {
		const tail = output.trim().split("\n").slice(-12).join("\n    ");
		throw new Error(`exit ${result.status}; see ${rel(log)}\n    ${tail}`);
	}
}
/** Runs a command that must fail, with output matching `expected`. */
function commandFails(name: string, args: string[], expected: RegExp): void {
	try {
		command(name, args);
	} catch (error) {
		const log = join(
			logsDir,
			`${String(stepNumber).padStart(2, "0")}-${name}.log`,
		);
		if (expected.test(readFileSync(log, "utf8"))) return;
		throw error;
	}
	throw new Error(`expected it to refuse (${expected}), but it succeeded`);
}
const contracts = (sub: string, ...args: string[]) => [
	"bash",
	"deploy/contracts/run.sh",
	sub,
	...args,
];

function compose(project: string, files: string[], ...args: string[]) {
	return [
		"docker",
		"compose",
		"-p",
		project,
		...files.flatMap((f) => ["-f", f]),
		...args,
	];
}
const forkCompose = (...args: string[]) =>
	compose("giano-fork", ["deploy/docker-compose.fork.yml"], ...args);

async function waitForFork(): Promise<void> {
	for (let i = 0; i < 30; i++) {
		try {
			if ((await publicClient.getChainId()) === profile.chainId) return;
		} catch {}
		await new Promise((r) => setTimeout(r, 1000));
	}
	throw new Error(`the fork at ${forkRpc} did not answer`);
}

let forkBlock = values["fork-block"];
/** Compose interpolates the whole file for every command, `down` included. */
const forkEnv = () => ({
	FORK_URL: forkUrl,
	FORK_BLOCK_NUMBER: forkBlock ?? "latest",
	FORK_PORT: values["fork-port"],
});
let timelock: Address | undefined;
let upgradeTarget: Address | undefined;

const steps: Step[] = [
	{
		name: "fork",
		needs: [],
		run: async () => {
			// The latest block unless pinned: a public, non-archive RPC serves only recent state.
			if (!forkBlock) {
				const source = createPublicClient({ transport: http(forkUrl) });
				forkBlock = String(await source.getBlockNumber());
			}
			// The fork reads its state from the public RPC, which can drop a connection at start; retry,
			// and show anvil's own error when it never comes up.
			for (let attempt = 1; ; attempt++) {
				command(
					"fork-down",
					forkCompose("down", "--remove-orphans"),
					forkEnv(),
				);
				command("fork-up", forkCompose("up", "-d", "--wait"), forkEnv());
				try {
					await waitForFork();
					break;
				} catch (error) {
					if (attempt < 3) continue;
					const logs = spawnSync(
						"docker",
						["compose", "-p", "giano-fork", "logs", "--tail", "8", "fork"],
						{
							cwd: REPO_ROOT,
							env: { ...stepEnv, ...forkEnv() },
							encoding: "utf8",
						},
					);
					throw new Error(
						`${(error as Error).message} after ${attempt} attempts; anvil said:\n    ${(logs.stdout ?? "").trim().split("\n").join("\n    ")}`,
					);
				}
			}
			if ((await forkUrlOf(publicClient)) === null)
				throw new Error("the node does not report a fork");
		},
	},
	{
		name: "prepare",
		needs: ["fork"],
		run: async () => {
			for (const key of Object.values(KEYS))
				await testClient.setBalance({
					address: address(key),
					value: parseEther("100"),
				});
			// The profile as an operator would fill it in: a ROLE_ADMIN, a proposer, the release.
			profile.release = release;
			profile.roleAdmin = address(KEYS.operator);
			if (!profile.timelock)
				throw new Error(`${values.chain} has no timelock section`);
			profile.timelock.address = null;
			profile.timelock.proposers = [address(KEYS.proposer)];
			profile.timelock.executors = [];
			writeFileSync(profileCopy, `${JSON.stringify(profile, null, "\t")}\n`);
			writeFileSync(
				operatorEnv,
				[
					"# Written by pnpm contracts:rehearse. Throwaway keys, for a fork only.",
					`DEPLOYER_PRIVATE_KEY=${KEYS.operator}`,
					// By address, as with an HSM-held signer; the key is for the platform stack's wallet-api.
					`SPONSORSHIP_SIGNER_ADDRESS=${address(KEYS.signer)}`,
					`SPONSORSHIP_SIGNER_KEY=${KEYS.signer}`,
					...ROLE_HOLDERS.map(
						({ variable, holder }) => `${variable}=${holder}`,
					),
					`BUNDLER_EXECUTOR_PRIVATE_KEYS=${KEYS.executor}`,
					"STAKE_ETH=0.1",
					"UNSTAKE_DELAY=86400",
					"TENANT_FUND_ETH=0.05",
					`TENANT_WITHDRAW_ADDRESS=${address(KEYS.tenantWithdraw)}`,
					`PAYMASTER_TENANTS=${TENANT.slug}:${TENANT.id}`,
					`TENANT_SLUG=${TENANT.slug}`,
					`TENANT_ID=${TENANT.id}`,
					`ADMIN_API_KEY=${TENANT.adminKey}`,
					// A public testnet has no demo ERC-20, and an empty allowlist sponsors nothing, so the
					// tenant allow-lists a contract of its own. Multicall3 stands in: it is on every chain
					// at this address, and the smoke test's self-call never touches it.
					"SPONSOR_ALLOWLIST=0xcA11bde05977b3631167028862bE2a173976CA11",
					"WALLET_ORIGIN=http://wallet.localhost:8081",
					"WALLET_API_URL=http://wallet.localhost:8081/api",
					"RP_ID=wallet.localhost",
					'RP_NAME="Giano Rehearsal"',
					'BRAND_NAME="Giano Rehearsal"',
					'GIANO_ALLOWED_DAPP_ORIGINS=["http://app.localhost:4400"]',
					'TENANT_CORS_ORIGINS=["http://app.localhost:4400"]',
					"OPEN_REGISTRATION=true",
					"METRICS_BEARER_TOKEN=rehearsal-metrics-token-0001",
					"GIANO_ENVIRONMENT=local-sepolia",
					// The platform containers reach the fork through the host.
					`RPC_URL=http://host.docker.internal:${values["fork-port"]}`,
					"",
				].join("\n"),
			);
		},
	},
	{
		name: "deploy",
		needs: ["prepare"],
		run: () =>
			command(
				"deploy",
				contracts(
					"deploy",
					"--config",
					profileCopy,
					"--rpc",
					forkRpc,
					"--release",
					release,
				),
				{ CANONICAL_DEPLOYER_PRIVATE_KEY: KEYS.deployer },
			),
	},
	{
		name: "provision",
		needs: ["deploy"],
		run: () =>
			command(
				"provision",
				contracts(
					"provision",
					"--config",
					profileCopy,
					"--env-file",
					operatorEnv,
				),
			),
	},
	{
		name: "timelock",
		needs: ["provision"],
		run: () => {
			command(
				"timelock",
				contracts(
					"timelock",
					"--config",
					profileCopy,
					"--env-file",
					operatorEnv,
				),
			);
			const saved = JSON.parse(readFileSync(profileCopy, "utf8"));
			timelock = getAddress(saved.timelock.address);
		},
	},
	{
		name: "handoff",
		needs: ["timelock"],
		run: () =>
			command(
				"handoff",
				contracts(
					"handoff",
					"--config",
					profileCopy,
					"--env-file",
					operatorEnv,
				),
			),
	},
	{
		name: "upgrade-propose",
		needs: ["handoff"],
		run: () => {
			// The class deployer places the upgrade target, as on a real chain; the timelock proposal
			// goes to the proposer.
			command(
				"upgrade-propose",
				[
					"pnpm",
					"--filter",
					"@appliedblockchain/giano-contracts",
					"deploy:cli",
					"upgrade",
					"--rpc",
					forkRpc,
					"--chain-config",
					profileCopy,
					"--contract",
					"paymaster",
					"--timelock",
					timelock as string,
				],
				{ DEPLOYER_PRIVATE_KEY: KEYS.deployer },
			);
			const record = readRecord(profile.chainId, undefined, recordsDir);
			const target = [...record.upgrades]
				.reverse()
				.find((u) => u.of === "paymasterImplementation");
			if (!target) throw new Error("no paymaster upgrade target was recorded");
			upgradeTarget = target.address;
		},
	},
	{
		name: "upgrade-execute",
		needs: ["upgrade-propose"],
		run: async () => {
			const record = readRecord(profile.chainId, undefined, recordsDir);
			const proxy = record.contracts.paymasterProxy?.address;
			if (!proxy || !timelock || !upgradeTarget)
				throw new Error("missing proxy, timelock or target");
			const proposal = await paymasterUpgradeProposal(
				publicClient as never,
				timelock,
				proxy,
				upgradeTarget,
			);
			const send = async (key: Hex, data: Hex) => {
				const wallet = createWalletClient({
					chain,
					transport: http(forkRpc),
					account: privateKeyToAccount(key),
				});
				const hash = await wallet.sendTransaction({ to: timelock, data });
				const receipt = await publicClient.waitForTransactionReceipt({ hash });
				if (receipt.status !== "success") throw new Error(`reverted: ${hash}`);
			};
			await send(KEYS.proposer, proposal.schedule);
			// Wait out the delay without waiting: the fork's clock is ours.
			await testClient.increaseTime({ seconds: Number(proposal.delay) + 1 });
			await testClient.mine({ blocks: 1 });
			await send(KEYS.anyone, proposal.execute);
			const slot = await publicClient.getStorageAt({
				address: proxy,
				slot: IMPLEMENTATION_SLOT,
			});
			const now = implementationFromSlot(slot);
			if (!now || getAddress(now) !== getAddress(upgradeTarget))
				throw new Error(`the proxy points at ${now}, not ${upgradeTarget}`);
		},
	},
	{
		name: "plan-after-upgrade",
		needs: ["upgrade-execute"],
		run: () =>
			command(
				"plan-after-upgrade",
				contracts(
					"deploy",
					"--plan",
					"--config",
					profileCopy,
					"--rpc",
					forkRpc,
				),
			),
	},
	{
		// The Helm deployer Job's run: core without a key verifies what is in place and saves the record.
		name: "verify-after-upgrade",
		needs: ["upgrade-execute"],
		run: () => {
			command("verify-after-upgrade", [
				"pnpm",
				"--filter",
				"@appliedblockchain/giano-contracts",
				"deploy:cli",
				"core",
				"--rpc",
				forkRpc,
				"--chain-config",
				profileCopy,
				"--role-admin",
				address(KEYS.operator),
			]);
			const record = readRecord(profile.chainId, undefined, recordsDir);
			const named = record.contracts.paymasterImplementation?.address;
			if (
				!named ||
				!upgradeTarget ||
				getAddress(named) !== getAddress(upgradeTarget)
			)
				throw new Error(
					`the record names ${named} as the paymaster implementation, not the executed upgrade ${upgradeTarget}`,
				);
		},
	},
	{
		// Bootstrap provisioning has nothing left to do once ROLE_ADMIN is the timelock's: it must refuse,
		// and say why.
		name: "provision-refused-after-handoff",
		needs: ["upgrade-execute"],
		run: () =>
			commandFails(
				"provision-refused-after-handoff",
				contracts(
					"provision",
					"--config",
					profileCopy,
					"--env-file",
					operatorEnv,
				),
				/held by the timelock/,
			),
	},
	{
		name: "doctor",
		needs: ["upgrade-execute"],
		run: () =>
			command(
				"doctor",
				contracts("doctor", "--config", profileCopy, "--env-file", operatorEnv),
			),
	},
];

const platformCompose = (...args: string[]) =>
	compose(
		"giano-rehearsal",
		["deploy/docker-compose.chain.yml", "deploy/docker-compose.rehearsal.yml"],
		"--env-file",
		operatorEnv,
		"--env-file",
		join(REHEARSAL_DIR, `${profile.chainId}.addresses.env`),
		...args,
	);
if (values.platform)
	steps.push(
		{
			// The upgrade step warped the fork past the timelock delay, so its clock now runs ahead of the
			// wall clock that wallet-api signs `validUntil` from, and every sponsorship would arrive
			// already expired (AA32). A real chain's clock is the wall clock: put the fork's back on it.
			name: "clock-reset",
			needs: ["doctor"],
			run: async () => {
				// evm_setTime, not setNextBlockTimestamp: anvil refuses a next block earlier than the last.
				const reset = await fetch(forkRpc, {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({
						jsonrpc: "2.0",
						id: 1,
						method: "evm_setTime",
						params: [Math.floor(Date.now() / 1000)],
					}),
				});
				const body = (await reset.json()) as { error?: { message: string } };
				if (body.error) throw new Error(`evm_setTime: ${body.error.message}`);
				await testClient.mine({ blocks: 1 });
				const block = await publicClient.getBlock();
				const skew = Number(block.timestamp) - Math.floor(Date.now() / 1000);
				if (Math.abs(skew) > 30)
					throw new Error(
						`the fork's clock is still ${skew}s off the wall clock`,
					);
			},
		},
		{
			name: "platform-up",
			needs: ["clock-reset"],
			run: () => {
				command(
					"platform-down",
					platformCompose("down", "-v", "--remove-orphans"),
				);
				command(
					"platform-up",
					platformCompose("up", "--build", "-d", "--wait"),
				);
			},
		},
		{
			name: "sponsorship-rules",
			needs: ["platform-up"],
			run: () =>
				command(
					"sponsorship-rules",
					contracts(
						"sponsorship",
						"--config",
						profileCopy,
						"--env-file",
						operatorEnv,
					),
				),
		},
		{
			name: "browser-smoke",
			needs: ["sponsorship-rules"],
			run: () => {
				const record = readRecord(profile.chainId, undefined, recordsDir);
				command(
					"browser-smoke",
					[
						"pnpm",
						"--filter",
						"@appliedblockchain/giano-e2e",
						"test:rehearsal",
					],
					{
						REHEARSAL_FORK_RPC: forkRpc,
						REHEARSAL_CHAIN_ID: String(profile.chainId),
						SPONSORSHIP_PAYMASTER_ADDRESS:
							record.contracts.paymasterProxy?.address ?? "",
						TENANT_ID: TENANT.id,
					},
				);
			},
		},
	);

async function main() {
	rmSync(REHEARSAL_DIR, { recursive: true, force: true });
	mkdirSync(logsDir, { recursive: true });
	copyFileSync(
		shipped.file,
		join(REHEARSAL_DIR, `${values.chain}.shipped.json`),
	);
	console.log(
		`Rehearsing ${profile.name} (${profile.chainId}), release ${release}, on a fork of ${new URL(forkUrl).origin}\nStand-in deployer ${address(KEYS.deployer)}. Output in ${rel(REHEARSAL_DIR)}/.\n`,
	);
	const outcome = new Map<string, Outcome>();
	for (const step of steps) {
		if (step.needs.some((n) => outcome.get(n) !== "pass")) {
			step.outcome = "skip";
			step.detail = `needs ${step.needs.filter((n) => outcome.get(n) !== "pass").join(", ")}`;
		} else {
			try {
				await step.run();
				step.outcome = "pass";
			} catch (error) {
				step.outcome = "fail";
				step.detail = error instanceof Error ? error.message : String(error);
			}
		}
		outcome.set(step.name, step.outcome);
		const mark = { pass: "✓", fail: "✗", skip: "-" }[step.outcome];
		console.log(
			`${mark} ${step.name}${step.detail ? `\n    ${step.detail}` : ""}`,
		);
		if (step.name === "fork" && forkBlock)
			console.log(`    forked at block ${forkBlock}`);
	}
	const failed = steps.filter((s) => s.outcome !== "pass");
	console.log(
		`\n${steps.length - failed.length}/${steps.length} steps passed.${values.keep || values.platform ? ` The fork is still running at ${forkRpc}.` : ""}`,
	);
	if (!values.keep && !values.platform)
		command("fork-down", forkCompose("down", "--remove-orphans"), forkEnv());
	process.exitCode = failed.length ? 1 : 0;
}

await main();
