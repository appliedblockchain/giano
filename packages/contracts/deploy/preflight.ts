/** Read-only gates shared by the guided deployer, the operator workflows and their regression tests. */
import {
	type Address,
	getAddress,
	type Hex,
	keccak256,
	type PublicClient,
	parseEther,
	zeroAddress,
} from "viem";
import { isCanonicalEntryPointCode } from "../entrypoint";
import { proxyImplementation } from "../erc1967";
import { gianoPaymasterAbi, gianoTimelockAbi } from "../generated";
import { releaseOf } from "../release-code";
import {
	delayPolicyProblems,
	delayShortfalls,
	formatDuration,
	paymasterSelector,
	TIMELOCKED_FUNCTION_NAMES,
	type TimelockDelays,
} from "../timelock";
import {
	DEPLOYERS,
	ENTRY_POINT_V09,
	isClassDeployer,
	type NetworkClass,
} from "./config";
import { CREATEX_ADDRESS } from "./create3";
import type { PaymasterParams } from "./deploy";
import {
	CORE_KEYS,
	formatPlan,
	IMPLEMENTATION_SLOT,
	type Plan,
	planCore,
} from "./plan";
import { type ChainProfile, paymasterParams } from "./profiles";
import type { DeploymentRecord } from "./records";

export { CORE_KEYS, IMPLEMENTATION_SLOT };

// CreateX upstream README, Security Considerations (pinned runtime hash).
export const CREATEX_CODEHASH =
	"0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f";

export function roleAdmin(value: string): Address {
	const address = getAddress(value);
	if (address === zeroAddress)
		throw new Error("ROLE_ADMIN must be a nonzero address.");
	return address;
}

/**
 * Refuses a deployer as the paymaster's ROLE_ADMIN on a non-local chain: the signing key or a
 * configured class deployer. A deployer key is a development-team key outside ABIP-8 only because it
 * holds no role on what it deploys (docs/key-ceremony.md).
 */
export function assertRoleAdminNotDeployer(
	admin: Address,
	signer: Address | null,
	local: boolean,
): void {
	if (local) return;
	if (
		isClassDeployer(admin) ||
		(signer !== null && getAddress(signer) === getAddress(admin))
	)
		throw new GateError(
			`ROLE_ADMIN ${admin} is a deployer key. The paymaster's role admin must be a timelock or Safe, never a deployer.`,
		);
}

const planned = (plan: Plan, key: (typeof CORE_KEYS)[number]) =>
	plan.contracts.find((c) => c.key === key);

/** What an existing paymaster proxy must be configured with, besides its ROLE_ADMIN. */
export type CoreConfig = Omit<PaymasterParams, "roleAdmin">;

/** The configuration a profile publishes: the canonical EntryPoint and the profile's fees. */
export function profileCoreConfig(profile: ChainProfile): CoreConfig {
	const { defaultFeeWei, postOpGasAllowance, penaltyBps } =
		paymasterParams(profile);
	return {
		entryPoint: ENTRY_POINT_V09,
		defaultFeeWei,
		postOpGasAllowance,
		penaltyBps,
	};
}

/**
 * An existing paymaster proxy, overridden or not, must be configured as this plan says: pointing at
 * the planned implementation, with `admin` holding ROLE_ADMIN, the EntryPoint of `config`, and (on
 * a non-local chain) no deployer holding ROLE_ADMIN. Those throw. The fees are operational
 * parameters that FEE_ADMIN_ROLE / PARAM_ADMIN_ROLE change on purpose (setDefaultFee,
 * setPostOpGasAllowance, setPenaltyBps), so a fee that differs from `config` is returned as a
 * warning instead of refusing the run. Shared by the guided wizard and `deploy:cli core`, which both
 * run it before deployCore records anything.
 */
export async function verifyCoreState(
	client: PublicClient,
	admin: Address,
	config: CoreConfig,
	plan: Plan,
	options: {
		/**
		 * The profile's timelock. After the hand-off it holds ROLE_ADMIN instead of `admin` (the
		 * bootstrap key, which renounced it), and a handed-off chain must still verify.
		 */
		timelock?: string | null;
	} = {},
): Promise<string[]> {
	const proxy = planned(plan, "paymasterProxy");
	if (!proxy?.actual) return [];
	const code = await client.getCode({ address: proxy.actual });
	if (!code || code === "0x") return [];
	const implementation = planned(plan, "paymasterImplementation")?.actual;
	const current = await proxyImplementation(client, proxy.actual);
	if (!current || !implementation || current !== getAddress(implementation))
		throw new GateError(
			"Paymaster was upgraded or points to an unexpected implementation; use the upgrade procedure.",
		);
	const read = { address: proxy.actual, abi: gianoPaymasterAbi } as const;
	const role = await client.readContract({
		...read,
		functionName: "ROLE_ADMIN",
	});
	const timelock = options.timelock ? getAddress(options.timelock) : null;
	const [adminHolds, timelockHolds, entryPoint, fee, allowance, penalty] =
		await Promise.all([
			client.readContract({
				...read,
				functionName: "hasRole",
				args: [role, admin],
			}),
			timelock
				? client.readContract({
						...read,
						functionName: "hasRole",
						args: [role, timelock],
					})
				: false,
			client.readContract({ ...read, functionName: "entryPoint" }),
			client.readContract({ ...read, functionName: "defaultFeeWei" }),
			client.readContract({ ...read, functionName: "postOpGasAllowance" }),
			client.readContract({ ...read, functionName: "penaltyBps" }),
		]);
	if (!adminHolds && !timelockHolds)
		throw new GateError(
			timelock
				? `Neither the profile's ROLE_ADMIN ${admin} nor its timelock ${timelock} holds ROLE_ADMIN on the paymaster. Review its configuration before continuing.`
				: `The profile's ROLE_ADMIN ${admin} does not hold ROLE_ADMIN on the paymaster. If the roles were handed to a timelock, set the profile's timelock.address. Review its configuration before continuing.`,
		);
	if (getAddress(entryPoint) !== getAddress(config.entryPoint))
		throw new GateError(
			"Existing paymaster EntryPoint differs from this plan. Review its configuration before continuing.",
		);
	const warnings: string[] = [];
	for (const [name, live, planned] of [
		["defaultFeeWei", fee, config.defaultFeeWei],
		["postOpGasAllowance", allowance, config.postOpGasAllowance],
		["penaltyBps", penalty, config.penaltyBps],
	] as const)
		if (BigInt(live) !== BigInt(planned))
			warnings.push(
				`paymaster ${name} is ${live} on chain, not ${planned}; fees are tuned by the fee and parameter admins, so this run leaves it as is`,
			);
	if (plan.network !== "local") {
		const deployers = [
			plan.signer,
			plan.classDeployer,
			DEPLOYERS.mainnet,
			DEPLOYERS.testnet,
		].filter((a): a is Address => a !== null);
		for (const deployer of new Set(deployers.map((a) => getAddress(a))))
			if (
				await client.readContract({
					...read,
					functionName: "hasRole",
					args: [role, deployer],
				})
			)
				throw new GateError(
					`Deployer ${deployer} holds ROLE_ADMIN on the paymaster at ${proxy.actual}. A deployer must hold no role.`,
				);
	}
	return warnings;
}

export type Check = { ok: boolean; message: string };

/**
 * Initcode that runs TLOAD and MCOPY, then stops: an `eth_call` of it succeeds only on a chain with
 * the Cancun opcodes the contracts and EntryPoint v0.9 are compiled for (evm_version = cancun).
 */
const CANCUN_PROBE: Hex = "0x5f5c505f5f5f5e00";

/** One requirement a chain must meet before any Giano contract is deployed or served on it. */
export type Prerequisite = { name: string; ok: boolean; detail: string };

/**
 * What the contracts need from a chain, checked the same way by the guided wizard, `deploy:cli core`
 * and the doctor: CreateX at its address with its upstream runtime (it places every CREATE3 address),
 * the canonical EntryPoint v0.9 (the wallet implementation hardcodes it), and the Cancun opcodes.
 * A P-256 precompile is not one: the wallet verifies passkeys with its own built-in fallback.
 */
export async function chainPrerequisites(
	client: PublicClient,
	chainId: number,
): Promise<Prerequisite[]> {
	const results: Prerequisite[] = [];
	const createX = await client.getCode({ address: CREATEX_ADDRESS });
	results.push({
		name: `CreateX at ${CREATEX_ADDRESS}`,
		ok: Boolean(createX) && keccak256(createX as Hex) === CREATEX_CODEHASH,
		detail: !createX
			? "no code. Follow https://github.com/pcaversaccio/createx; never install a local-chain substitute on a public chain."
			: keccak256(createX) === CREATEX_CODEHASH
				? "upstream runtime"
				: `unrecognised runtime ${keccak256(createX)}, not the upstream ${CREATEX_CODEHASH}`,
	});
	const entryPoint = await client.getCode({ address: ENTRY_POINT_V09 });
	const canonical = isCanonicalEntryPointCode(entryPoint, chainId);
	results.push({
		name: `EntryPoint v0.9 at ${ENTRY_POINT_V09}`,
		ok: canonical,
		detail: canonical
			? "canonical runtime"
			: entryPoint
				? "noncanonical runtime. Do not deploy or serve this chain."
				: "no code. Do not deploy or serve this chain.",
	});
	let cancun = true;
	try {
		await client.call({ data: CANCUN_PROBE });
	} catch {
		cancun = false;
	}
	results.push({
		name: "Cancun opcodes (TLOAD, MCOPY)",
		ok: cancun,
		detail: cancun
			? "available"
			: "unavailable. The contracts are compiled for Cancun; they cannot run on this chain.",
	});
	return results;
}

export type InspectOptions = {
	/** The signing key's address; null for a plan without a key. */
	signer: Address | null;
	record?: DeploymentRecord;
	/** For tests: the class deployer instead of deploy/config.ts. */
	deployer?: Address | null;
};

export type Inspection = {
	checks: Check[];
	/** Absent when the RPC is not the profile's chain (nothing else is read then). */
	plan?: Plan;
};

/**
 * Every read-only check before a deployment: the chain, CreateX, the EntryPoint, the plan (expected
 * and actual address per contract, overrides verified, deviations classified) and the existing
 * configuration. Signing is safe only when every check is ok; deviations are the caller's gate.
 */
export async function inspectDeployment(
	client: PublicClient,
	profile: ChainProfile,
	release: string,
	admin: Address,
	options: InspectOptions,
): Promise<Inspection> {
	const checks: Check[] = [];
	async function check(message: string, action: () => Promise<unknown>) {
		try {
			const detail = await action();
			checks.push({
				ok: true,
				message: typeof detail === "string" ? `${message}: ${detail}` : message,
			});
		} catch (error) {
			// RPC errors can contain credential-bearing URLs. Only expose our own actionable messages.
			checks.push({
				ok: false,
				message: `${message}: ${error instanceof GateError ? error.message : "RPC/read failed; check endpoint access and retry (provider details suppressed)."}`,
			});
		}
	}
	await check(`RPC is ${profile.name} (${profile.chainId})`, async () => {
		if ((await client.getChainId()) !== profile.chainId)
			throw new GateError(
				"Wrong chain: provide the selected network's RPC URL. No transactions sent.",
			);
	});
	if (!checks[0].ok) return { checks };
	let prerequisites: Prerequisite[] = [];
	try {
		prerequisites = await chainPrerequisites(client, profile.chainId);
	} catch {
		checks.push({
			ok: false,
			message:
				"Chain prerequisites: RPC/read failed; check endpoint access and retry (provider details suppressed).",
		});
	}
	for (const p of prerequisites)
		checks.push({ ok: p.ok, message: `${p.name}: ${p.detail}` });
	await check("ROLE_ADMIN is not a deployer key", async () =>
		assertRoleAdminNotDeployer(admin, options.signer, false),
	);
	let plan: Plan | undefined;
	await check(`Deployment plan (${profile.network})`, async () => {
		try {
			plan = await planCore(client, {
				network: profile.network,
				signer: options.signer,
				overrides: profile.addresses,
				record: options.record,
				release,
				deployer: options.deployer,
			});
		} catch {
			throw new GateError(
				"Could not read the planned addresses; check endpoint access and retry.",
			);
		}
		return `\n${formatPlan(plan).join("\n")}`;
	});
	if (!plan) return { checks };
	for (const blocker of plan.blockers)
		checks.push({ ok: false, message: blocker });
	await check(
		"Existing paymaster configuration matches the plan (when present)",
		async () => {
			try {
				const warnings = await verifyCoreState(
					client,
					admin,
					profileCoreConfig(profile),
					plan as Plan,
					{ timelock: profile.timelock?.address },
				);
				if (warnings.length) return `⚠ ${warnings.join("; ")}`;
			} catch (error) {
				throw error instanceof GateError
					? error
					: new GateError(
							"Configuration could not be verified. Review the proxy implementation slot, ROLE_ADMIN and EntryPoint.",
						);
			}
		},
	);
	// The key that will pay: the loaded signer, or, for a plan run without a key, the class's
	// canonical deployer, so the plan says which address to fund before the key is ever loaded.
	const payer = plan.signer ?? plan.classDeployer;
	const missing = plan.contracts.some(
		(c) => c.code.state === "empty" && c.source !== "override",
	);
	if (missing && payer)
		await check(
			`${plan.signer ? "Signer" : `Canonical ${plan.network} deployer`} ${payer} has at least ${profile.minDeployerBalanceEth} ETH (conservative gas reserve)`,
			async () => {
				if (
					(await client.getBalance({ address: payer })) <
					parseEther(profile.minDeployerBalanceEth)
				)
					throw new GateError(
						`Fund ${payer} on ${profile.name}, then rerun. Reserve is not a gas quote; L1 data fees and changing gas prices need headroom.`,
					);
			},
		);
	return { checks, plan };
}
export class GateError extends Error {}

/**
 * Whether `code` is a contract account, such as a Safe. An address with no code is a key, and so is an
 * EOA with an EIP-7702 delegation: its code is the 23-byte designator `0xef0100‖address`, but one
 * private key still controls it. "Has code" alone takes such an EOA for a Safe.
 */
export function isContractAccount(code: Hex | string | undefined): boolean {
	if (!code || code === "0x") return false;
	const hex = code.toLowerCase();
	return !(hex.length === 2 + 23 * 2 && hex.startsWith("0xef0100"));
}

/** The timelock configuration a hand-off is checked against: the profile's, else the recorded one. */
export type PublishedTimelock = {
	proposers: readonly string[];
	executors: readonly string[];
	delays: Partial<TimelockDelays>;
	/** The block the timelock was deployed in, to enumerate its role grants from. */
	fromBlock?: bigint;
};

/**
 * Everything wrong with handing `proxy`'s timelocked roles to `timelock`, checked before anything is
 * sent, because the hand-off renounces ROLE_ADMIN and cannot be undone. The timelock's code must be a
 * release's GianoTimelock; its proposers and executors must be the published ones; its delays must be
 * at least the published ones and keep role changes at least as slow as what they could bypass; and on
 * a mainnet every proposer must be a contract account, never a key. Empty means safe to hand off.
 */
export async function handOffProblems(
	client: PublicClient,
	options: {
		network: NetworkClass;
		proxy: Address;
		timelock: Address;
		published: PublishedTimelock;
	},
): Promise<string[]> {
	const { timelock, proxy, published } = options;
	const problems: string[] = [];
	const code = await client.getCode({ address: timelock });
	if (!code || !releaseOf("GianoTimelock", code, timelock)) {
		problems.push(
			`${timelock} holds ${code ? `code ${keccak256(code)}` : "no code"}, which matches no release's GianoTimelock`,
		);
		return problems;
	}
	const read = (functionName: string, args: readonly unknown[] = []) =>
		client.readContract({
			address: timelock,
			abi: gianoTimelockAbi,
			functionName: functionName as never,
			args: args as never,
		}) as Promise<unknown>;
	const [proposerRole, cancellerRole, executorRole] = (await Promise.all([
		read("PROPOSER_ROLE"),
		read("CANCELLER_ROLE"),
		read("EXECUTOR_ROLE"),
	])) as Hex[];
	const holds = async (role: Hex, account: string) =>
		(await read("hasRole", [role, getAddress(account)])) as boolean;

	// Proposers: every published one holds the role, and nobody else was ever granted it.
	const expected = new Set(published.proposers.map((p) => getAddress(p)));
	for (const proposer of expected) {
		if (!(await holds(proposerRole, proposer)))
			problems.push(
				`published proposer ${proposer} does not hold PROPOSER_ROLE`,
			);
		else if (!(await holds(cancellerRole, proposer)))
			problems.push(
				`published proposer ${proposer} does not hold CANCELLER_ROLE`,
			);
	}
	try {
		const grants = await client.getLogs({
			address: timelock,
			event: roleGranted,
			args: { role: proposerRole },
			fromBlock: published.fromBlock ?? 0n,
			toBlock: "latest",
		});
		for (const grant of grants) {
			const account = getAddress(grant.args.account as Address);
			if (!expected.has(account) && (await holds(proposerRole, account)))
				problems.push(
					`${account} holds PROPOSER_ROLE but is not a published proposer`,
				);
		}
	} catch {
		// Some RPCs cap log ranges. The published proposers were still checked one by one.
	}
	if (options.network === "mainnet")
		for (const proposer of expected)
			if (!isContractAccount(await client.getCode({ address: proposer })))
				problems.push(
					`proposer ${proposer} is a key (no code, or only an EIP-7702 delegation), not a Safe or other contract: one key could queue anything`,
				);

	// Executors: open execution when none are published, else exactly the published ones may run.
	const open = await holds(executorRole, zeroAddress);
	if (published.executors.length === 0 && !open)
		problems.push(
			"the profile publishes open execution, but the timelock restricts EXECUTOR_ROLE",
		);
	if (published.executors.length > 0) {
		if (open)
			problems.push(
				"the profile restricts execution, but the timelock lets anyone execute",
			);
		for (const executor of published.executors)
			if (!(await holds(executorRole, executor)))
				problems.push(
					`published executor ${getAddress(executor)} does not hold EXECUTOR_ROLE`,
				);
	}

	// Delays: what the timelock enforces against what was published.
	const minDelay = Number(await read("getMinDelay"));
	const actual = { minDelay } as TimelockDelays;
	for (const name of TIMELOCKED_FUNCTION_NAMES)
		actual[name] = Number(
			await read("getEffectiveDelay", [proxy, paymasterSelector(name)]),
		);
	for (const short of delayShortfalls(actual, published.delays))
		problems.push(
			`${short.name} waits ${formatDuration(short.actual)}, less than the published ${formatDuration(short.expected)}`,
		);
	problems.push(...delayPolicyProblems(actual));
	return problems;
}

const roleGranted = {
	type: "event",
	name: "RoleGranted",
	inputs: [
		{ name: "role", type: "bytes32", indexed: true },
		{ name: "account", type: "address", indexed: true },
		{ name: "sender", type: "address", indexed: true },
	],
} as const;
