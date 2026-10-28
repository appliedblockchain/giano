/**
 * The paymaster's timelock policy (G9): which operations wait for a public delay, which do not, and
 * the encoders that turn an operation into a timelock proposal a Safe can sign.
 *
 * The contract side is GianoTimelock (src/paymaster/GianoTimelock.sol): an OpenZeppelin
 * TimelockController whose delay can differ per (target, selector), floored at `minDelay`. It holds
 * every role in {@link TIMELOCKED_ROLES}; every other role stays on an operational key so its
 * functions take effect immediately. specs/PAYMASTER-REQUIREMENTS.md §G9 records the decisions.
 *
 * The deploy CLI, giano-doctor, the giano-paymaster CLI and the operator console all read this
 * module, so the policy lives in one place.
 */
import {
	type Address,
	encodeAbiParameters,
	encodeFunctionData,
	getAddress,
	type Hex,
	keccak256,
	parseAbiParameters,
	toFunctionSelector,
	zeroHash,
} from "viem";
import { gianoPaymasterAbi, gianoTimelockAbi } from "./generated";

/** A paymaster function the timelock gates, and the role the timelock holds to call it. */
export type TimelockedOperation = {
	functionName:
		| "upgradeToAndCall"
		| "grantRole"
		| "revokeRole"
		| "renounceRole"
		| "setTenantWithdrawAddress"
		| "setDefaultFee"
		| "setTenantFee";
	role:
		| "UPGRADER_ROLE"
		| "ROLE_ADMIN"
		| "WITHDRAW_ADDRESS_ADMIN_ROLE"
		| "FEE_ADMIN_ROLE";
	why: string;
};

/**
 * Every paymaster function that goes through the timelock, keyed by the name its delay has in
 * {@link TimelockDelays}. Each one has its own delay.
 */
export const TIMELOCKED_OPERATIONS: Record<
	TimelockedOperation["functionName"],
	TimelockedOperation
> = {
	upgradeToAndCall: {
		functionName: "upgradeToAndCall",
		role: "UPGRADER_ROLE",
		why: "an upgrade can do anything, including take tenant funds (R-50/R-51)",
	},
	grantRole: {
		functionName: "grantRole",
		role: "ROLE_ADMIN",
		why: "granting a timelocked role to a key would bypass that role's delay (R-46)",
	},
	revokeRole: {
		functionName: "revokeRole",
		role: "ROLE_ADMIN",
		why: "revoking the timelock's roles changes who governs the paymaster",
	},
	renounceRole: {
		functionName: "renounceRole",
		role: "ROLE_ADMIN",
		why: "the timelock renouncing a role changes who governs the paymaster",
	},
	setTenantWithdrawAddress: {
		functionName: "setTenantWithdrawAddress",
		role: "WITHDRAW_ADDRESS_ADMIN_ROLE",
		why: "it redirects where a tenant's balance can be withdrawn to (R-48)",
	},
	setDefaultFee: {
		functionName: "setDefaultFee",
		role: "FEE_ADMIN_ROLE",
		why: "it changes what every tenant is charged",
	},
	setTenantFee: {
		functionName: "setTenantFee",
		role: "FEE_ADMIN_ROLE",
		why: "it changes what a tenant is charged",
	},
};

export type TimelockedFunctionName = keyof typeof TIMELOCKED_OPERATIONS;

export const TIMELOCKED_FUNCTION_NAMES: readonly TimelockedFunctionName[] =
	Object.keys(TIMELOCKED_OPERATIONS) as TimelockedFunctionName[];

/** The roles the timelock holds, and nothing else may. */
export const TIMELOCKED_ROLES: readonly TimelockedOperation["role"][] = [
	"ROLE_ADMIN",
	"UPGRADER_ROLE",
	"FEE_ADMIN_ROLE",
	"WITHDRAW_ADDRESS_ADMIN_ROLE",
];

/** The roles whose functions take effect immediately, and why. They stay on operational keys. */
export const IMMEDIATE_ROLES: Record<string, string> = {
	SIGNER_ADMIN_ROLE:
		"addSigner and removeSigner: key rotation and leaked-key response must not wait",
	PARAM_ADMIN_ROLE:
		"setPostOpGasAllowance and setPenaltyBps: bounded operational parameters",
	PAUSER_ROLE:
		"pause and unpause: an emergency stop; withdrawals stay open while paused (R-53)",
	STAKE_ADMIN_ROLE:
		"addStake, unlockStake and withdrawStake: touch the stake only, never the deposit",
	TENANT_ADMIN_ROLE:
		"registerTenant and setTenantEnabled: day-to-day onboarding and offboarding",
	FEE_COLLECTOR_ROLE:
		"withdrawFees: capped at accrued treasury, cannot reach tenant balances",
};

/**
 * One environment's delays, in seconds. `minDelay` is the timelock's floor and the delay of any
 * call not listed; each named function waits its own delay, never less than `minDelay`.
 */
export type TimelockDelays = { minDelay: number } & Record<
	TimelockedFunctionName,
	number
>;

/** The 4-byte selector of a timelocked paymaster function. */
export function paymasterSelector(functionName: TimelockedFunctionName): Hex {
	const item = gianoPaymasterAbi.find(
		(entry) => entry.type === "function" && entry.name === functionName,
	);
	if (!item) throw new Error(`GianoPaymaster has no function ${functionName}`);
	return toFunctionSelector(item as Parameters<typeof toFunctionSelector>[0]);
}

/** A `GianoTimelock` constructor entry. */
export type FunctionDelay = { target: Address; selector: Hex; delay: bigint };

/** The constructor's `functionDelays` for a paymaster at `paymaster`. */
export function paymasterFunctionDelays(
	paymaster: Address,
	delays: TimelockDelays,
): FunctionDelay[] {
	return TIMELOCKED_FUNCTION_NAMES.map((name) => ({
		target: getAddress(paymaster),
		selector: paymasterSelector(name),
		delay: BigInt(delays[name]),
	}));
}

/**
 * What is wrong with a delay policy, if anything. The rule that matters: a role change must wait at
 * least as long as the longest delay it could bypass, because granting a timelocked role to a key
 * would let that key skip the role's delay from then on.
 */
export function delayPolicyProblems(delays: TimelockDelays): string[] {
	const problems: string[] = [];
	for (const [name, value] of Object.entries(delays)) {
		if (!Number.isSafeInteger(value) || value < 0)
			problems.push(`${name} must be a whole number of seconds`);
	}
	const effective = (name: TimelockedFunctionName) =>
		Math.max(delays.minDelay, delays[name]);
	const longest = Math.max(
		...TIMELOCKED_FUNCTION_NAMES.filter(
			(name) => TIMELOCKED_OPERATIONS[name].role !== "ROLE_ADMIN",
		).map(effective),
	);
	for (const name of ["grantRole", "revokeRole", "renounceRole"] as const) {
		if (effective(name) < longest)
			problems.push(
				`${name} waits ${formatDuration(effective(name))}, shorter than the longest delay it could bypass (${formatDuration(longest)})`,
			);
	}
	return problems;
}

const UNITS: Record<string, number> = {
	s: 1,
	m: 60,
	h: 3600,
	d: 86400,
	w: 604800,
};

/** `90`, `90s`, `15m`, `6h`, `7d`, `2w` → seconds. */
export function parseDuration(value: string): number {
	const match = /^(\d+)\s*([smhdw]?)$/.exec(value.trim());
	if (!match)
		throw new Error(
			`"${value}" is not a duration; use seconds or a number with s, m, h, d or w`,
		);
	return Number(match[1]) * UNITS[match[2] || "s"];
}

/** Seconds → the largest whole unit up to days, e.g. 604800 → `7d`. */
export function formatDuration(seconds: number | bigint): string {
	const value = Number(seconds);
	for (const [unit, size] of [
		["d", 86400],
		["h", 3600],
		["m", 60],
	] as const) {
		if (value >= size && value % size === 0) return `${value / size}${unit}`;
	}
	return `${value}s`;
}

/** One call the timelock will make. */
export type TimelockCall = { target: Address; value?: bigint; data: Hex };

/** A call to schedule, with what identifies it on-chain. */
export type TimelockProposal = {
	timelock: Address;
	calls: TimelockCall[];
	/** Seconds. Must be at least the timelock's `getDelay`/`getBatchDelay` for the calls. */
	delay: bigint;
	predecessor: Hex;
	salt: Hex;
	/** The operation id `hashOperation`/`hashOperationBatch` returns. */
	id: Hex;
	/** Calldata for the timelock's `schedule` or `scheduleBatch`. Sent by a proposer. */
	schedule: Hex;
	/** Calldata for the timelock's `execute` or `executeBatch`. Sent by an executor once ready. */
	execute: Hex;
	/** Calldata for the timelock's `cancel`. Sent by a canceller while pending. */
	cancel: Hex;
};

/**
 * Encodes a timelock proposal for one call or a batch. A random-looking but deterministic salt is
 * the caller's to choose: proposing the same calls twice needs a different salt.
 */
export function encodeTimelockProposal(options: {
	timelock: Address;
	calls: TimelockCall[];
	delay: bigint;
	salt?: Hex;
	predecessor?: Hex;
}): TimelockProposal {
	const { timelock, calls, delay } = options;
	if (calls.length === 0) throw new Error("a proposal needs at least one call");
	const salt = options.salt ?? zeroHash;
	const predecessor = options.predecessor ?? zeroHash;
	const targets = calls.map((call) => getAddress(call.target));
	const values = calls.map((call) => call.value ?? 0n);
	const payloads = calls.map((call) => call.data);

	let id: Hex;
	let schedule: Hex;
	let execute: Hex;
	if (calls.length === 1) {
		id = keccak256(
			encodeAbiParameters(
				parseAbiParameters("address, uint256, bytes, bytes32, bytes32"),
				[targets[0], values[0], payloads[0], predecessor, salt],
			),
		);
		schedule = encodeFunctionData({
			abi: gianoTimelockAbi,
			functionName: "schedule",
			args: [targets[0], values[0], payloads[0], predecessor, salt, delay],
		});
		execute = encodeFunctionData({
			abi: gianoTimelockAbi,
			functionName: "execute",
			args: [targets[0], values[0], payloads[0], predecessor, salt],
		});
	} else {
		id = keccak256(
			encodeAbiParameters(
				parseAbiParameters("address[], uint256[], bytes[], bytes32, bytes32"),
				[targets, values, payloads, predecessor, salt],
			),
		);
		schedule = encodeFunctionData({
			abi: gianoTimelockAbi,
			functionName: "scheduleBatch",
			args: [targets, values, payloads, predecessor, salt, delay],
		});
		execute = encodeFunctionData({
			abi: gianoTimelockAbi,
			functionName: "executeBatch",
			args: [targets, values, payloads, predecessor, salt],
		});
	}
	const cancel = encodeFunctionData({
		abi: gianoTimelockAbi,
		functionName: "cancel",
		args: [id],
	});
	return {
		timelock: getAddress(timelock),
		calls: calls.map((call, i) => ({
			target: targets[i],
			value: values[i],
			data: call.data,
		})),
		delay,
		predecessor,
		salt,
		id,
		schedule,
		execute,
		cancel,
	};
}

/** A Safe Transaction Builder batch file (the JSON its "Upload" button accepts). */
export type SafeTransactionBatch = {
	version: "1.0";
	chainId: string;
	createdAt: number;
	meta: { name: string; description: string };
	transactions: { to: Address; value: string; data: Hex }[];
};

/**
 * The Safe Transaction Builder file that sends one timelock call from the Safe: `step: "schedule"`
 * for the proposer Safe, `"execute"` once the delay has passed (when executors are restricted to
 * the Safe), or `"cancel"`.
 */
export function safeTransactionBatch(
	proposal: TimelockProposal,
	options: {
		chainId: number;
		step: "schedule" | "execute" | "cancel";
		description: string;
		createdAt?: number;
	},
): SafeTransactionBatch {
	return {
		version: "1.0",
		chainId: String(options.chainId),
		createdAt: options.createdAt ?? Date.now(),
		meta: {
			name: `Giano timelock ${options.step} ${proposal.id.slice(0, 10)}`,
			description: options.description,
		},
		transactions: [
			{
				to: proposal.timelock,
				value: "0",
				data: proposal[options.step],
			},
		],
	};
}
