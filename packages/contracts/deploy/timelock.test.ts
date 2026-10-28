import assert from "node:assert/strict";
import { test } from "node:test";
import {
	decodeFunctionData,
	encodeFunctionData,
	getAddress,
	toFunctionSelector,
} from "viem";
import { gianoPaymasterAbi, gianoTimelockAbi } from "../generated";
import {
	delayPolicyProblems,
	encodeTimelockProposal,
	formatDuration,
	parseDuration,
	paymasterFunctionDelays,
	paymasterSelector,
	safeTransactionBatch,
	TIMELOCKED_FUNCTION_NAMES,
	TIMELOCKED_ROLES,
	type TimelockDelays,
} from "../timelock";

const PAYMASTER = getAddress("0x4Bf0c2F63C4fA20D88B8126298fFFC64710Ece96");
const TIMELOCK = getAddress("0x1000000000000000000000000000000000000001");

const DAY = 86400;
const policy: TimelockDelays = {
	minDelay: DAY,
	upgradeToAndCall: 7 * DAY,
	grantRole: 7 * DAY,
	revokeRole: 7 * DAY,
	renounceRole: 7 * DAY,
	setTenantWithdrawAddress: 7 * DAY,
	setDefaultFee: 3 * DAY,
	setTenantFee: 2 * DAY,
};

test("the user's decisions: these and only these paymaster functions are timelocked", () => {
	assert.deepEqual([...TIMELOCKED_FUNCTION_NAMES].sort(), [
		"grantRole",
		"renounceRole",
		"revokeRole",
		"setDefaultFee",
		"setTenantFee",
		"setTenantWithdrawAddress",
		"upgradeToAndCall",
	]);
	assert.deepEqual([...TIMELOCKED_ROLES].sort(), [
		"FEE_ADMIN_ROLE",
		"ROLE_ADMIN",
		"UPGRADER_ROLE",
		"WITHDRAW_ADDRESS_ADMIN_ROLE",
	]);
});

test("selectors are the paymaster's own", () => {
	assert.equal(
		paymasterSelector("setDefaultFee"),
		toFunctionSelector("setDefaultFee(uint128)"),
	);
	assert.equal(
		paymasterSelector("upgradeToAndCall"),
		toFunctionSelector("upgradeToAndCall(address,bytes)"),
	);
	assert.equal(
		paymasterSelector("grantRole"),
		toFunctionSelector("grantRole(bytes32,address)"),
	);
	const entries = paymasterFunctionDelays(PAYMASTER, policy);
	assert.equal(entries.length, TIMELOCKED_FUNCTION_NAMES.length);
	assert.ok(entries.every((entry) => entry.target === PAYMASTER));
	assert.equal(
		entries.find(
			(entry) =>
				entry.selector ===
				toFunctionSelector("setTenantFee(bytes16,bool,uint128)"),
		)?.delay,
		BigInt(2 * DAY),
	);
});

test("a role change must wait at least as long as anything it could bypass", () => {
	assert.deepEqual(delayPolicyProblems(policy), []);
	const short = { ...policy, grantRole: DAY };
	assert.match(
		delayPolicyProblems(short).join("\n"),
		/grantRole waits 1d, shorter than .* \(7d\)/,
	);
	// The floor counts: a function below minDelay waits minDelay.
	assert.deepEqual(
		delayPolicyProblems({
			...policy,
			minDelay: 7 * DAY,
			grantRole: 0,
			revokeRole: 0,
			renounceRole: 0,
		}),
		[],
	);
	assert.match(
		delayPolicyProblems({ ...policy, setTenantFee: -1 }).join(),
		/whole number/,
	);
});

test("durations", () => {
	assert.equal(parseDuration("90"), 90);
	assert.equal(parseDuration("15m"), 900);
	assert.equal(parseDuration("7d"), 7 * DAY);
	assert.equal(parseDuration("2w"), 14 * DAY);
	assert.throws(() => parseDuration("1.5d"), /not a duration/);
	assert.equal(formatDuration(7 * DAY), "7d");
	assert.equal(formatDuration(3 * DAY), "3d");
	assert.equal(formatDuration(90), "90s");
});

test("a single-call proposal encodes schedule, execute and cancel for the same operation", () => {
	const data = encodeFunctionData({
		abi: gianoPaymasterAbi,
		functionName: "setDefaultFee",
		args: [1n],
	});
	const proposal = encodeTimelockProposal({
		timelock: TIMELOCK,
		calls: [{ target: PAYMASTER, data }],
		delay: BigInt(3 * DAY),
	});
	const schedule = decodeFunctionData({
		abi: gianoTimelockAbi,
		data: proposal.schedule,
	});
	assert.equal(schedule.functionName, "schedule");
	assert.deepEqual(schedule.args, [
		PAYMASTER,
		0n,
		data,
		proposal.predecessor,
		proposal.salt,
		BigInt(3 * DAY),
	]);
	const execute = decodeFunctionData({
		abi: gianoTimelockAbi,
		data: proposal.execute,
	});
	assert.equal(execute.functionName, "execute");
	const cancel = decodeFunctionData({
		abi: gianoTimelockAbi,
		data: proposal.cancel,
	});
	assert.deepEqual(cancel.args, [proposal.id]);

	const batch = safeTransactionBatch(proposal, {
		chainId: 84532,
		step: "schedule",
		description: "set the default fee",
		createdAt: 1,
	});
	assert.deepEqual(batch.transactions, [
		{ to: TIMELOCK, value: "0", data: proposal.schedule },
	]);
	assert.equal(batch.chainId, "84532");
});

test("a multi-call proposal uses the batch entry points, and a salt changes the id", () => {
	const calls = [
		{
			target: PAYMASTER,
			data: encodeFunctionData({
				abi: gianoPaymasterAbi,
				functionName: "setDefaultFee",
				args: [1n],
			}),
		},
		{
			target: PAYMASTER,
			data: encodeFunctionData({
				abi: gianoPaymasterAbi,
				functionName: "setTenantFee",
				args: ["0x00000000000000000000000000000001", true, 2n],
			}),
		},
	];
	const a = encodeTimelockProposal({ timelock: TIMELOCK, calls, delay: 1n });
	const b = encodeTimelockProposal({
		timelock: TIMELOCK,
		calls,
		delay: 1n,
		salt: `0x${"11".repeat(32)}`,
	});
	assert.equal(
		decodeFunctionData({ abi: gianoTimelockAbi, data: a.schedule })
			.functionName,
		"scheduleBatch",
	);
	assert.equal(
		decodeFunctionData({ abi: gianoTimelockAbi, data: a.execute }).functionName,
		"executeBatch",
	);
	assert.notEqual(a.id, b.id);
	assert.throws(() =>
		encodeTimelockProposal({ timelock: TIMELOCK, calls: [], delay: 1n }),
	);
});
