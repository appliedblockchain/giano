import { concat, encodeErrorResult, type Hex, padHex } from "viem";
import { entryPoint09Abi } from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import {
	decodeEntryPointRevert,
	simulationError,
	validationError,
} from "../src/errors.js";
import { describeRevert, executionGasUsed } from "../src/estimator.js";
import { unpack } from "../src/lookup.js";
import { staticPreVerificationGas } from "../src/pvg.js";
import { packUserOp, type UserOp } from "../src/userop.js";

const op: UserOp = {
	sender: "0xd6120f4D7a2b48735EFFc7eA0731cB18B3a25A98",
	nonce: 3n,
	callData: "0xb61d27f6",
	callGasLimit: 60_000n,
	verificationGasLimit: 800_000n,
	preVerificationGas: 50_000n,
	maxFeePerGas: 2_000_000_000n,
	maxPriorityFeePerGas: 1_000_000n,
	signature: `0x${"ab".repeat(65)}`,
};

describe("executionGasUsed", () => {
	// v0.9 waives the penalty below 40,000 unused gas.
	const charge = (used: bigint, limit: bigint) =>
		limit - used <= 40_000n ? used : used + ((limit - used) * 10n) / 100n;

	it("bounds usage conservatively across the penalty threshold", () => {
		for (const [used, limit] of [
			[45_123n, 6_000_000n],
			[1n, 10n],
			[21_000n, 21_000n],
			[0n, 9_000n],
			[250_001n, 6_500_000n],
			[60_001n, 100_000n],
			[60_000n, 100_000n],
			[59_999n, 100_000n],
		]) {
			const recovered = executionGasUsed(charge(used, limit), limit);
			expect(recovered >= used && recovered - used <= 4_445n).toBe(true);
		}
	});

	it("is the charge itself when nothing went unused", () => {
		expect(executionGasUsed(7_000n, 5_000n)).toBe(7_000n);
	});
});

describe("staticPreVerificationGas", () => {
	it("estimates at least what submission will measure, for a signature up to twice the stub", () => {
		const stub = staticPreVerificationGas(op, "estimate");
		const real = staticPreVerificationGas(
			{ ...op, signature: `0x${"cd".repeat(129)}` },
			"exact",
		);
		expect(stub).toBeGreaterThanOrEqual(real);
	});

	it("does not depend on the gas values, so filling them in leaves it unchanged", () => {
		expect(
			staticPreVerificationGas(
				{ ...op, callGasLimit: 1n, preVerificationGas: 1n },
				"exact",
			),
		).toBe(staticPreVerificationGas(op, "exact"));
	});

	it("includes the 21k base and per-operation overhead", () => {
		expect(staticPreVerificationGas(op, "exact")).toBeGreaterThan(
			21_000n + 18_300n,
		);
	});
});

describe("EntryPoint reverts", () => {
	const failedOp = (reason: string) => ({
		cause: {
			data: encodeErrorResult({
				abi: entryPoint09Abi,
				errorName: "FailedOp",
				args: [0n, reason],
			}),
		},
	});

	it("decodes FailedOp and FailedOpWithRevert wherever viem nests the data", () => {
		expect(
			decodeEntryPointRevert({ cause: failedOp("AA24 signature error") }),
		).toEqual({ kind: "failed-op", reason: "AA24 signature error" });
		const withRevert = encodeErrorResult({
			abi: entryPoint09Abi,
			errorName: "FailedOpWithRevert",
			args: [0n, "AA23 reverted", "0x1234"],
		});
		expect(decodeEntryPointRevert({ data: { data: withRevert } })).toEqual({
			kind: "failed-op",
			reason: "AA23 reverted",
			inner: "0x1234",
		});
	});

	it("maps AA codes to Alto's error codes", () => {
		const code = (reason: string) =>
			validationError(decodeEntryPointRevert(failedOp(reason))).code;
		expect(code("AA24 signature error")).toBe(-32507);
		expect(code("AA34 signature error")).toBe(-32507);
		expect(code("AA22 expired or not due")).toBe(-32503);
		expect(code("AA25 invalid account nonce")).toBe(-32602);
		expect(code("AA31 paymaster deposit too low")).toBe(-32501);
		expect(code("AA21 didn't pay prefund")).toBe(-32500);
		expect(
			validationError(
				decodeEntryPointRevert(failedOp("AA21 didn't pay prefund")),
			).message,
		).toBe("UserOperation reverted with reason: AA21 didn't pay prefund");
		expect(simulationError("AA23 reverted").code).toBe(-32500);
		expect(simulationError("execution reverted").code).toBe(-32521);
	});

	it("describes Error(string) reverts by their message", () => {
		const data = concat([
			"0x08c379a0",
			padHex("0x20", { size: 32 }),
			padHex("0x05", { size: 32 }),
			padHex("0x68656c6c6f", { dir: "right", size: 32 }),
		]) as Hex;
		expect(describeRevert(data)).toBe("hello");
		expect(describeRevert("0x")).toBe("execution reverted");
		expect(describeRevert("0xdeadbeef")).toBe("0xdeadbeef");
	});
});

describe("unpack", () => {
	it("is the inverse of packing, with and without factory and paymaster", () => {
		expect(unpack(packUserOp(op))).toEqual(op);
		const full: UserOp = {
			...op,
			factory: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
			factoryData: "0x5fbfb9cf",
			paymaster: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
			paymasterVerificationGasLimit: 150_000n,
			paymasterPostOpGasLimit: 100_000n,
			paymasterData: "0x0102",
		};
		expect(unpack(packUserOp(full))).toEqual(full);
	});
});
