import {
	ContractFunctionExecutionError,
	ContractFunctionRevertedError,
	encodeErrorResult,
} from "viem";
import { describe, expect, it } from "vitest";
import { describeError } from "./format";

describe("describeError", () => {
	it("reads a viem error by its short message and the node's own words, not its whole dump", () => {
		const error = Object.assign(
			new Error(
				"RPC Request failed.\n\nURL: /api/v1/platform/rpc/31337\nRequest body: {...}\n\nDetails: platform RPC relay limit of 1200/minute per session exceeded\nVersion: viem@2.57.10",
			),
			{
				shortMessage: "RPC Request failed.",
				details: "platform RPC relay limit of 1200/minute per session exceeded",
			},
		);
		expect(describeError(error)).toBe(
			"RPC Request failed: platform RPC relay limit of 1200/minute per session exceeded",
		);
	});

	it("keeps a short message that already says it all, and plain errors as they are", () => {
		expect(
			describeError(
				Object.assign(new Error("long"), {
					shortMessage: "User rejected the request.",
					details: "User rejected the request.",
				}),
			),
		).toBe("User rejected the request.");
		expect(describeError(new Error("the session ended"))).toBe(
			"the session ended",
		);
		expect(describeError("plain")).toBe("plain");
	});

	it("names the contract's own error on a revert, which viem leaves out of the short message", () => {
		// The paymaster's grantRole and OpenZeppelin's AccessControl error, as its ABI has them.
		const gianoPaymasterAbi = [
			{
				type: "function",
				name: "grantRole",
				stateMutability: "nonpayable",
				inputs: [
					{ name: "role", type: "bytes32" },
					{ name: "account", type: "address" },
				],
				outputs: [],
			},
			{
				type: "error",
				name: "AccessControlUnauthorizedAccount",
				inputs: [
					{ name: "account", type: "address" },
					{ name: "neededRole", type: "bytes32" },
				],
			},
		] as const;
		const account = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
		const role = `0x${"ab".repeat(32)}` as const;
		const reverted = new ContractFunctionRevertedError({
			abi: gianoPaymasterAbi,
			functionName: "grantRole",
			data: encodeErrorResult({
				abi: gianoPaymasterAbi,
				errorName: "AccessControlUnauthorizedAccount",
				args: [account, role],
			}),
		});
		const error = new ContractFunctionExecutionError(reverted, {
			abi: gianoPaymasterAbi,
			functionName: "grantRole",
			args: [role, account],
		});
		expect(describeError(error)).toBe(
			`The contract function "grantRole" reverted: AccessControlUnauthorizedAccount(${account}, ${role})`,
		);
	});
});
