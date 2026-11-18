import {
	createPublicClient,
	custom,
	encodeAbiParameters,
	encodeFunctionData,
	type Hex,
	type PublicClient,
	padHex,
} from "viem";
import { entryPoint09Abi } from "viem/account-abstraction";
import { describe, expect, it } from "vitest";
import { createLookup } from "../src/lookup.js";
import type { Submitter } from "../src/submitter.js";
import {
	formatUserOp,
	packUserOp,
	type UserOp,
	userOpHash,
} from "../src/userop.js";

const chainId = 19877;
const entryPoint = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
const beneficiary = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const USER_OPERATION_EVENT =
	"0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f";
const TRANSACTION_HASH = `0x${"aa".repeat(32)}` as Hex;
const BLOCK_HASH = `0x${"bb".repeat(32)}` as Hex;
/** What Silent Data returns to an unsigned reader in place of the bundle transaction's `to`. */
const REDACTED_TO = "0xffffffffffffffffffffffffffffffffffffffff";

const op: UserOp = {
	sender: "0xd6120f4D7a2b48735EFFc7eA0731cB18B3a25A98",
	nonce: 7n,
	callData: "0xb61d27f6",
	callGasLimit: 60_000n,
	verificationGasLimit: 800_000n,
	preVerificationGas: 50_000n,
	maxFeePerGas: 0n,
	maxPriorityFeePerGas: 0n,
	signature: `0x${"ab".repeat(65)}`,
};
const hash = userOpHash(op, entryPoint, chainId);

/** UserOperationEvent for `op`: success, cost 0 (a gasless chain), 91,234 gas used. */
const event = {
	address: entryPoint.toLowerCase(),
	topics: [
		USER_OPERATION_EVENT,
		hash,
		padHex(op.sender, { size: 32 }),
		padHex("0x00", { size: 32 }),
	],
	data: encodeAbiParameters(
		[
			{ type: "uint256" },
			{ type: "bool" },
			{ type: "uint256" },
			{ type: "uint256" },
		],
		[op.nonce, true, 0n, 91_234n],
	),
	blockHash: BLOCK_HASH,
	blockNumber: "0x10",
	transactionHash: TRANSACTION_HASH,
	transactionIndex: "0x0",
	logIndex: "0x0",
	removed: false,
};

const handleOpsInput = encodeFunctionData({
	abi: entryPoint09Abi,
	functionName: "handleOps",
	args: [[packUserOp(op)], beneficiary],
});

/**
 * The bundle transaction and its receipt as an RPC returns them. `redacted` is what Silent Data
 * returns to an unsigned reader: input `0x`, `to` all ones, receipt `from` 0x0 and `gasUsed` 0.
 */
function lookupOn(redacted: boolean) {
	const client = createPublicClient({
		transport: custom(
			{
				async request({ method }: { method: string }) {
					if (method === "eth_getTransactionByHash")
						return {
							hash: TRANSACTION_HASH,
							blockHash: BLOCK_HASH,
							blockNumber: "0x10",
							from: redacted
								? "0x0000000000000000000000000000000000000000"
								: beneficiary,
							to: redacted ? REDACTED_TO : entryPoint.toLowerCase(),
							input: redacted ? "0x" : handleOpsInput,
						};
					if (method === "eth_getTransactionReceipt")
						return {
							transactionHash: TRANSACTION_HASH,
							transactionIndex: "0x0",
							blockHash: BLOCK_HASH,
							blockNumber: "0x10",
							from: redacted
								? "0x0000000000000000000000000000000000000000"
								: beneficiary,
							to: redacted ? REDACTED_TO : entryPoint.toLowerCase(),
							cumulativeGasUsed: redacted ? "0x0" : "0x20000",
							gasUsed: redacted ? "0x0" : "0x20000",
							logs: [event],
							logsBloom: `0x${"00".repeat(256)}`,
							status: "0x1",
							effectiveGasPrice: "0x0",
						};
					throw new Error(`unexpected ${method}`);
				},
			},
			{ retryCount: 0 },
		),
	}) as PublicClient;
	const submitter = {
		get: (wanted: Hex) =>
			wanted.toLowerCase() === hash.toLowerCase()
				? { status: "included", transactionHash: TRANSACTION_HASH }
				: undefined,
	} as unknown as Submitter;
	return createLookup({
		client,
		chainId,
		entryPoint,
		maxBlockRange: 2000n,
		submitter,
	});
}

describe("eth_getUserOperationByHash", () => {
	it("answers null when the bundle transaction's calldata is redacted", async () => {
		expect(await lookupOn(true).byHash(hash)).toBeNull();
	});

	it("returns the operation when the calldata is readable", async () => {
		expect(await lookupOn(false).byHash(hash)).toEqual({
			userOperation: formatUserOp(op),
			entryPoint,
			transactionHash: TRANSACTION_HASH,
			blockHash: BLOCK_HASH,
			blockNumber: "0x10",
		});
	});
});

describe("eth_getUserOperationReceipt on a redacted bundle transaction", () => {
	it("reports the outcome from UserOperationEvent, not from the receipt's from and gasUsed", async () => {
		const receipt = await lookupOn(true).receipt(hash);
		expect(receipt).toMatchObject({
			userOpHash: hash,
			sender: op.sender,
			success: true,
			actualGasUsed: "0x16462",
			actualGasCost: "0x0",
			receipt: {
				from: "0x0000000000000000000000000000000000000000",
				gasUsed: "0x0",
			},
		});
	});
});
