import {
	createPublicClient,
	custom,
	encodeAbiParameters,
	numberToHex,
	type PublicClient,
} from "viem";
import { describe, expect, it } from "vitest";
import { RpcError } from "../src/errors.js";
import { createEstimator } from "../src/estimator.js";
import { GAS_PRICE_ORACLE, scale } from "../src/pvg.js";
import type { UserOp } from "../src/userop.js";

const entryPoint = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
const executor = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const paymaster = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";
/** What the mocked GasPriceOracle answers to getL1Fee, in wei. */
const L1_FEE = 1_000_000_000_000n;

const op: UserOp = {
	sender: "0xd6120f4D7a2b48735EFFc7eA0731cB18B3a25A98",
	nonce: 0n,
	callData: "0xb61d27f6",
	callGasLimit: 0n,
	verificationGasLimit: 0n,
	preVerificationGas: 0n,
	maxFeePerGas: 2_000_000_000n,
	maxPriorityFeePerGas: 1_000_000n,
	signature: `0x${"ab".repeat(65)}`,
};

type Call = { method: string; params: unknown[] };

/**
 * A chain whose RPC answers only what the fixed path needs: the latest block and the
 * GasPriceOracle's getL1Fee. Any other eth_call (a simulation) is refused, as Silent Data refuses
 * an eth_call with a state override.
 */
function chain(options: { baseFeePerGas?: bigint | null }) {
	const calls: Call[] = [];
	const client = createPublicClient({
		transport: custom(
			{
				async request({
					method,
					params,
				}: {
					method: string;
					params: unknown[];
				}) {
					calls.push({ method, params });
					if (method === "eth_getBlockByNumber")
						return {
							number: "0x10",
							hash: `0x${"11".repeat(32)}`,
							parentHash: `0x${"22".repeat(32)}`,
							timestamp: "0x6553f100",
							gasLimit: "0x1c9c380",
							gasUsed: "0x0",
							transactions: [],
							...(options.baseFeePerGas === null
								? {}
								: { baseFeePerGas: numberToHex(options.baseFeePerGas ?? 0n) }),
						};
					// reads the simulation's state override is built from
					if (method === "eth_getBalance") return "0x0";
					if (method === "eth_getCode") return "0x";
					if (method === "eth_call") {
						const [request] = params as [{ to: string }];
						if (
							params.length === 2 &&
							request.to.toLowerCase() === GAS_PRICE_ORACLE.toLowerCase()
						)
							return encodeAbiParameters([{ type: "uint256" }], [L1_FEE]);
						throw new Error("state override not allowed");
					}
					throw new Error(`unexpected ${method}`);
				},
			},
			{ retryCount: 0 },
		),
	}) as PublicClient;
	return { client, calls };
}

const estimatorOn = (
	client: PublicClient,
	options: { chainType?: "default" | "op-stack"; stateOverride?: boolean } = {},
) =>
	createEstimator({
		client,
		entryPoint,
		chainId: 19874,
		chainType: options.chainType ?? "default",
		executor,
		stateOverride: options.stateOverride,
	});

/** eth_call requests with a third parameter: the state override. */
const overrideCalls = (calls: Call[]) =>
	calls.filter((call) => call.method === "eth_call" && call.params.length > 2);

describe("estimate with stateOverride: false", () => {
	it("returns the fixed limits and sends no eth_call with a state override", async () => {
		const { client, calls } = chain({ baseFeePerGas: 1_000_000_000n });
		const estimate = await estimatorOn(client, {
			stateOverride: false,
		}).estimate(op);
		expect(estimate.verificationGasLimit).toBe(1_000_000n);
		expect(estimate.callGasLimit).toBe(300_000n);
		expect(estimate.paymasterVerificationGasLimit).toBe(0n);
		expect(estimate.paymasterPostOpGasLimit).toBe(0n);
		expect(estimate.preVerificationGas).toBeGreaterThan(21_000n + 18_300n);
		expect(overrideCalls(calls)).toEqual([]);
	});

	it("keeps the call gas the caller sends", async () => {
		const { client } = chain({});
		const estimate = await estimatorOn(client, {
			stateOverride: false,
		}).estimate({ ...op, callGasLimit: 120_000n });
		expect(estimate.callGasLimit).toBe(120_000n);
	});

	it("keeps a verification gas above the fixed limit", async () => {
		const { client } = chain({});
		const estimate = await estimatorOn(client, {
			stateOverride: false,
		}).estimate({ ...op, verificationGasLimit: 1_500_000n });
		expect(estimate.verificationGasLimit).toBe(1_500_000n);
	});

	it("estimates call gas 0 for empty call data", async () => {
		const { client } = chain({});
		const estimate = await estimatorOn(client, {
			stateOverride: false,
		}).estimate({ ...op, callData: "0x" });
		expect(estimate.callGasLimit).toBe(0n);
	});

	it("gives a paymaster at least 200,000 verification gas, and keeps a higher one", async () => {
		const { client, calls } = chain({});
		const estimator = estimatorOn(client, { stateOverride: false });
		const sponsored: UserOp = {
			...op,
			paymaster,
			paymasterData: "0x01",
			paymasterVerificationGasLimit: 0n,
			paymasterPostOpGasLimit: 0n,
		};
		const fixed = await estimator.estimate(sponsored);
		expect(fixed.paymasterVerificationGasLimit).toBe(200_000n);
		// a paymaster that did not size its postOp gets the default
		expect(fixed.paymasterPostOpGasLimit).toBe(50_000n);
		const given = await estimator.estimate({
			...sponsored,
			paymasterVerificationGasLimit: 250_000n,
			paymasterPostOpGasLimit: 80_000n,
		});
		expect(given.paymasterVerificationGasLimit).toBe(250_000n);
		expect(given.paymasterPostOpGasLimit).toBe(80_000n);
		expect(overrideCalls(calls)).toEqual([]);
	});

	it("adds the L1 data fee to pre-verification gas on an OP Stack chain", async () => {
		const baseFeePerGas = 1_000_000_000n;
		const plain = chain({ baseFeePerGas });
		const opStack = chain({ baseFeePerGas });
		const withoutL1 = await estimatorOn(plain.client, {
			stateOverride: false,
		}).estimate(op);
		const withL1 = await estimatorOn(opStack.client, {
			chainType: "op-stack",
			stateOverride: false,
		}).estimate(op);

		// the L1 fee in L2 gas at the operation's price, rounded up, plus 25%
		const price = baseFeePerGas + op.maxPriorityFeePerGas;
		const l1Gas = (L1_FEE + price - 1n) / price;
		expect(withL1.preVerificationGas - withoutL1.preVerificationGas).toBe(
			scale(l1Gas, 125n),
		);
		// the GasPriceOracle read is a plain eth_call, with no state override
		expect(
			opStack.calls.some(
				(call) =>
					call.method === "eth_call" &&
					(call.params[0] as { to: string }).to.toLowerCase() ===
						GAS_PRICE_ORACLE.toLowerCase(),
			),
		).toBe(true);
		expect(overrideCalls(opStack.calls)).toEqual([]);
	});
});

describe("estimate on a default chain", () => {
	it("simulates with an eth_call state override when stateOverride is not set", async () => {
		const { client, calls } = chain({});
		await expect(estimatorOn(client).estimate(op)).rejects.toThrow();
		expect(overrideCalls(calls).length).toBeGreaterThan(0);
	});
});

describe("a fee of 0 at estimation", () => {
	for (const [label, baseFeePerGas] of [
		["is 0", 0n],
		["is absent", null],
	] as const)
		it(`is accepted when the base fee ${label}`, async () => {
			const { client } = chain({ baseFeePerGas });
			const estimate = await estimatorOn(client, {
				stateOverride: false,
			}).estimate({ ...op, maxFeePerGas: 0n, maxPriorityFeePerGas: 0n });
			expect(estimate.callGasLimit).toBe(300_000n);
		});

	it("is refused with invalid params when the base fee is above 0", async () => {
		const { client } = chain({ baseFeePerGas: 251n });
		const error = await estimatorOn(client, { stateOverride: false })
			.estimate({ ...op, maxFeePerGas: 0n, maxPriorityFeePerGas: 0n })
			.catch((caught: unknown) => caught);
		expect(error).toBeInstanceOf(RpcError);
		expect(error).toMatchObject({
			code: -32602,
			message:
				"user operation max fee per gas must be larger than 0 during gas estimation",
		});
	});
});
