import { execFileSync } from "node:child_process";
import { pino } from "pino";
import { describe, expect, it } from "vitest";
import { RpcError } from "../src/errors.js";
import { createMetrics } from "../src/metrics.js";
import { createMethods, handleJsonRpc, type RpcContext } from "../src/rpc.js";

const entryPoint = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
const sent: unknown[] = [];
const context = {
	chainId: 84532,
	entryPoint,
	estimator: {
		estimate: async () => {
			throw new RpcError(
				-32521,
				"UserOperation reverted during simulation with reason: nope",
			);
		},
	},
	submitter: {
		send: async (op: unknown) => {
			sent.push(op);
			return `0x${"ab".repeat(32)}`;
		},
		executorStatus: async () => ({
			gasPrice: 1_000_000_000n,
			executors: [
				{
					address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
					balance: 10n ** 18n,
					busy: true,
					latestNonce: 41,
					pendingNonce: 42,
				},
				{
					address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
					balance: 0n,
					busy: false,
					latestNonce: 0,
					pendingNonce: 0,
				},
			],
		}),
	},
	lookup: { receipt: async () => null, byHash: async () => null },
	metrics: createMetrics(),
	log: pino({ level: "silent" }),
} as unknown as RpcContext;
const methods = createMethods(context);
const call = (body: unknown) => handleJsonRpc(context, methods, body);

const op = {
	sender: "0xd6120f4d7a2b48735effc7ea0731cb18b3a25a98",
	nonce: "0x0",
	callData: "0x",
	callGasLimit: "0x0",
	verificationGasLimit: "0x186a0",
	preVerificationGas: "0xc350",
	maxFeePerGas: "0x1",
	maxPriorityFeePerGas: "0x1",
	signature: "0x",
	unknownField: "dropped",
};

describe("JSON-RPC", () => {
	it("answers chain id and entry points from configuration", async () => {
		expect(
			await call({ jsonrpc: "2.0", id: 1, method: "eth_chainId" }),
		).toEqual({ jsonrpc: "2.0", id: 1, result: "0x14a34" });
		expect(
			await call({
				jsonrpc: "2.0",
				id: "a",
				method: "eth_supportedEntryPoints",
				params: [],
			}),
		).toEqual({ jsonrpc: "2.0", id: "a", result: [entryPoint] });
	});

	it("reports each executor lane for chain status, by address and never by key", async () => {
		const response = await call({
			jsonrpc: "2.0",
			id: 7,
			method: "giano_executors",
		});
		expect(response).toEqual({
			jsonrpc: "2.0",
			id: 7,
			result: {
				gasPriceWei: "0x3b9aca00",
				executors: [
					{
						address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
						balanceWei: "0xde0b6b3a7640000",
						busy: true,
						latestNonce: "0x29",
						pendingNonce: "0x2a",
					},
					{
						address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
						balanceWei: "0x0",
						busy: false,
						latestNonce: "0x0",
						pendingNonce: "0x0",
					},
				],
			},
		});
		expect(JSON.stringify(response)).not.toMatch(/privateKey|[0-9a-f]{64}/i);
	});

	it("refuses unsupported 7702 and parallel-paymaster fields instead of discarding them", async () => {
		for (const key of ["authorization", "eip7702Auth", "paymasterSignature"]) {
			expect(
				await call({
					jsonrpc: "2.0",
					id: 20,
					method: "eth_sendUserOperation",
					params: [{ ...op, [key]: "0x" }, entryPoint],
				}),
			).toMatchObject({ error: { code: -32602 } });
		}
		// The v0.9 EntryPoint reads initCode starting 0x7702 as a 7702 authorization.
		expect(
			await call({
				jsonrpc: "2.0",
				id: 21,
				method: "eth_sendUserOperation",
				params: [
					{
						...op,
						factory: "0x7702000000000000000000000000000000000000",
						factoryData: "0x",
					},
					entryPoint,
				],
			}),
		).toMatchObject({ error: { code: -32602 } });
	});

	it("refuses unknown methods and malformed envelopes", async () => {
		expect(
			await call({
				jsonrpc: "2.0",
				id: 2,
				method: "eth_sendRawTransaction",
				params: [],
			}),
		).toMatchObject({ id: 2, error: { code: -32601 } });
		expect(
			await call({ jsonrpc: "2.0", id: 3, method: "constructor" }),
		).toMatchObject({ error: { code: -32601 } });
		expect(await call({ id: 4, method: "eth_chainId" })).toMatchObject({
			id: null,
			error: { code: -32600 },
		});
	});

	it("validates parameters before anything reaches the chain", async () => {
		expect(
			await call({
				jsonrpc: "2.0",
				id: 5,
				method: "eth_sendUserOperation",
				params: [{ sender: "nope" }, entryPoint],
			}),
		).toMatchObject({
			error: { code: -32602 },
		});
		expect(
			await call({
				jsonrpc: "2.0",
				id: 6,
				method: "eth_getUserOperationReceipt",
				params: ["0x12"],
			}),
		).toMatchObject({ error: { code: -32602 } });
		expect(
			await call({
				jsonrpc: "2.0",
				id: 7,
				method: "eth_estimateUserOperationGas",
				params: [op, entryPoint, {}],
			}),
		).toMatchObject({
			error: {
				code: -32602,
				message: expect.stringMatching(/state overrides/),
			},
		});
		expect(
			await call({
				jsonrpc: "2.0",
				id: 8,
				method: "eth_sendUserOperation",
				params: [op, "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"],
			}),
		).toMatchObject({
			error: { code: -32602, message: expect.stringMatching(/not supported/) },
		});
	});

	it("passes a 4337 error through with its code", async () => {
		expect(
			await call({
				jsonrpc: "2.0",
				id: 9,
				method: "eth_estimateUserOperationGas",
				params: [op, entryPoint],
			}),
		).toEqual({
			jsonrpc: "2.0",
			id: 9,
			error: {
				code: -32521,
				message: "UserOperation reverted during simulation with reason: nope",
			},
		});
	});

	it("hands the submitter a normalised operation", async () => {
		const result = await call({
			jsonrpc: "2.0",
			id: 10,
			method: "eth_sendUserOperation",
			params: [op, entryPoint.toLowerCase()],
		});
		expect(result).toEqual({
			jsonrpc: "2.0",
			id: 10,
			result: `0x${"ab".repeat(32)}`,
		});
		expect(sent.at(-1)).toEqual({
			sender: "0xd6120f4D7a2b48735EFFc7eA0731cB18B3a25A98",
			nonce: 0n,
			callData: "0x",
			callGasLimit: 0n,
			verificationGasLimit: 100_000n,
			preVerificationGas: 50_000n,
			maxFeePerGas: 1n,
			maxPriorityFeePerGas: 1n,
			signature: "0x",
		});
	});
});

describe("generated simulation code", () => {
	it("matches the pinned @account-abstraction/contracts artifacts", () => {
		execFileSync("node", ["scripts/generate-simulations.mjs", "--check"], {
			cwd: new URL("..", import.meta.url),
		});
	});
});
