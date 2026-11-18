import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { createPublicClient, HttpRequestError, http } from "viem";
import { isFullBlockRequestError, waitForReceipt } from "../receipt";

const HASH = `0x${"ab".repeat(32)}` as const;
const BLOCK_HASH = `0x${"cd".repeat(32)}` as const;
const FROM = "0xf39fd6e51aad88f6f4ce6ab8827279cffb92266";
const TO = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const hex = (n: number) => `0x${n.toString(16)}`;

type Chain = {
	/** The block the receipt first appears in; earlier polls answer null. */
	minedAt: number;
	/** `eth_getBlockByNumber` with `true`: answered, or refused as the Silent Data gateway does. */
	fullBlocks: "allowed" | "refused-200" | "refused-403";
	/** `eth_getTransactionReceipt` fails with this error instead. */
	receiptError?: { code: number; message: string };
};

/**
 * A stub RPC. The head moves one block per `eth_blockNumber`; the transaction is pending until
 * `minedAt`, so viem's replacement check asks for a full block first.
 */
async function stubRpc(chain: Chain) {
	let head = 1;
	const methods: string[] = [];
	const server = createServer(async (req, res) => {
		let body = "";
		for await (const chunk of req) body += chunk;
		const request = JSON.parse(body) as {
			id: number;
			method: string;
			params: unknown[];
		};
		const full =
			request.method === "eth_getBlockByNumber" && request.params[1] === true;
		methods.push(full ? "eth_getBlockByNumber(full)" : request.method);
		const reply = (status: number, payload: object) => {
			res.writeHead(status, { "content-type": "application/json" });
			res.end(JSON.stringify({ jsonrpc: "2.0", id: request.id, ...payload }));
		};
		const mined = head >= chain.minedAt;
		switch (request.method) {
			case "eth_chainId":
				return reply(200, { result: "0x1" });
			case "eth_blockNumber":
				head++;
				return reply(200, { result: hex(head) });
			case "eth_getTransactionByHash":
				return reply(200, {
					result: {
						hash: HASH,
						nonce: "0x0",
						from: FROM,
						to: TO,
						value: "0x0",
						gas: "0x5208",
						gasPrice: "0x1",
						input: "0x",
						type: "0x0",
						blockHash: mined ? BLOCK_HASH : null,
						blockNumber: mined ? hex(chain.minedAt) : null,
						transactionIndex: mined ? "0x0" : null,
						v: "0x1b",
						r: "0x1",
						s: "0x1",
					},
				});
			case "eth_getTransactionReceipt":
				if (chain.receiptError)
					return reply(200, { error: chain.receiptError });
				return reply(200, {
					result: mined
						? {
								transactionHash: HASH,
								transactionIndex: "0x0",
								blockHash: BLOCK_HASH,
								blockNumber: hex(chain.minedAt),
								from: FROM,
								to: TO,
								cumulativeGasUsed: "0x5208",
								gasUsed: "0x5208",
								effectiveGasPrice: "0x1",
								contractAddress: null,
								logs: [],
								logsBloom: `0x${"00".repeat(256)}`,
								status: "0x1",
								type: "0x0",
							}
						: null,
				});
			case "eth_getBlockByNumber":
				if (full && chain.fullBlocks !== "allowed")
					return reply(chain.fullBlocks === "refused-403" ? 403 : 200, {
						error: {
							code: -107486,
							message: "param values not whitelisted for JSON RPC method",
						},
					});
				return reply(200, {
					result: {
						number: request.params[0],
						hash: BLOCK_HASH,
						parentHash: BLOCK_HASH,
						timestamp: "0x1",
						transactions: [],
					},
				});
			default:
				return reply(200, {
					error: { code: -32601, message: "method not found" },
				});
		}
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	const client = createPublicClient({
		transport: http(`http://127.0.0.1:${port}`, { retryCount: 0 }),
		pollingInterval: 5,
	});
	/** Records the parameters of each wait waitForReceipt starts. */
	const waits: { checkReplacement?: boolean }[] = [];
	const counted = {
		waitForTransactionReceipt(
			parameters: Parameters<typeof client.waitForTransactionReceipt>[0],
		) {
			waits.push({ checkReplacement: parameters.checkReplacement });
			return client.waitForTransactionReceipt(parameters);
		},
	};
	return { client, counted, methods, waits, close: () => server.close() };
}

for (const fullBlocks of ["refused-200", "refused-403"] as const)
	test(`a refused full block (${fullBlocks}) falls back to polling the receipt alone`, async () => {
		const rpc = await stubRpc({ minedAt: 6, fullBlocks });
		try {
			// viem's own wait fails on the refused full block, though the transaction is mined.
			await assert.rejects(
				rpc.client.waitForTransactionReceipt({ hash: HASH, timeout: 5_000 }),
				(error) => isFullBlockRequestError(error),
			);
			const receipt = await waitForReceipt(rpc.counted, {
				hash: HASH,
				timeout: 5_000,
			});
			assert.equal(receipt.status, "success");
			assert.equal(receipt.blockNumber, 6n);
			assert.deepEqual(rpc.waits, [
				{ checkReplacement: undefined },
				{ checkReplacement: false },
			]);
		} finally {
			rpc.close();
		}
	});

test("on a chain that returns full blocks, the wait is viem's and runs once", async () => {
	const rpc = await stubRpc({ minedAt: 6, fullBlocks: "allowed" });
	try {
		const receipt = await waitForReceipt(rpc.counted, {
			hash: HASH,
			timeout: 5_000,
		});
		assert.equal(receipt.blockNumber, 6n);
		assert.deepEqual(rpc.waits, [{ checkReplacement: undefined }]);
		// The replacement check still ran: nothing changes where full blocks are allowed.
		assert.ok(rpc.methods.includes("eth_getBlockByNumber(full)"));
	} finally {
		rpc.close();
	}
});

test("any other failure is thrown as it is, with no second wait", async () => {
	const rpc = await stubRpc({
		minedAt: 6,
		fullBlocks: "refused-200",
		receiptError: { code: -32000, message: "receipt lookup failed" },
	});
	try {
		await assert.rejects(
			waitForReceipt(rpc.counted, { hash: HASH, timeout: 5_000 }),
			/receipt lookup failed/,
		);
		assert.equal(rpc.waits.length, 1);
	} finally {
		rpc.close();
	}
});

test("isFullBlockRequestError reads the request from body or metaMessages, through causes", () => {
	const full = { method: "eth_getBlockByNumber", params: ["0x88be", true] };
	const header = { method: "eth_getBlockByNumber", params: ["latest", false] };
	const http = (body: object) =>
		new HttpRequestError({ body: body as never, url: "http://rpc" });
	assert.equal(isFullBlockRequestError(http(full)), true);
	assert.equal(
		isFullBlockRequestError(http({ ...full, method: "eth_getBlockByHash" })),
		true,
	);
	assert.equal(isFullBlockRequestError(http([header, full])), true);
	assert.equal(
		isFullBlockRequestError(new Error("outer", { cause: http(full) })),
		true,
	);
	assert.equal(
		isFullBlockRequestError({
			metaMessages: [
				"URL: http://rpc",
				`Request body: ${JSON.stringify(full)}`,
			],
		}),
		true,
	);
	assert.equal(isFullBlockRequestError(http(header)), false);
	assert.equal(
		isFullBlockRequestError(
			http({ method: "eth_getLogs", params: [{}, true] }),
		),
		false,
	);
	assert.equal(
		isFullBlockRequestError(new Error("param values not whitelisted")),
		false,
	);
	assert.equal(isFullBlockRequestError(undefined), false);
});
