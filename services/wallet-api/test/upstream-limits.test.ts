import http from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	BundlerRpcError,
	createBundlerService,
} from "../src/services/bundler.js";
import {
	createNodeRpcService,
	NodeRpcError,
} from "../src/services/node-rpc.js";
import {
	UpstreamLimitError,
	type UpstreamLimits,
} from "../src/services/upstream-fetch.js";

/**
 * G37: every wallet-api call to the bundler or a chain's node is bounded in time and in response
 * size. Runs both clients against a real HTTP server, so the abort and the cancelled body are the
 * real `fetch` behaviour, not a test double's.
 */

const LIMITS: UpstreamLimits = { timeoutMs: 200, maxBytes: 64 * 1024 };
/** The bundler's send deadline: longer than the read deadline, as in production. */
const SEND_TIMEOUT_MS = LIMITS.timeoutMs * 10;
/** Far more than LIMITS.maxBytes: what an upstream would send if nothing stopped reading. */
const FLOOD_BYTES = 64 * 1024 * 1024;
const CHUNK = Buffer.alloc(64 * 1024, "a");

type Behaviour =
	| "ok"
	| "slow-ok"
	| "slow-headers"
	| "very-slow-headers"
	| "no-answer"
	| "stalled-body"
	| "declared-large"
	| "streamed-large"
	| "rpc-error";

/** One upstream exchange, as the server saw it. */
type Exchange = { closed: Promise<void>; written: () => number };

function startUpstream() {
	const exchanges: Exchange[] = [];
	const server = http.createServer((req, res) => {
		let body = "";
		let written = 0;
		const closed = new Promise<void>((resolve) => res.on("close", resolve));
		exchanges.push({ closed, written: () => written });
		req.on("data", (chunk) => (body += chunk));
		req.on("end", async () => {
			const behaviour = req.url?.slice(1) as Behaviour;
			const { id } = JSON.parse(body) as { id: number };
			const answer = JSON.stringify({ jsonrpc: "2.0", id, result: "0x2a" });
			res.setHeader("content-type", "application/json");
			switch (behaviour) {
				case "ok":
					return res.end(answer);
				case "slow-ok":
					return setTimeout(() => res.end(answer), LIMITS.timeoutMs / 4);
				case "slow-headers":
					return setTimeout(() => res.end(answer), LIMITS.timeoutMs * 5);
				case "very-slow-headers":
					return setTimeout(() => res.end(answer), SEND_TIMEOUT_MS * 3);
				case "no-answer":
					return; // never writes a byte
				case "stalled-body":
					// Headers and half a body, then nothing.
					res.writeHead(200);
					return res.write(answer.slice(0, 10));
				case "declared-large":
					res.writeHead(200, { "content-length": String(FLOOD_BYTES) });
					return res.write(CHUNK);
				case "streamed-large": {
					// Chunked, no declared length: only reading it tells the client how big it is.
					res.writeHead(200);
					let open = true;
					closed.then(() => (open = false));
					while (open && written < FLOOD_BYTES) {
						written += CHUNK.length;
						if (!res.write(CHUNK))
							await Promise.race([
								new Promise((r) => res.once("drain", r)),
								closed,
							]);
					}
					return res.end();
				}
				case "rpc-error":
					return res.end(
						JSON.stringify({
							jsonrpc: "2.0",
							id,
							error: { code: -32500, message: "AA23 reverted" },
						}),
					);
			}
		});
	});
	return new Promise<{
		url: (behaviour: Behaviour) => string;
		last: () => Exchange;
		close: () => Promise<void>;
	}>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const { port } = server.address() as { port: number };
			resolve({
				url: (behaviour) => `http://127.0.0.1:${port}/${behaviour}`,
				last: () => exchanges[exchanges.length - 1],
				close: () => {
					server.closeAllConnections();
					return new Promise((r) => server.close(() => r()));
				},
			});
		});
	});
}

let upstream: Awaited<ReturnType<typeof startUpstream>>;

beforeAll(async () => {
	upstream = await startUpstream();
});

afterAll(async () => {
	await upstream?.close();
});

const ENTRY_POINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
const HASH = `0x${"ab".repeat(32)}`;

/** One call through each client: what it returns, and the error its upstream's own refusal raises. */
const clients = {
	bundler: {
		call: (url: string, fetchImpl?: typeof fetch) =>
			createBundlerService(url, ENTRY_POINT, {
				limits: LIMITS,
				sendTimeoutMs: SEND_TIMEOUT_MS,
				fetchImpl,
			}).getUserOperationReceipt(HASH),
		rpcError: BundlerRpcError,
	},
	node: {
		call: (url: string, fetchImpl?: typeof fetch) =>
			createNodeRpcService(url, { limits: LIMITS, fetchImpl }).call(
				"eth_blockNumber",
				[],
			),
		rpcError: NodeRpcError,
	},
};

/** Runs `call` and returns what it threw, with how long it took. */
async function failure(call: () => Promise<unknown>) {
	const started = Date.now();
	try {
		await call();
	} catch (error) {
		return { error, elapsed: Date.now() - started };
	}
	throw new Error("expected the call to fail");
}

describe.each(Object.entries(clients))("%s client", (upstreamName, client) => {
	it("returns the result of a prompt answer", async () => {
		expect(await client.call(upstream.url("ok"))).toBe("0x2a");
	});

	it("still passes the upstream's own JSON-RPC error through", async () => {
		const { error } = await failure(() =>
			client.call(upstream.url("rpc-error")),
		);
		expect(error).toBeInstanceOf(client.rpcError);
	});

	describe("time", () => {
		it("waits for a slow upstream that answers within the limit", async () => {
			expect(await client.call(upstream.url("slow-ok"))).toBe("0x2a");
		});

		it("gives up on a slow upstream at the limit, and releases the connection", async () => {
			const { error, elapsed } = await failure(() =>
				client.call(upstream.url("slow-headers")),
			);
			expect(error).toBeInstanceOf(UpstreamLimitError);
			expect(error).toMatchObject({
				reason: "timeout",
				upstream: upstreamName,
			});
			expect(elapsed).toBeLessThan(LIMITS.timeoutMs * 3);
			await upstream.last().closed;
		});

		it("gives up on an upstream that never answers", async () => {
			const { error, elapsed } = await failure(() =>
				client.call(upstream.url("no-answer")),
			);
			expect(error).toMatchObject({ reason: "timeout" });
			expect(elapsed).toBeLessThan(LIMITS.timeoutMs * 3);
			await upstream.last().closed;
		});

		it("gives up on a body that stops half way: the limit covers the body, not just the headers", async () => {
			const { error, elapsed } = await failure(() =>
				client.call(upstream.url("stalled-body")),
			);
			expect(error).toMatchObject({ reason: "timeout" });
			expect(elapsed).toBeLessThan(LIMITS.timeoutMs * 3);
			await upstream.last().closed;
		});

		it("gives up even when the fetch implementation ignores its abort signal", async () => {
			const neverSettles: typeof fetch = () => new Promise(() => {});
			const { error, elapsed } = await failure(() =>
				client.call("http://upstream.test", neverSettles),
			);
			expect(error).toMatchObject({ reason: "timeout" });
			expect(elapsed).toBeLessThan(LIMITS.timeoutMs * 3);
		});

		it("names no URL in the error", async () => {
			const { error } = await failure(() =>
				client.call(upstream.url("no-answer")),
			);
			expect((error as Error).message).not.toContain("127.0.0.1");
		});
	});

	describe("size", () => {
		it("refuses a body whose declared length is over the limit, without reading it", async () => {
			const { error } = await failure(() =>
				client.call(upstream.url("declared-large")),
			);
			expect(error).toBeInstanceOf(UpstreamLimitError);
			expect(error).toMatchObject({
				reason: "too-large",
				upstream: upstreamName,
			});
			await upstream.last().closed;
		});

		it("stops reading an undeclared body once it passes the limit", async () => {
			const { error } = await failure(() =>
				client.call(upstream.url("streamed-large")),
			);
			expect(error).toMatchObject({ reason: "too-large" });
			const exchange = upstream.last();
			await exchange.closed;
			// The connection was dropped long before the upstream finished sending.
			expect(exchange.written()).toBeLessThan(FLOOD_BYTES / 4);
		});
	});
});

describe("bundler client: eth_sendUserOperation and caller signals", () => {
	const bundlerAt = (url: string) =>
		createBundlerService(url, ENTRY_POINT, {
			limits: LIMITS,
			sendTimeoutMs: SEND_TIMEOUT_MS,
		});

	it("waits past the read deadline for a send: the bundler may hold it until a lane is free", async () => {
		const bundler = bundlerAt(upstream.url("slow-headers"));
		expect(await bundler.sendUserOperation({})).toBe("0x2a");
	});

	it("still gives up on a send at the send deadline", async () => {
		const bundler = bundlerAt(upstream.url("very-slow-headers"));
		const { error, elapsed } = await failure(() =>
			bundler.sendUserOperation({}),
		);
		expect(error).toMatchObject({ reason: "timeout", upstream: "bundler" });
		expect(elapsed).toBeGreaterThanOrEqual(SEND_TIMEOUT_MS - 20);
		expect(elapsed).toBeLessThan(SEND_TIMEOUT_MS * 2);
		await upstream.last().closed;
	});

	it("cancels the request when the caller's own signal ends first", async () => {
		const bundler = bundlerAt(upstream.url("no-answer"));
		const { error, elapsed } = await failure(() =>
			bundler.supportedEntryPoints(AbortSignal.timeout(LIMITS.timeoutMs / 4)),
		);
		expect(error).not.toBeInstanceOf(UpstreamLimitError);
		expect((error as Error).name).toBe("TimeoutError");
		expect(elapsed).toBeLessThan(LIMITS.timeoutMs);
		await upstream.last().closed;
	});

	it("keeps its own limits when the caller passes a signal", async () => {
		const bundler = bundlerAt(upstream.url("streamed-large"));
		const { error } = await failure(() =>
			bundler.executors(AbortSignal.timeout(SEND_TIMEOUT_MS)),
		);
		expect(error).toMatchObject({ reason: "too-large" });
	});
});
