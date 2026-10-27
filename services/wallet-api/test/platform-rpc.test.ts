import http from "node:http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { resolveEnvironment } from "../src/environments.js";
import {
	ADMIN_KEY,
	PLATFORM_ENV,
	platformSignIn,
	SECOND_ADMIN,
	startTestStack,
	stopTestStack,
	type TestContext,
} from "./setup.js";

/**
 * The platform chain read relay (openspec platform-chain-reads): what a hosted paymaster console
 * reads the chain through. Runs against a node stub that records every call, because most of what
 * this route promises is that a refused request never reaches the node.
 */

type NodeMode = "ok" | "revert" | "down";

/** The chain node, recording what reaches it. Answers boot-time reads as the suite's stock mock does. */
function startRecordingNode() {
	const calls: string[] = [];
	let mode: NodeMode = "ok";
	const server = http.createServer((req, res) => {
		let body = "";
		req.on("data", (chunk) => (body += chunk));
		req.on("end", () => {
			const { id, method } = JSON.parse(body) as { id: number; method: string };
			calls.push(method);
			if (mode === "down") {
				res.statusCode = 502;
				return res.end("bad gateway");
			}
			res.setHeader("content-type", "application/json");
			if (mode === "revert" && method === "eth_call") {
				return res.end(
					JSON.stringify({
						jsonrpc: "2.0",
						id,
						error: {
							code: 3,
							message: "execution reverted: nope",
							data: "0x08c379a0",
						},
					}),
				);
			}
			const result =
				method === "eth_chainId"
					? "0x7a69"
					: method === "eth_blockNumber"
						? "0x2a"
						: method === "eth_getLogs"
							? []
							: method === "eth_getCode"
								? "0x"
								: "0x0";
			res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
		});
	});
	return new Promise<{
		url: string;
		calls: string[];
		setMode: (next: NodeMode) => void;
		close: () => Promise<void>;
	}>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const { port } = server.address() as { port: number };
			resolve({
				url: `http://127.0.0.1:${port}`,
				calls,
				setMode: (next) => {
					mode = next;
				},
				close: () => new Promise((r) => server.close(() => r())),
			});
		});
	});
}

let ctx: TestContext;
let node: Awaited<ReturnType<typeof startRecordingNode>>;
let token: string;

type RpcBody = {
	jsonrpc: "2.0";
	id: number;
	result?: unknown;
	error?: { code: number; message: string; data?: unknown };
};

const rpc = async (
	method: string,
	params: unknown[] = [],
	{
		as = token,
		chainId = 31337,
		headers = {},
		app = ctx.app,
	}: {
		as?: string | null;
		chainId?: number;
		headers?: Record<string, string>;
		app?: TestContext["app"];
	} = {},
) => {
	const res = await app.inject({
		method: "POST",
		url: `/v1/platform/rpc/${chainId}`,
		headers: { ...(as ? { authorization: `Bearer ${as}` } : {}), ...headers },
		payload: { jsonrpc: "2.0", id: 7, method, params },
	});
	return {
		status: res.statusCode,
		body: res.json() as RpcBody & { error?: unknown; message?: string },
	};
};

/** Methods the node saw while `run` ran. */
const nodeCallsDuring = async (run: () => Promise<unknown>) => {
	const before = node.calls.length;
	await run();
	return node.calls.slice(before);
};

beforeAll(async () => {
	node = await startRecordingNode();
	ctx = await startTestStack({ ...PLATFORM_ENV, RPC_URL: node.url });
	token = await platformSignIn(ctx.app);
}, 120_000);

afterAll(async () => {
	if (ctx) await stopTestStack(ctx);
	if (node) await node.close();
});

beforeEach(() => node.setMode("ok"));

describe("access", () => {
	it("forwards a read for a signed-in platform admin", async () => {
		const calls = await nodeCallsDuring(async () => {
			const { status, body } = await rpc("eth_blockNumber");
			expect(status).toBe(200);
			expect(body).toEqual({ jsonrpc: "2.0", id: 7, result: "0x2a" });
		});
		expect(calls).toEqual(["eth_blockNumber"]);
	});

	it("answers eth_chainId from configuration", async () => {
		const calls = await nodeCallsDuring(async () => {
			expect((await rpc("eth_chainId")).body.result).toBe("0x7a69");
		});
		expect(calls).toEqual([]);
	});

	it("refuses a request with no session, with the platform 401 body, and reaches no node", async () => {
		const calls = await nodeCallsDuring(async () => {
			const { status, body } = await rpc("eth_blockNumber", [], { as: null });
			expect(status).toBe(401);
			expect(body).toEqual({
				error: "unauthorized",
				message: "platform admin session required",
			});
		});
		expect(calls).toEqual([]);
	});

	it("refuses a tenant admin key", async () => {
		expect((await rpc("eth_blockNumber", [], { as: ADMIN_KEY })).status).toBe(
			401,
		);
	});

	it("refuses any Origin, before authentication", async () => {
		const { status, body } = await rpc("eth_blockNumber", [], {
			headers: { origin: "https://evil.example" },
		});
		expect(status).toBe(403);
		expect(body.error).toBe("platform-origin-refused");
	});

	it("refuses a revoked session", async () => {
		const other = await platformSignIn(ctx.app, SECOND_ADMIN);
		await ctx.app.inject({
			method: "POST",
			url: "/v1/platform/auth/logout",
			headers: { authorization: `Bearer ${other}` },
		});
		expect((await rpc("eth_blockNumber", [], { as: other })).status).toBe(401);
	});

	it("refuses an unserved chain, listing the served ones", async () => {
		const { status, body } = await rpc("eth_blockNumber", [], {
			chainId: 999,
		});
		expect(status).toBe(400);
		expect(body).toMatchObject({
			error: "unsupported-chain",
			servedChainIds: [31337],
		});
	});

	it("does not exist where the environment has no platform sign-in domain", async () => {
		const disabled = await buildApp({
			config: { ...ctx.config, ENVIRONMENT: resolveEnvironment("reference") },
			db: ctx.db,
		});
		try {
			expect((await rpc("eth_blockNumber", [], { app: disabled })).status).toBe(
				404,
			);
		} finally {
			await disabled.close();
		}
	});
});

describe("what is forwarded", () => {
	it("refuses writes, debug and trace methods without reaching the node", async () => {
		const calls = await nodeCallsDuring(async () => {
			for (const method of [
				"eth_sendRawTransaction",
				"eth_sendTransaction",
				"debug_traceTransaction",
				"trace_block",
				"eth_newFilter",
			]) {
				const { status, body } = await rpc(method, []);
				expect(status).toBe(200);
				expect(body.error, method).toMatchObject({ code: -32601 });
			}
		});
		expect(calls).toEqual([]);
	});

	it("refuses a batch with 400", async () => {
		const calls = await nodeCallsDuring(async () => {
			const res = await ctx.app.inject({
				method: "POST",
				url: "/v1/platform/rpc/31337",
				headers: { authorization: `Bearer ${token}` },
				payload: [
					{ jsonrpc: "2.0", id: 1, method: "eth_blockNumber" },
					{ jsonrpc: "2.0", id: 2, method: "eth_blockNumber" },
				] as never,
			});
			expect(res.statusCode).toBe(400);
		});
		expect(calls).toEqual([]);
	});

	it("refuses a body over 16 KiB with 413", async () => {
		const calls = await nodeCallsDuring(async () => {
			const { status } = await rpc("eth_call", [
				{
					to: "0x2222222222222222222222222222222222222222",
					data: `0x${"00".repeat(10 * 1024)}`,
				},
				"latest",
			]);
			expect(status).toBe(413);
		});
		expect(calls).toEqual([]);
	});
});

describe("log queries", () => {
	const logs = (filter: Record<string, unknown>) =>
		rpc("eth_getLogs", [
			{ address: "0x2222222222222222222222222222222222222222", ...filter },
		]);

	it("forwards the SDK's 9 000-block window and a blockHash filter", async () => {
		const calls = await nodeCallsDuring(async () => {
			expect(
				(await logs({ fromBlock: "0x0", toBlock: `0x${(8999).toString(16)}` }))
					.body.result,
			).toEqual([]);
			expect(
				(await logs({ blockHash: `0x${"ab".repeat(32)}` })).body.result,
			).toEqual([]);
		});
		expect(calls).toEqual(["eth_getLogs", "eth_getLogs"]);
	});

	it("refuses tags, missing bounds and spans over the limit with -32602", async () => {
		const calls = await nodeCallsDuring(async () => {
			for (const filter of [
				{ fromBlock: "earliest", toBlock: "latest" },
				{ fromBlock: "0x0" },
				{},
				{ fromBlock: "0x0", toBlock: `0x${(50_000).toString(16)}` },
				{ fromBlock: "0x1", toBlock: `0x${(10_001).toString(16)}` },
				{ blockHash: `0x${"ab".repeat(32)}`, fromBlock: "0x0" },
			]) {
				const { body } = await logs(filter);
				expect(body.error, JSON.stringify(filter)).toMatchObject({
					code: -32602,
				});
				expect((body.error as { message: string }).message).toContain(
					"10000 blocks",
				);
			}
		});
		expect(calls).toEqual([]);
	});

	it("forwards exactly the limit", async () => {
		const { body } = await logs({
			fromBlock: "0x1",
			toBlock: `0x${(10_000).toString(16)}`,
		});
		expect(body.result).toEqual([]);
	});
});

describe("rate limit", () => {
	it("limits forwarded reads per session, apart from the tenant-management budget", async () => {
		const limited = await buildApp({
			config: {
				...ctx.config,
				PLATFORM_RPC_RATE_LIMIT_PER_MINUTE: 2,
				PLATFORM_RATE_LIMIT_PER_MINUTE: 2,
			},
			db: ctx.db,
		});
		try {
			const mine = await platformSignIn(limited);
			const theirs = await platformSignIn(limited, SECOND_ADMIN);
			const codes = [];
			for (let i = 0; i < 3; i++)
				codes.push(
					(await rpc("eth_blockNumber", [], { as: mine, app: limited })).body
						.error?.code ?? "ok",
				);
			expect(codes).toEqual(["ok", "ok", -32021]);

			// over the limit, nothing reaches the node
			expect(
				await nodeCallsDuring(() =>
					rpc("eth_blockNumber", [], { as: mine, app: limited }),
				),
			).toEqual([]);

			// another session is unaffected
			expect(
				(await rpc("eth_blockNumber", [], { as: theirs, app: limited })).body
					.result,
			).toBe("0x2a");

			// three reads did not spend this session's two management calls
			const tenants = await limited.inject({
				method: "GET",
				url: "/v1/platform/tenants",
				headers: { authorization: `Bearer ${mine}` },
			});
			expect(tenants.statusCode).toBe(200);
		} finally {
			await limited.close();
		}
	});
});

describe("node answers", () => {
	it("passes a revert through with its code, message and data", async () => {
		node.setMode("revert");
		const { body } = await rpc("eth_call", [
			{ to: "0x2222222222222222222222222222222222222222", data: "0x" },
			"latest",
		]);
		expect(body.error).toEqual({
			code: 3,
			message: "execution reverted: nope",
			data: "0x08c379a0",
		});
	});

	it("answers -32023 when the node cannot be reached, naming no URL", async () => {
		node.setMode("down");
		const { body } = await rpc("eth_blockNumber");
		expect(body.error).toMatchObject({ code: -32023 });
		expect(JSON.stringify(body)).not.toContain("127.0.0.1");
	});

	it("counts requests by method, chain and outcome", async () => {
		await rpc("eth_blockNumber");
		const metrics = await ctx.app.inject({ method: "GET", url: "/metrics" });
		expect(metrics.body).toMatch(
			/giano_platform_rpc_relay_requests_total\{method="eth_blockNumber",chain="31337",outcome="ok"\} \d+/,
		);
	});
});

describe("configuration", () => {
	const load = (env: Record<string, string>) => () =>
		loadConfig({
			NODE_ENV: "test",
			GIANO_DEPLOYMENT_CLASS: "development",
			GIANO_ENVIRONMENT: "test",
			DATABASE_URL: "postgres://u:p@localhost:5432/db",
			CHAIN_ID: "31337",
			RPC_URL: "http://localhost:8545",
			BUNDLER_URL: "http://localhost:4337",
			ENTRYPOINT_ADDRESS: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
			FACTORY_ADDRESS: "0x2222222222222222222222222222222222222222",
			...env,
		} as NodeJS.ProcessEnv);

	it("defaults the relay limits and refuses a log limit below the SDK's window", () => {
		expect(load({})()).toMatchObject({
			PLATFORM_RPC_RATE_LIMIT_PER_MINUTE: 1200,
			PLATFORM_RPC_MAX_LOG_BLOCKS: 10000,
		});
		expect(load({ PLATFORM_RPC_MAX_LOG_BLOCKS: "5000" })).toThrow(
			/PLATFORM_RPC_MAX_LOG_BLOCKS/,
		);
	});
});
