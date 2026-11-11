import http from "node:http";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { tenants, useropLog } from "../src/db/schema.js";
import {
	startTestStack,
	stopTestStack,
	TENANT_A,
	TENANT_B,
	type TestContext,
} from "./setup.js";

/**
 * G37 at the routes: what a caller is told when the node or the bundler hits wallet-api's time or
 * size limit, and that one tenant's stuck reads do not hold up anyone else's.
 */

const TIMEOUT_MS = 300;
const MAX_BYTES = 4096;

/** Whose balance read the node never answers. */
const STUCK = "0x000000000000000000000000000000000000dead";

/** A chain node that never answers one balance read and answers eth_call with too much. */
function startNode() {
	const server = http.createServer((req, res) => {
		let body = "";
		req.on("data", (chunk) => (body += chunk));
		req.on("end", () => {
			const { id, method, params } = JSON.parse(body) as {
				id: number;
				method: string;
				params: unknown[];
			};
			if (method === "eth_getBalance" && params[0] === STUCK) return;
			const result =
				method === "eth_call"
					? `0x${"00".repeat(MAX_BYTES)}`
					: method === "eth_blockNumber"
						? "0x2a"
						: method === "eth_chainId"
							? "0x7a69"
							: "0x0";
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
		});
	});
	return new Promise<{ url: string; close: () => Promise<void> }>((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const { port } = server.address() as { port: number };
			resolve({
				url: `http://127.0.0.1:${port}`,
				close: () => {
					server.closeAllConnections();
					return new Promise((r) => server.close(() => r()));
				},
			});
		});
	});
}

let ctx: TestContext;
let node: Awaited<ReturnType<typeof startNode>>;

beforeAll(async () => {
	node = await startNode();
	ctx = await startTestStack({
		RPC_URL: node.url,
		UPSTREAM_TIMEOUT_MS: String(TIMEOUT_MS),
		UPSTREAM_MAX_RESPONSE_BYTES: String(MAX_BYTES),
	});
}, 120_000);

afterAll(async () => {
	if (ctx) await stopTestStack(ctx);
	if (node) await node.close();
});

type RpcBody = {
	jsonrpc: "2.0";
	id: number;
	result?: unknown;
	error?: { code: number; message: string };
};

const read = async (
	method: string,
	params: unknown[] = [],
	origin = TENANT_A.walletOrigin,
) => {
	const res = await ctx.app.inject({
		method: "POST",
		url: "/v1/rpc/31337",
		headers: { origin },
		payload: { jsonrpc: "2.0", id: 5, method, params },
	});
	return { status: res.statusCode, body: res.json() as RpcBody };
};

describe("chain RPC read relay", () => {
	it("answers a node that does not answer in time with -32023, at the limit", async () => {
		const started = Date.now();
		const { status, body } = await read("eth_getBalance", [STUCK, "latest"]);
		expect(status).toBe(200);
		expect(body.error).toEqual({
			code: -32023,
			message: "the chain RPC did not answer in time",
		});
		expect(Date.now() - started).toBeLessThan(TIMEOUT_MS * 5);
	});

	it("answers an oversized node response with -32023", async () => {
		const { status, body } = await read("eth_call", [
			{ to: "0x2222222222222222222222222222222222222222", data: "0x" },
			"latest",
		]);
		expect(status).toBe(200);
		expect(body.error).toEqual({
			code: -32023,
			message: "the chain RPC response is too large to relay",
		});
		expect(JSON.stringify(body)).not.toContain("127.0.0.1");
	});

	it("counts each limit as its own outcome", async () => {
		const metrics = await ctx.app.inject({ method: "GET", url: "/metrics" });
		expect(metrics.body).toMatch(
			/giano_rpc_relay_requests_total\{[^}]*outcome="node-timeout"[^}]*\} \d+/,
		);
		expect(metrics.body).toMatch(
			/giano_rpc_relay_requests_total\{[^}]*outcome="node-response-too-large"[^}]*\} \d+/,
		);
	});

	it("serves other tenants' pre-login reads while one tenant's reads are stuck", async () => {
		let stuckSettled = false;
		const stuck = Promise.all(
			Array.from({ length: 10 }, () =>
				read("eth_getBalance", [STUCK, "latest"]),
			),
		).finally(() => {
			stuckSettled = true;
		});

		const started = Date.now();
		const other = await read("eth_blockNumber", [], TENANT_B.walletOrigin);
		expect(other.body.result).toBe("0x2a");
		expect(Date.now() - started).toBeLessThan(TIMEOUT_MS);
		// The receipt route needs no session either.
		const receipt = await ctx.app.inject({
			method: "GET",
			url: `/v1/userops/0x${"cd".repeat(32)}/receipt`,
		});
		expect(receipt.statusCode).toBe(200);
		expect(stuckSettled).toBe(false);

		// And the stuck reads are released at the limit, each with the defined error.
		for (const { body } of await stuck) expect(body.error?.code).toBe(-32023);
	});
});

describe("receipt route (bundler)", () => {
	const hash = `0x${"ef".repeat(32)}`;

	// The receipt route asks the bundler only about an operation this deployment relayed.
	beforeAll(async () => {
		const tenant = await ctx.db.query.tenants.findFirst({
			where: eq(tenants.slug, TENANT_A.slug),
		});
		if (!tenant) throw new Error(`tenant ${TENANT_A.slug} is not seeded`);
		await ctx.db.insert(useropLog).values({
			useropHash: hash,
			chainId: 31337,
			sender: "0x000000000000000000000000000000000000beef",
			tenantId: tenant.id,
			status: "submitted",
		});
	});

	const receiptVia = async (fetchImpl: typeof fetch) => {
		const app = await buildApp({ config: ctx.config, db: ctx.db, fetchImpl });
		try {
			const res = await app.inject({
				method: "GET",
				url: `/v1/userops/${hash}/receipt`,
			});
			return { status: res.statusCode, body: res.json() };
		} finally {
			await app.close();
		}
	};

	it("answers a bundler that does not answer in time with 504", async () => {
		const { status, body } = await receiptVia(() => new Promise(() => {}));
		expect(status).toBe(504);
		expect(body).toEqual({
			error: "upstream-timeout",
			message: `bundler did not answer within ${TIMEOUT_MS} ms`,
		});
	});

	it("answers an oversized bundler response with 502", async () => {
		const { status, body } = await receiptVia(
			async () =>
				new Response(
					JSON.stringify({
						jsonrpc: "2.0",
						id: 1,
						result: { logs: "x".repeat(MAX_BYTES) },
					}),
				),
		);
		expect(status).toBe(502);
		expect(body).toEqual({
			error: "upstream-response-too-large",
			message: `bundler response exceeded ${MAX_BYTES} bytes`,
		});
	});
});
