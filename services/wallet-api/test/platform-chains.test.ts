import * as http from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { paymasterState } from "../src/db/schema.js";
import { probeChain } from "../src/services/chain-probe.js";
import type { ChainVerification } from "../src/services/chain-verify.js";
import {
	ADMIN,
	PLATFORM_ENV,
	platformSignIn,
	type SponsorshipTestContext,
	startMockRpc,
	startSponsorshipStack,
	startTestStack,
	stopTestStack,
	TEST_PAYMASTER_ADDRESS,
	type TestContext,
} from "./setup.js";

/**
 * GET /v1/platform/chains (specs/PLATFORM-ADMIN-SPECS.md §10, openspec platform-chain-status): what
 * only wallet-api can see about each chain, probed in parallel with a 3-second timeout each.
 */

const ENTRY_POINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
const FACTORY = "0x2222222222222222222222222222222222222222";

/** A node that accepts the connection and never answers. */
function startSilentNode(): Promise<{
	url: string;
	close: () => Promise<void>;
}> {
	const held: http.ServerResponse[] = [];
	const server = http.createServer((_req, res) => {
		held.push(res);
	});
	return new Promise((resolve) => {
		server.listen(0, "127.0.0.1", () => {
			const { port } = server.address() as { port: number };
			resolve({
				url: `http://127.0.0.1:${port}`,
				close: () =>
					new Promise((done) => {
						for (const res of held) res.destroy();
						server.closeAllConnections();
						server.close(() => done());
					}),
			});
		});
	});
}

const get = (ctx: TestContext, token?: string) =>
	ctx.app.inject({
		method: "GET",
		url: "/v1/platform/chains",
		headers: token ? { authorization: `Bearer ${token}` } : {},
	});

describe("two chains, one of them down", () => {
	let ctx: TestContext;
	let node: Awaited<ReturnType<typeof startMockRpc>>;
	let silent: Awaited<ReturnType<typeof startSilentNode>>;

	beforeAll(async () => {
		node = await startMockRpc(undefined, { head: 100n });
		silent = await startSilentNode();
		ctx = await startTestStack({
			...PLATFORM_ENV,
			GIANO_CHAINS: JSON.stringify(
				[
					{ chainId: 31337, name: "Devnet A", rpcUrl: node.url },
					{ chainId: 31338, name: "Devnet B", rpcUrl: silent.url },
				].map((chain) => ({
					...chain,
					entryPoint: ENTRY_POINT,
					walletApi: {
						bundlerUrl: `http://bundler-${chain.chainId}.internal:4337`,
						factory: FACTORY,
					},
				})),
			),
		});
	});

	afterAll(async () => {
		await stopTestStack(ctx);
		await node.close();
		await silent.close();
	});

	it("refuses a request without a platform admin session", async () => {
		expect((await get(ctx)).statusCode).toBe(401);
	});

	it("answers within about three seconds: the live chain complete, the dead one's node unreachable", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const started = Date.now();
		const response = await get(ctx, token);
		const elapsed = Date.now() - started;

		expect(response.statusCode).toBe(200);
		expect(elapsed).toBeLessThan(4_500);
		const { signer, chains } = response.json();
		expect(signer).toBe("disabled");
		expect(chains.map((chain: { chainId: number }) => chain.chainId)).toEqual([
			31337, 31338,
		]);
		expect(chains[0]).toMatchObject({
			name: "Devnet A",
			registryStatus: "ready",
			node: { reachable: true, headBlock: "100" },
			bundler: { reachable: true, entryPointSupported: true },
			paymaster: null,
		});
		expect(chains[0].node.headAgeSeconds).toBeLessThan(10);
		expect(chains[1]).toMatchObject({
			name: "Devnet B",
			node: { reachable: false, headBlock: null, headAgeSeconds: null },
			// its bundler is a different endpoint, and answers
			bundler: { reachable: true },
		});
		// no node or bundler URL, internal or keyed, ever leaves the API
		expect(response.body).not.toMatch(/127\.0\.0\.1|internal|http:/);
	}, 10_000);

	it("reports when the prober last looked, not the boot time", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const chain = ctx.app.chains.get(31337);
		const thirtySecondsAgo = new Date(Date.now() - 30_000);
		chain.lastProbe = { at: thirtySecondsAgo, ok: true };

		const [live] = (await get(ctx, token)).json().chains;
		expect(live.lastProbe).toEqual({
			at: thirtySecondsAgo.toISOString(),
			ok: true,
		});

		await probeChain(chain, { log: ctx.app.log, onStatus: () => {} });
		expect(chain.lastProbe?.ok).toBe(true);
		expect(chain.lastProbe?.at.getTime() ?? 0).toBeGreaterThan(
			thirtySecondsAgo.getTime(),
		);
	}, 10_000);

	it("records a recovering chain's full verification, and keeps it unavailable while it fails", async () => {
		const chain = ctx.app.chains.get(31338);
		chain.status = "unavailable";
		const failed: ChainVerification = {
			chainId: 31338,
			reachable: false,
			failures: [{ kind: "unreachable", detail: "no answer" }],
		};
		await probeChain(chain, {
			log: ctx.app.log,
			onStatus: () => {},
			verify: async () => failed,
		});
		expect(chain.status).toBe("unavailable");
		expect(chain.verification?.failures).toEqual(failed.failures);
		expect(chain.lastProbe).toMatchObject({ ok: false, detail: "no answer" });

		await probeChain(chain, {
			log: ctx.app.log,
			onStatus: () => {},
			verify: async () => ({ chainId: 31338, reachable: true, failures: [] }),
		});
		expect(chain.status).toBe("ready");
		expect(chain.verification?.failures).toEqual([]);
	});
});

describe("a sponsoring chain", () => {
	let ctx: SponsorshipTestContext;

	beforeAll(async () => {
		ctx = await startSponsorshipStack(PLATFORM_ENV);
		await ctx.db.insert(paymasterState).values({
			chainId: 31337,
			paymasterAddress: TEST_PAYMASTER_ADDRESS.toLowerCase(),
			depositWei: "5000",
			treasuryWei: "100",
			stakeWei: "1000",
			invariantSlackWei: "40",
			lastSyncedBlock: 90n,
			checkedAt: new Date("2026-11-03T12:00:00Z"),
		});
	});

	afterAll(async () => {
		await stopTestStack(ctx);
	});

	it("reports the signer once, and the paymaster's ledger with the watcher's lag behind the head", async () => {
		// this stack's node is at genesis; the watcher's lag needs a head ahead of what it synced
		const chain = ctx.app.chains.get(31337);
		const read = chain.publicClient.getBlock.bind(chain.publicClient);
		vi.spyOn(chain.publicClient, "getBlock").mockImplementation(
			async (args) => ({
				...(await read(args)),
				number: 100n,
			}),
		);
		const token = await platformSignIn(ctx.app, ADMIN);
		const response = await get(ctx, token);
		expect(response.statusCode).toBe(200);
		const { signer, chains } = response.json();
		expect(signer).toBe("ok");
		expect(chains[0].paymaster).toEqual({
			address: TEST_PAYMASTER_ADDRESS,
			depositWei: "5000",
			treasuryWei: "100",
			stakeWei: "1000",
			invariantSlackWei: "40",
			lastSyncedBlock: "90",
			watcherLagBlocks: 10,
			checkedAt: "2026-11-03T12:00:00.000Z",
		});
	});
});
