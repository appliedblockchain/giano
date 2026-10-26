import { type Address, parseEther } from "viem";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	anvilAvailable,
	type Bundler,
	type Devnet,
	executeCall,
	rpc,
	startBundler,
	startDevnet,
} from "./harness.js";
import { createOps } from "./ops.js";

/**
 * One bundler process serving several chains, as GIANO_CHAINS configures it: each chain at its
 * own path with its own lanes, and a chain that cannot connect refused without affecting the rest.
 */

const recipient: Address = "0x000000000000000000000000000000000000dEaD";

describe.skipIf(!anvilAvailable)("one bundler, several chains", () => {
	let a: Devnet;
	let b: Devnet;
	let bundler: Bundler;

	beforeAll(async () => {
		[a, b] = await Promise.all([startDevnet(31337), startDevnet(31338)]);
		bundler = await startBundler([a, b], {
			// A third chain whose RPC never answers: it must stay unavailable without blocking the others.
			extraChains: [
				{
					chainId: 999,
					name: "unreachable",
					rpcUrl: "http://127.0.0.1:1",
					entryPoint: a.entryPoint,
					chainType: "default",
					maxBlockRange: 2000n,
				},
			],
		});
	});
	afterAll(async () => {
		await bundler?.stop();
		a?.stop();
		b?.stop();
	});

	it("serves each chain at its own path", async () => {
		expect((await rpc(`${bundler.base}/31337`, "eth_chainId")).result).toBe(
			"0x7a69",
		);
		expect((await rpc(`${bundler.base}/31338`, "eth_chainId")).result).toBe(
			"0x7a6a",
		);
	});

	it("submits on both chains through one process, each with its own nonce lane", async () => {
		const results = await Promise.all(
			[a, b].map(async (devnet) => {
				const url = `${bundler.base}/${devnet.chainId}`;
				const ops = createOps(devnet, url);
				const sender = (await ops.draft(7n, "0x", false)).sender as Address;
				await devnet.test.setBalance({
					address: sender,
					value: parseEther("1"),
				});
				const { op, hash } = await ops.prepare(7n, executeCall(recipient, 1n));
				expect(
					(await rpc(url, "eth_sendUserOperation", [op, devnet.entryPoint]))
						.result,
				).toBe(hash);
				return { devnet, receipt: await ops.waitForReceipt(hash), hash };
			}),
		);
		for (const { devnet, receipt, hash } of results) {
			expect(receipt).toMatchObject({ userOpHash: hash, success: true });
			// Each chain's operation is found on that chain and only there.
			const other = devnet === a ? b : a;
			expect(
				(
					await rpc(
						`${bundler.base}/${other.chainId}`,
						"eth_getUserOperationReceipt",
						[hash],
					)
				).result,
			).toBeNull();
		}
	});

	it("refuses an operation sent to the wrong chain", async () => {
		const ops = createOps(a, `${bundler.base}/31337`);
		// The account funded and deployed on chain A by the test above.
		const { op } = await ops.prepare(7n, executeCall(recipient, 1n));
		// Signed for chain A: on chain B the hash differs, so the signature cannot validate.
		const misrouted = await rpc(
			`${bundler.base}/31338`,
			"eth_sendUserOperation",
			[op, b.entryPoint],
		);
		expect(misrouted.error?.message).toMatch(/AA2[0-9]/);
	});

	it("asks for a chain in the path when it serves more than one", async () => {
		const response = await fetch(bundler.base, {
			method: "POST",
			body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId" }),
		});
		expect(response.status).toBe(400);
		expect(
			((await response.json()) as { error: { message: string } }).error.message,
		).toMatch(/serves chains 31337, 31338, 999: POST \/<chainId>/);
	});

	it("tells an unserved chain from an unavailable one", async () => {
		const unserved = await fetch(`${bundler.base}/1`, {
			method: "POST",
			body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId" }),
		});
		expect(unserved.status).toBe(404);
		const unavailable = await fetch(`${bundler.base}/999`, {
			method: "POST",
			body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId" }),
		});
		expect(unavailable.status).toBe(503);
		expect(
			((await unavailable.json()) as { error: { message: string } }).error
				.message,
		).toMatch(/chain 999 is not available yet/);
	});

	it("reports health per chain, and stays healthy while one chain is down", async () => {
		const response = await fetch(`${bundler.base}/health`);
		expect(response.status).toBe(200);
		const health = (await response.json()) as {
			chains: Array<{ chainId: number; status: string }>;
		};
		expect(health.chains.map((chain) => [chain.chainId, chain.status])).toEqual(
			[
				[31337, "ready"],
				[31338, "ready"],
				[999, "connecting"],
			],
		);
	});
});
