import assert from "node:assert/strict";
import { test } from "node:test";
import { getAddress, type Hex, pad } from "viem";
import {
	implementationFromSlot,
	implementationFromUpgradedLogs,
	isMethodRefusedError,
	isUpgradedLogWalkLimitError,
	proxyDeployBlock,
	proxyImplementation,
	proxyImplementationWithSource,
	UPGRADED_LOG_CHUNK,
	UPGRADED_LOG_MAX_CHUNKS,
	UpgradedLogWalkLimitError,
} from "../erc1967";

const implementation = getAddress("0x326549c3600bfa31cb44213df0576ae79e70e4ac");
const proxy = getAddress("0x4bf0c2f63c4fa20d88b8126298fffc64710ece96");

test("implementationFromSlot reads the low 20 bytes of the slot word, however a client returns it", () => {
	assert.equal(implementationFromSlot(pad(implementation)), implementation);
	assert.equal(
		implementationFromSlot(implementation.toLowerCase()),
		implementation,
	);
});

test("an empty or zero slot is no implementation", () => {
	for (const word of [undefined, null, "0x", pad("0x00"), "not hex"])
		assert.equal(implementationFromSlot(word), null, String(word));
});

test("the Upgraded-log walk reads back from latest in chunks and takes the newest upgrade", async () => {
	const older = getAddress("0x44ef48a4bead5571b3b13b81400ea7930e5810d6");
	const ranges: [bigint, bigint][] = [];
	const found = await implementationFromUpgradedLogs(async (from, to) => {
		ranges.push([from, to]);
		// Two upgrades in the second chunk back; nothing in the newest one.
		return from <= 5_000n && 5_000n <= to
			? [
					{ topics: ["0x", pad(older)] },
					{ topics: ["0x", pad(implementation)] },
				]
			: [];
	}, 15_000n);
	assert.equal(found, implementation);
	assert.deepEqual(ranges, [
		[15_000n - UPGRADED_LOG_CHUNK + 1n, 15_000n],
		[0n, 15_000n - UPGRADED_LOG_CHUNK],
	]);
	assert.equal(
		await implementationFromUpgradedLogs(async () => [], 25_000n),
		null,
	);
});

test("each chunk spans at most 9,000 blocks, counted inclusively, so a relay capped at 9,000 accepts it", async () => {
	assert.equal(UPGRADED_LOG_CHUNK, 9_000n);
	const spans: bigint[] = [];
	await implementationFromUpgradedLogs(async (from, to) => {
		spans.push(to - from + 1n);
		return [];
	}, 50_000n);
	assert.ok(spans.length > 1);
	for (const span of spans) assert.ok(span <= 9_000n, String(span));
});

test("the walk stops at fromBlock", async () => {
	const ranges: [bigint, bigint][] = [];
	const found = await implementationFromUpgradedLogs(
		async (from, to) => {
			ranges.push([from, to]);
			return [];
		},
		30_000n,
		{ fromBlock: 20_000n },
	);
	assert.equal(found, null);
	assert.deepEqual(ranges, [
		[21_001n, 30_000n],
		[20_000n, 21_000n],
	]);
});

test("a walk that finds no upgrade gives up after maxChunks requests, with an error that says how to go further", async () => {
	let requests = 0;
	await assert.rejects(
		implementationFromUpgradedLogs(
			async () => {
				requests++;
				return [];
			},
			100_000_000n,
			{ maxChunks: 3 },
		),
		/no Upgraded event in blocks 99973001-100000000.*after 3 eth_getLogs requests.*larger maxChunks/,
	);
	assert.equal(requests, 3);
	// The default stops a non-proxy far above block 0 on a long chain.
	requests = 0;
	await assert.rejects(
		implementationFromUpgradedLogs(async () => {
			requests++;
			return [];
		}, 100_000_000n),
		/no Upgraded event/,
	);
	assert.equal(requests, UPGRADED_LOG_MAX_CHUNKS);
});

/** A client whose eth_getStorageAt is refused, with logs from `upgrades` (block → implementation). */
function refusingClient(
	upgrades: Map<bigint, Hex>,
	head: { block: bigint },
	refusal: unknown = new Error("JSON RPC method not whitelisted"),
) {
	const requests: [bigint, bigint][] = [];
	/** The arguments of each getBlockNumber call. */
	const heads: unknown[] = [];
	const client = {
		getStorageAt: async () => {
			throw refusal;
		},
		getBlockNumber: async (args?: unknown) => {
			heads.push(args);
			return head.block;
		},
		request: async ({
			params: [filter],
		}: {
			params: [{ fromBlock: Hex; toBlock: Hex }];
		}) => {
			const from = BigInt(filter.fromBlock);
			const to = BigInt(filter.toBlock);
			requests.push([from, to]);
			return [...upgrades]
				.filter(([block]) => from <= block && block <= to)
				.sort(([a], [b]) => (a < b ? -1 : 1))
				.map(([block, address]) => ({
					blockNumber: `0x${block.toString(16)}`,
					topics: ["0x", pad(address)],
				}));
		},
	};
	return { client: client as never, requests, heads };
}

test("proxyImplementation falls back to the Upgraded logs when eth_getStorageAt is refused", async () => {
	const refused = new Error("JSON RPC method not whitelisted");
	const { client } = refusingClient(
		new Map([[1n, implementation]]),
		{ block: 3n },
		refused,
	);
	assert.equal(await proxyImplementation(client, proxy), implementation);
	// A client that cannot read logs keeps the original error.
	await assert.rejects(
		proxyImplementation(
			{
				getStorageAt: async () => {
					throw refused;
				},
			},
			proxy,
		),
		refused,
	);
});

test("proxyImplementation falls back on a method-not-found code too (wallet-api's read relay)", async () => {
	const { client } = refusingClient(
		new Map([[1n, implementation]]),
		{ block: 3n },
		Object.assign(new Error("RPC Request failed."), { code: -32601 }),
	);
	assert.equal(await proxyImplementation(client, proxy), implementation);
});

test("proxyImplementation raises any other storage-read error unchanged, and reads no logs", async () => {
	for (const failure of [
		new Error("The request took too long to respond."),
		Object.assign(
			new Error(
				'HTTP request failed.\n\nStatus: 429\nRequest body: {"method":"eth_getStorageAt","params":[]}',
			),
			{ status: 429 },
		),
	]) {
		const { client, requests } = refusingClient(
			new Map([[1n, implementation]]),
			{ block: 3n },
			failure,
		);
		await assert.rejects(proxyImplementation(client, proxy), failure);
		assert.deepEqual(requests, []);
	}
});

test("when the fallback fails too, its error names both failures and keeps the storage-read error as cause", async () => {
	const refused = new Error("JSON RPC method not whitelisted");
	const client = {
		getStorageAt: async () => {
			throw refused;
		},
		getBlockNumber: async () => 3n,
		request: async () => {
			throw new Error("HTTP request failed. Status: 429");
		},
	};
	await assert.rejects(proxyImplementation(client as never, proxy), (error) => {
		assert.ok(error instanceof Error);
		assert.match(error.message, /refused eth_getStorageAt/);
		assert.match(error.message, /Status: 429/);
		assert.equal(error.cause, refused);
		return true;
	});
});

test("proxyImplementation reads only the blocks after its checkpoint, per client and proxy", async () => {
	const upgraded = getAddress("0x44ef48a4bead5571b3b13b81400ea7930e5810d6");
	const upgrades = new Map<bigint, Hex>([[1_000n, implementation]]);
	const head = { block: 50_000n };
	const { client, requests } = refusingClient(upgrades, head);

	assert.equal(await proxyImplementation(client, proxy), implementation);
	const firstWalk = requests.length;
	assert.equal(firstWalk, 6);

	// Same head: one request over the blocks after the checkpoint, 64 blocks behind the head.
	assert.equal(await proxyImplementation(client, proxy), implementation);
	assert.deepEqual(requests.slice(firstWalk), [[49_937n, 50_000n]]);

	// Ten new blocks, no upgrade in them: one request from the checkpoint to the head.
	head.block = 50_010n;
	assert.equal(await proxyImplementation(client, proxy), implementation);
	assert.deepEqual(requests.slice(firstWalk + 1), [[49_937n, 50_010n]]);

	// An upgrade in the new blocks is picked up.
	upgrades.set(50_015n, upgraded);
	head.block = 50_020n;
	assert.equal(await proxyImplementation(client, proxy), upgraded);
	assert.deepEqual(requests.at(-1), [49_947n, 50_020n]);

	// Another client, or another proxy, walks on its own.
	const other = refusingClient(upgrades, head);
	assert.equal(await proxyImplementation(other.client, proxy), upgraded);
	assert.equal(other.requests.length, 1);
});

test("proxyImplementationWithSource says whether the answer came from the slot or from the logs", async () => {
	const slotClient = {
		getStorageAt: async () => pad(implementation),
	} as never;
	assert.deepEqual(await proxyImplementationWithSource(slotClient, proxy), {
		implementation,
		source: "slot",
	});
	const { client } = refusingClient(new Map([[1n, implementation]]), {
		block: 3n,
	});
	assert.deepEqual(await proxyImplementationWithSource(client, proxy), {
		implementation,
		source: "logs",
	});
	assert.equal(await proxyImplementation(client, proxy), implementation);
});

test("an upgrade a reorganisation removes is not kept, and a head below the checkpoint starts the walk again", async () => {
	const orphaned = getAddress("0x44ef48a4bead5571b3b13b81400ea7930e5810d6");
	const upgrades = new Map<bigint, Hex>([[1_000n, implementation]]);
	const head = { block: 50_000n };
	const { client, requests } = refusingClient(upgrades, head);
	assert.equal(await proxyImplementation(client, proxy), implementation);

	// An upgrade within 64 blocks of the head is returned, but not kept.
	upgrades.set(49_990n, orphaned);
	assert.equal(await proxyImplementation(client, proxy), orphaned);
	// A reorganisation removes it: the next read, at the same head or a newer one, does not return it.
	upgrades.delete(49_990n);
	assert.equal(await proxyImplementation(client, proxy), implementation);
	head.block = 50_001n;
	assert.equal(await proxyImplementation(client, proxy), implementation);

	// The head falls below the checkpoint (49,937): nothing kept is trusted, and the walk starts
	// again from the new head.
	head.block = 49_000n;
	const before = requests.length;
	assert.equal(await proxyImplementation(client, proxy), implementation);
	assert.deepEqual(requests[before], [40_001n, 49_000n]);
	assert.equal(requests.length - before, 6);
});

test("a walk that hits maxChunks continues back on the next read through the same client", async () => {
	const head = { block: 100_000n };
	const { client, requests } = refusingClient(
		new Map([[60_000n, implementation]]),
		head,
	);
	await assert.rejects(
		proxyImplementation(client, proxy, { maxChunks: 3 }),
		/no Upgraded event in blocks 73001-100000.*Read again through the same client to continue the search further back/,
	);
	assert.deepEqual(requests, [
		[91_001n, 100_000n],
		[82_001n, 91_000n],
		[73_001n, 82_000n],
	]);
	// The next read checks the newest blocks, then goes on back from block 73,000.
	assert.equal(
		await proxyImplementation(client, proxy, { maxChunks: 3 }),
		implementation,
	);
	assert.deepEqual(requests.slice(3), [
		[99_937n, 100_000n],
		[64_001n, 73_000n],
		[55_001n, 64_000n],
	]);
	// Complete now: one request for the newest blocks.
	assert.equal(
		await proxyImplementation(client, proxy, { maxChunks: 3 }),
		implementation,
	);
	assert.deepEqual(requests.slice(6), [[99_937n, 100_000n]]);
});

/** `client` with eth_getLogs failing on the requests numbered in `failOn` (1-based), as a rate limit does. */
function failingOn(client: unknown, failOn: Set<number>) {
	let calls = 0;
	const inner = client as { request: (args: unknown) => Promise<unknown> };
	return {
		...(client as object),
		request: async (args: unknown) => {
			calls++;
			if (failOn.has(calls))
				throw Object.assign(new Error("HTTP request failed. Status: 429"), {
					status: 429,
				});
			return inner.request(args);
		},
	} as never;
}

test("a walk stopped at its limit is an UpgradedLogWalkLimitError naming the proxy; a failed request is not", async () => {
	const { client } = refusingClient(new Map([[60_000n, implementation]]), {
		block: 100_000n,
	});
	await assert.rejects(
		proxyImplementationWithSource(client, proxy, { maxChunks: 1 }),
		(error) => {
			assert.ok(error instanceof UpgradedLogWalkLimitError);
			assert.ok(isUpgradedLogWalkLimitError(error));
			assert.match(
				(error as Error).message,
				new RegExp(`could not read the implementation of ${proxy}`),
			);
			return true;
		},
	);
	const failing = refusingClient(new Map([[60_000n, implementation]]), {
		block: 100_000n,
	});
	await assert.rejects(
		proxyImplementationWithSource(
			failingOn(failing.client, new Set([1])),
			proxy,
		),
		(error) => {
			assert.equal(isUpgradedLogWalkLimitError(error), false);
			assert.match((error as Error).message, /Status: 429/);
			return true;
		},
	);
	// The type is found through a cause chain too.
	assert.ok(
		isUpgradedLogWalkLimitError(
			new Error("outer", { cause: new UpgradedLogWalkLimitError("inner") }),
		),
	);
	assert.equal(isUpgradedLogWalkLimitError("not an error"), false);
});

test("a failed eth_getLogs request keeps the blocks already answered: the next read continues below them", async () => {
	const head = { block: 100_000n };
	const { client, requests } = refusingClient(
		new Map([[60_000n, implementation]]),
		head,
	);
	// The third request fails.
	const flaky = failingOn(client, new Set([3]));
	await assert.rejects(proxyImplementation(flaky, proxy), /Status: 429/);
	assert.deepEqual(requests, [
		[91_001n, 100_000n],
		[82_001n, 91_000n],
	]);
	// The next read checks the newest blocks, then retries the failed chunk and goes on back.
	assert.equal(await proxyImplementation(flaky, proxy), implementation);
	assert.deepEqual(requests.slice(2), [
		[99_937n, 100_000n],
		[73_001n, 82_000n],
		[64_001n, 73_000n],
		[55_001n, 64_000n],
	]);
});

test("a failed request after a complete walk keeps the answer it found", async () => {
	const head = { block: 100_000n };
	const { client, requests } = refusingClient(
		new Map([[60_000n, implementation]]),
		head,
	);
	// The sixth request, the first of the second read, fails.
	const flaky = failingOn(client, new Set([6]));
	assert.equal(await proxyImplementation(flaky, proxy), implementation);
	assert.equal(requests.length, 5);
	await assert.rejects(proxyImplementation(flaky, proxy), /Status: 429/);
	// The answer was kept: one request for the newest blocks, no new walk.
	assert.equal(await proxyImplementation(flaky, proxy), implementation);
	assert.deepEqual(requests.slice(5), [[99_937n, 100_000n]]);
});

test("a failed request in the stateless walk is raised as it is", async () => {
	const failure = new Error("HTTP request failed. Status: 429");
	await assert.rejects(
		implementationFromUpgradedLogs(async () => {
			throw failure;
		}, 100_000n),
		failure,
	);
});

test("maxChunks must be a non-negative safe integer, checked before any request", async () => {
	for (const maxChunks of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
		let walkRequests = 0;
		await assert.rejects(
			implementationFromUpgradedLogs(
				async () => {
					walkRequests++;
					return [];
				},
				100n,
				{ maxChunks },
			),
			/maxChunks must be a non-negative integer/,
			String(maxChunks),
		);
		assert.equal(walkRequests, 0);
		let storageReads = 0;
		const { client, requests } = refusingClient(new Map(), { block: 100n });
		await assert.rejects(
			proxyImplementation(
				{
					...(client as object),
					getStorageAt: async () => {
						storageReads++;
						throw new Error("JSON RPC method not whitelisted");
					},
				} as never,
				proxy,
				{ maxChunks },
			),
			/maxChunks must be a non-negative integer/,
		);
		assert.deepEqual([storageReads, requests.length], [0, 0]);
	}
	// Zero is a valid limit: no request at all.
	await assert.rejects(
		implementationFromUpgradedLogs(async () => [], 100n, { maxChunks: 0 }),
		/after 0 eth_getLogs requests/,
	);
});

test("the head is read uncached, so an upgrade in the newest block is not missed", async () => {
	const { client, heads } = refusingClient(new Map([[1n, implementation]]), {
		block: 3n,
	});
	await proxyImplementation(client, proxy);
	assert.deepEqual(heads, [{ cacheTime: 0 }]);
});

test("concurrent reads on the same client and proxy share one walk", async () => {
	const head = { block: 50_000n };
	const { client, requests, heads } = refusingClient(
		new Map([[1_000n, implementation]]),
		head,
	);
	assert.deepEqual(
		await Promise.all([
			proxyImplementation(client, proxy),
			proxyImplementation(client, proxy),
		]),
		[implementation, implementation],
	);
	assert.equal(heads.length, 1);
	assert.equal(requests.length, 6);
	// The shared walk kept its checkpoint: the next read starts from it.
	head.block = 50_010n;
	assert.equal(await proxyImplementation(client, proxy), implementation);
	assert.deepEqual(requests.slice(6), [[49_937n, 50_010n]]);
});

test("the memory is kept per fromBlock, and a retry with a larger maxChunks searches further", async () => {
	const head = { block: 50_000n };
	const { client } = refusingClient(new Map([[1_000n, implementation]]), head);
	// No upgrade since block 40,000; a lower floor still finds the older one.
	assert.equal(
		await proxyImplementation(client, proxy, { fromBlock: 40_000n }),
		null,
	);
	assert.equal(await proxyImplementation(client, proxy), implementation);

	const other = refusingClient(new Map([[1_000n, implementation]]), head);
	await assert.rejects(
		proxyImplementation(other.client, proxy, { maxChunks: 2 }),
		/no Upgraded event/,
	);
	assert.equal(
		await proxyImplementation(other.client, proxy, { maxChunks: 10 }),
		implementation,
	);
});

test("isMethodRefusedError matches refusals of the method, and nothing else", () => {
	for (const refusal of [
		new Error("JSON RPC method not whitelisted"),
		new Error("method eth_getStorageAt is not allowed"),
		new Error("the method eth_getStorageAt does not exist/is not available"),
		new Error("Method not found"),
		new Error("Unauthorized method: eth_getStorageAt"),
		Object.assign(new Error("x"), { code: -32004 }),
		// viem: the node's error under `cause`
		new Error("RPC Request failed.", {
			cause: { code: -32601, message: "x" },
		}),
		// ethers v6: the node's error under `error` or `info.error`
		Object.assign(new Error("could not coalesce error"), {
			error: { code: -32000, message: "JSON RPC method not whitelisted" },
		}),
		Object.assign(new Error("unsupported operation"), {
			info: { error: { code: -32601, message: "x" } },
		}),
	])
		assert.equal(isMethodRefusedError(refusal), true, refusal.message);

	for (const other of [
		new Error("The request took too long to respond."),
		new Error(
			'HTTP request failed. Status: 429 Request body: {"method":"eth_getStorageAt"}',
		),
		Object.assign(new Error("could not coalesce error"), {
			error: { code: -32000, message: "header not found" },
			payload: { method: "eth_getStorageAt" },
		}),
		Object.assign(new Error("limit exceeded"), { code: -32005 }),
		undefined,
		"timeout",
	])
		assert.equal(isMethodRefusedError(other), false, String(other));
});

test("a deployment block applies only to the proxy it was recorded for", () => {
	const proxy = getAddress("0xb2c7081be89d88f1da020530ebd5c14b8871615a");
	const deployed = { address: proxy, blockNumber: 557_335 };
	assert.equal(proxyDeployBlock(proxy, deployed), 557_335n);
	assert.equal(
		proxyDeployBlock(proxy, { address: proxy, blockNumber: 7n }),
		7n,
	);
	// Case does not matter, on either side.
	assert.equal(
		proxyDeployBlock(proxy.toLowerCase() as Hex, deployed),
		557_335n,
	);
	assert.equal(
		proxyDeployBlock(proxy, {
			...deployed,
			address: proxy.toLowerCase() as Hex,
		}),
		557_335n,
	);
	// Another proxy, or anything missing: the walk starts at block 0.
	assert.equal(
		proxyDeployBlock("0x0000000000000000000000000000000000000001", deployed),
		undefined,
	);
	assert.equal(proxyDeployBlock(undefined, deployed), undefined);
	assert.equal(proxyDeployBlock(proxy, undefined), undefined);
	assert.equal(proxyDeployBlock(proxy, { address: proxy }), undefined);
	assert.equal(proxyDeployBlock(proxy, { blockNumber: 1 }), undefined);
	// A malformed address (an unvalidated flag) does not match, and does not throw.
	assert.equal(
		proxyDeployBlock("0xnot-an-address" as Hex, deployed),
		undefined,
	);
	// Not even when both sides hold the same malformed value.
	assert.equal(
		proxyDeployBlock("0x", { address: "0x", blockNumber: 7 }),
		undefined,
	);
	assert.equal(
		proxyDeployBlock("0xnot-an-address" as Hex, {
			address: "0xNOT-AN-ADDRESS" as Hex,
			blockNumber: 7,
		}),
		undefined,
	);
});
