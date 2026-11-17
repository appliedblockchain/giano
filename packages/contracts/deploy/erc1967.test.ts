import assert from "node:assert/strict";
import { test } from "node:test";
import { getAddress, type Hex, pad } from "viem";
import {
	implementationFromSlot,
	implementationFromUpgradedLogs,
	isMethodRefusedError,
	proxyImplementation,
	UPGRADED_LOG_CHUNK,
	UPGRADED_LOG_MAX_CHUNKS,
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
		/no Upgraded event in blocks 99973001-100000000.*after 3 eth_getLogs requests.*fromBlock/,
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
	const client = {
		getStorageAt: async () => {
			throw refusal;
		},
		getBlockNumber: async () => head.block,
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
				.map(([, address]) => ({ topics: ["0x", pad(address)] }));
		},
	};
	return { client: client as never, requests };
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

test("proxyImplementation walks only the blocks after its last walk, per client and proxy", async () => {
	const upgraded = getAddress("0x44ef48a4bead5571b3b13b81400ea7930e5810d6");
	const upgrades = new Map<bigint, Hex>([[1_000n, implementation]]);
	const head = { block: 50_000n };
	const { client, requests } = refusingClient(upgrades, head);

	assert.equal(await proxyImplementation(client, proxy), implementation);
	const firstWalk = requests.length;
	assert.equal(firstWalk, 6);

	// Same head: no request at all.
	assert.equal(await proxyImplementation(client, proxy), implementation);
	assert.equal(requests.length, firstWalk);

	// Ten new blocks, no upgrade in them: one request over those blocks only.
	head.block = 50_010n;
	assert.equal(await proxyImplementation(client, proxy), implementation);
	assert.deepEqual(requests.slice(firstWalk), [[50_001n, 50_010n]]);

	// An upgrade in the new blocks is picked up.
	upgrades.set(50_015n, upgraded);
	head.block = 50_020n;
	assert.equal(await proxyImplementation(client, proxy), upgraded);
	assert.deepEqual(requests.at(-1), [50_011n, 50_020n]);

	// Another client, or another proxy, walks on its own.
	const other = refusingClient(upgrades, head);
	assert.equal(await proxyImplementation(other.client, proxy), upgraded);
	assert.equal(other.requests.length, 1);
});

test("a walk that gave up is not repeated on the next read", async () => {
	const head = { block: 100_000n };
	const { client, requests } = refusingClient(new Map(), head);
	await assert.rejects(
		proxyImplementation(client, proxy, { maxChunks: 2 }),
		/no Upgraded event/,
	);
	assert.equal(requests.length, 2);
	await assert.rejects(
		proxyImplementation(client, proxy, { maxChunks: 2 }),
		/no Upgraded event/,
	);
	assert.equal(requests.length, 2);
	head.block = 100_005n;
	await assert.rejects(
		proxyImplementation(client, proxy, { maxChunks: 2 }),
		/no Upgraded event/,
	);
	assert.deepEqual(requests.slice(2), [[100_001n, 100_005n]]);
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
