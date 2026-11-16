import assert from "node:assert/strict";
import { test } from "node:test";
import { getAddress, pad } from "viem";
import {
	implementationFromSlot,
	implementationFromUpgradedLogs,
	proxyImplementation,
	UPGRADED_LOG_CHUNK,
} from "../erc1967";

const implementation = getAddress("0x326549c3600bfa31cb44213df0576ae79e70e4ac");

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

test("proxyImplementation falls back to the Upgraded logs when eth_getStorageAt is refused", async () => {
	const refused = new Error("JSON RPC method not whitelisted");
	const client = {
		getStorageAt: async () => {
			throw refused;
		},
		getBlockNumber: async () => 3n,
		request: async () => [{ topics: ["0x", pad(implementation)] }],
	};
	assert.equal(
		await proxyImplementation(client as never, implementation),
		implementation,
	);
	// A client that cannot read logs keeps the original error.
	await assert.rejects(
		proxyImplementation({ getStorageAt: client.getStorageAt }, implementation),
		refused,
	);
});
