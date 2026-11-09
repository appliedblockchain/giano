import type { TimelockOperation } from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import { merge, readForward } from "./usePendingOperations";

const operation = (
	id: string,
	overrides: Partial<TimelockOperation> = {},
): TimelockOperation => ({
	id: `0x${id.padStart(64, "0")}`,
	calls: [{ target: `0x${"11".repeat(20)}`, value: 0n, data: "0x1234" }],
	predecessor: `0x${"00".repeat(32)}`,
	salt: `0x${"5a".repeat(32)}`,
	delay: 60n,
	state: "waiting",
	readyAt: 1_800_000_000,
	scheduledBlock: 10n,
	scheduledTransaction: `0x${"aa".repeat(32)}`,
	complete: true,
	...overrides,
});

describe("merge", () => {
	it("keeps what an operation was scheduled with, and takes its new state from the newer read", () => {
		const scheduled = operation("1");
		// what an execution log alone reconstructs: no scheduling, so incomplete
		const executed = operation("1", {
			state: "done",
			readyAt: undefined,
			complete: false,
			salt: `0x${"00".repeat(32)}`,
			scheduledBlock: undefined,
			scheduledTransaction: undefined,
			executedBlock: 20n,
			executedTransaction: `0x${"bb".repeat(32)}`,
		});
		const [merged] = merge([scheduled], [executed]);
		expect(merged).toMatchObject({
			state: "done",
			complete: true,
			salt: scheduled.salt,
			scheduledTransaction: scheduled.scheduledTransaction,
			executedTransaction: executed.executedTransaction,
			readyAt: scheduled.readyAt,
		});
	});

	it("adds operations the newer read found, and keeps those it did not mention", () => {
		const merged = merge(
			[operation("1")],
			[operation("2", { scheduledBlock: 30n })],
		);
		expect(merged.map((entry) => entry.id.slice(-1))).toEqual(["1", "2"]);
	});

	it("lets a complete newer read fill in an operation first seen incomplete", () => {
		const partial = operation("3", {
			complete: false,
			salt: `0x${"00".repeat(32)}`,
		});
		const [merged] = merge([partial], [operation("3")]);
		expect(merged.complete).toBe(true);
		expect(merged.salt).toBe(`0x${"5a".repeat(32)}`);
	});
});

describe("merge of a cancelled operation scheduled again", () => {
	it("takes the new scheduling whole, with nothing of the cancelled one", () => {
		const cancelled = operation("1", {
			state: "cancelled",
			cancelledBlock: 20n,
			cancelledTransaction: `0x${"cc".repeat(32)}`,
		});
		const again = operation("1", {
			scheduledBlock: 30n,
			scheduledTransaction: `0x${"bb".repeat(32)}`,
		});
		const [merged] = merge([cancelled], [again]);
		expect(merged.state).toBe("waiting");
		expect(merged.cancelledBlock).toBeUndefined();
		expect(merged.scheduledTransaction).toBe(again.scheduledTransaction);
	});
});

describe("readForward", () => {
	/** A timelock whose node accepts at most `cap` blocks a query, narrowing to the newest as readWindow does. */
	const timelock = (head: bigint, cap: bigint, found: Map<bigint, string>) => {
		const asked: [bigint, bigint][] = [];
		return {
			asked,
			client: {
				publicClient: { getBlockNumber: async () => head },
				getOperations: async ({
					range,
				}: {
					range: { fromBlock: bigint; toBlock: bigint };
				}) => {
					const fromBlock =
						range.toBlock - range.fromBlock + 1n > cap
							? range.toBlock - cap + 1n
							: range.fromBlock;
					asked.push([fromBlock, range.toBlock]);
					const operations = [...found]
						.filter(([block]) => block >= fromBlock && block <= range.toBlock)
						.map(([block, id]) => operation(id, { scheduledBlock: block }));
					return { fromBlock, toBlock: range.toBlock, operations };
				},
			} as unknown as Parameters<typeof readForward>[0],
		};
	};

	it("reads every block to the head, including what a capped node narrowed away", async () => {
		// a long gap: 25,000 blocks, read from a node that takes 2,000 a query
		const found = new Map([
			[1_000n, "1"],
			[12_000n, "2"],
			[25_000n, "3"],
		]);
		const { client, asked } = timelock(25_000n, 2_000n, found);
		const result = await readForward(client, 1n);

		expect(result.toBlock).toBe(25_000n);
		expect(result.operations.map((entry) => entry.id.slice(-1)).sort()).toEqual(
			["1", "2", "3"],
		);
		// covered without a hole: every block from 1 to the head is in some query
		const covered = [...asked].sort((a, b) => Number(a[0] - b[0]));
		let next = 1n;
		for (const [from, to] of covered) {
			expect(from).toBeLessThanOrEqual(next);
			if (to + 1n > next) next = to + 1n;
		}
		expect(next).toBe(25_001n);
	});

	it("reads nothing when there are no new blocks", async () => {
		const { client, asked } = timelock(100n, 9_000n, new Map());
		expect(await readForward(client, 101n)).toEqual({
			toBlock: 100n,
			operations: [],
		});
		expect(asked).toEqual([]);
	});
});
