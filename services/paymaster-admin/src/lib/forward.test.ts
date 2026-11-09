import { describe, expect, it } from "vitest";
import { readForwardPages } from "./forward";

/** A node that takes at most `cap` blocks a query, narrowing to the newest as readWindow does. */
const capped = (cap: bigint, events: readonly bigint[]) => {
	const asked: [bigint, bigint][] = [];
	const read = async ({
		fromBlock,
		toBlock,
	}: {
		fromBlock: bigint;
		toBlock: bigint;
	}) => {
		const from =
			toBlock - fromBlock + 1n > cap ? toBlock - cap + 1n : fromBlock;
		asked.push([from, toBlock]);
		return {
			fromBlock: from,
			toBlock,
			items: events.filter((block) => block >= from && block <= toBlock),
		};
	};
	return { read, asked };
};

describe("readForwardPages", () => {
	it("reads a long gap without a hole, oldest first, through a capped node", async () => {
		const events = [5n, 2_500n, 9_100n, 18_000n];
		const { read, asked } = capped(2_000n, events);
		const result = await readForwardPages(read, 1n, 18_000n, 9_000n);

		expect(result).toEqual({ fromBlock: 1n, toBlock: 18_000n, items: events });
		const covered = [...asked].sort((a, b) => Number(a[0] - b[0]));
		let next = 1n;
		for (const [from, to] of covered) {
			expect(from).toBeLessThanOrEqual(next);
			if (to + 1n > next) next = to + 1n;
		}
		expect(next).toBe(18_001n);
	});

	it("reads nothing when there are no new blocks", async () => {
		const { read, asked } = capped(9_000n, []);
		expect(await readForwardPages(read, 101n, 100n)).toEqual({
			fromBlock: 101n,
			toBlock: 100n,
			items: [],
		});
		expect(asked).toEqual([]);
	});
});
