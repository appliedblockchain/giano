import { describe, expect, it } from "vitest";
import { readForwardPages } from "./forward";

/** A node that takes at most `cap` blocks a query, narrowing to the newest as readWindow does. */
const capped = (cap: bigint, events: readonly bigint[]) => {
	const asked: [bigint, bigint][] = [];
	/** Every range asked for, before the node narrowed it. */
	const requested: [bigint, bigint][] = [];
	const read = async ({
		fromBlock,
		toBlock,
	}: {
		fromBlock: bigint;
		toBlock: bigint;
	}) => {
		requested.push([fromBlock, toBlock]);
		const from =
			toBlock - fromBlock + 1n > cap ? toBlock - cap + 1n : fromBlock;
		asked.push([from, toBlock]);
		return {
			fromBlock: from,
			toBlock,
			items: events.filter((block) => block >= from && block <= toBlock),
		};
	};
	return { read, asked, requested };
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

	it("asks for the narrowed span from then on, so a capped node refuses only the first request", async () => {
		// sepolia.base.org takes 200: a whole 45,000-block gap must not be narrowed again for every 200.
		const { read, requested } = capped(200n, [7n, 44_999n]);
		const result = await readForwardPages(read, 1n, 45_000n, 9_000n);

		expect(result.items).toEqual([7n, 44_999n]);
		const tooWide = requested.filter(([from, to]) => to - from + 1n > 200n);
		expect(tooWide).toHaveLength(1);
		expect(requested).toHaveLength(225);
	});

	it("keeps a newest-first read newest first", async () => {
		const events = [5n, 2_500n, 9_100n];
		const { read } = capped(2_000n, events);
		const newestFirst = async (range: {
			fromBlock: bigint;
			toBlock: bigint;
		}) => {
			const page = await read(range);
			return { ...page, items: [...page.items].reverse() };
		};
		const result = await readForwardPages(
			newestFirst,
			1n,
			10_000n,
			9_000n,
			true,
		);
		expect(result.items).toEqual([9_100n, 2_500n, 5n]);
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
