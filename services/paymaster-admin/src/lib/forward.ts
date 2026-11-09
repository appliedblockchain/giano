import {
	type BlockRange,
	DEFAULT_LOG_WINDOW,
	type Page,
} from "@appliedblockchain/giano-paymaster-sdk";

/**
 * Every block from `fromBlock` to `head`, read forward a window at a time, items oldest first.
 *
 * One request for the whole gap (a laptop asleep overnight is some 18,000 blocks on Base Sepolia)
 * is refused by a capped node or by wallet-api's relay. The SDK then narrows it to its newest
 * blocks (`readWindow`), and the older part would never be read. So the gap is read a window at a
 * time, and where a node narrows a window, what it left out is read next with the narrower span.
 * `read` returns a window's items oldest first, as the SDK's log reads do.
 */
export async function readForwardPages<T>(
	read: (range: BlockRange) => Promise<Page & { items: readonly T[] }>,
	fromBlock: bigint,
	head: bigint,
	window: bigint = DEFAULT_LOG_WINDOW,
): Promise<{ fromBlock: bigint; toBlock: bigint; items: T[] }> {
	const items: T[] = [];
	let width = window;
	for (let start = fromBlock; start <= head; ) {
		const end = start + width - 1n < head ? start + width - 1n : head;
		const pieces: (readonly T[])[] = [];
		for (let to = end; to >= start; ) {
			const page = await read({ fromBlock: start, toBlock: to });
			pieces.unshift(page.items);
			if (page.fromBlock <= start) break;
			// Narrowed to the newest blocks: keep the span the node accepts, and read the rest.
			width = page.toBlock - page.fromBlock + 1n;
			to = page.fromBlock - 1n;
		}
		for (const piece of pieces) items.push(...piece);
		start = end + 1n;
	}
	return { fromBlock, toBlock: head, items };
}
