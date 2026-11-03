import type { BlockRange, Page } from "@appliedblockchain/giano-paymaster-sdk";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { describeError } from "../lib/format";
import { readForwardPages } from "../lib/forward";

type Window<T> = BlockRange & { items: readonly T[] };

/**
 * A log read a window of blocks at a time, newest first (openspec K6, G5, D12).
 *
 * The first read is the window ending at the head; `lookFurther` adds the one before it, with no
 * cap on rows; and each change of `trigger` (a console refresh) reads every block since the newest
 * one read, keeping every older window already loaded. `read` returns a window's items newest
 * first; a new `read` (another client, another timelock) starts again.
 *
 * A refresh after a long gap (a laptop asleep overnight) asks for everything since the last block;
 * where a node or wallet-api's relay narrows that to its newest blocks, the rest is read forward a
 * window at a time (readForwardPages), so the gap is read whole. Windows with nothing in them are
 * not kept: the range read is tracked apart. "Look further back" has its own loading and error, so
 * a poll neither clears nor hides them, and reads one older window at a time.
 */
export function useWindows<T>(
	read: (
		range?: Partial<BlockRange>,
	) => Promise<Page & { items: readonly T[] }>,
	trigger: unknown,
) {
	const [windows, setWindows] = useState<readonly Window<T>[]>([]);
	const [range, setRange] = useState<BlockRange>();
	const [older, setOlder] = useState<BlockRange>();
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string>();
	const [settled, setSettled] = useState(false);
	const [olderLoading, setOlderLoading] = useState(false);
	const [olderError, setOlderError] = useState<string>();
	const newest = useRef<bigint | undefined>(undefined);
	/** The read in flight, so a refresh of the same source waits for it and another's does not. */
	const running = useRef<typeof read | undefined>(undefined);
	const readingOlder = useRef(false);
	const current = useRef(read);

	const refresh = useCallback(async () => {
		if (running.current === read) return;
		running.current = read;
		setLoading(true);
		try {
			const from = newest.current;
			if (from === undefined) {
				const page = await read();
				if (current.current !== read) return;
				setWindows(
					page.items.length > 0
						? [
								{
									fromBlock: page.fromBlock,
									toBlock: page.toBlock,
									items: page.items,
								},
							]
						: [],
				);
				setRange({ fromBlock: page.fromBlock, toBlock: page.toBlock });
				setOlder(page.older);
				newest.current = page.toBlock;
			} else {
				const latest = await read({ fromBlock: from + 1n });
				// Narrowed: the node read only the newest blocks of the gap. Read the rest, forward.
				const gap =
					latest.fromBlock > from + 1n
						? await readForwardPages(
								(window) => read(window),
								from + 1n,
								latest.fromBlock - 1n,
								latest.toBlock - latest.fromBlock + 1n,
								true,
							)
						: undefined;
				if (current.current !== read) return;
				if (latest.toBlock > from) {
					const items = [...latest.items, ...(gap?.items ?? [])];
					if (items.length > 0)
						setWindows((loaded) => [
							{ fromBlock: from + 1n, toBlock: latest.toBlock, items },
							...loaded,
						]);
					setRange((known) => known && { ...known, toBlock: latest.toBlock });
					newest.current = latest.toBlock;
				}
			}
			setError(undefined);
		} catch (cause) {
			if (current.current === read) setError(describeError(cause));
		} finally {
			if (running.current === read) running.current = undefined;
			if (current.current === read) {
				setLoading(false);
				setSettled(true);
			}
		}
	}, [read]);

	useEffect(() => {
		if (current.current === read) return;
		current.current = read;
		newest.current = undefined;
		setWindows([]);
		setRange(undefined);
		setOlder(undefined);
		setSettled(false);
		setError(undefined);
		setOlderError(undefined);
	}, [read]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `trigger` is a trigger: read the new blocks with every console refresh
	useEffect(() => {
		void refresh();
	}, [refresh, trigger]);

	const lookFurther = useCallback(async () => {
		if (!older || readingOlder.current) return;
		readingOlder.current = true;
		setOlderLoading(true);
		try {
			const page = await read(older);
			if (current.current !== read) return;
			if (page.items.length > 0)
				setWindows((loaded) =>
					loaded.some((window) => window.fromBlock === page.fromBlock)
						? loaded
						: [
								...loaded,
								{
									fromBlock: page.fromBlock,
									toBlock: page.toBlock,
									items: page.items,
								},
							],
				);
			setRange((known) => known && { ...known, fromBlock: page.fromBlock });
			setOlder(page.older);
			setOlderError(undefined);
		} catch (cause) {
			if (current.current === read) setOlderError(describeError(cause));
		} finally {
			readingOlder.current = false;
			setOlderLoading(false);
		}
	}, [read, older]);

	const items = useMemo(
		() => windows.flatMap((window) => window.items),
		[windows],
	);

	return {
		windows,
		items,
		range,
		older,
		loading,
		error,
		settled,
		olderLoading,
		olderError,
		refresh,
		lookFurther,
	};
}
