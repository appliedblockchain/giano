import type { BlockRange, Page } from "@appliedblockchain/giano-paymaster-sdk";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { describeError } from "../lib/format";

type Window<T> = BlockRange & { items: readonly T[] };

/**
 * A log read a window of blocks at a time, newest first (openspec K6, G5, D12).
 *
 * The first read is the window ending at the head; `lookFurther` adds the one before it, with no
 * cap on rows; and each change of `trigger` (a console refresh) reads only the blocks since the
 * newest one read, keeping every older window already loaded. `read` returns a window's items
 * newest first; a new `read` (another client, another timelock) starts again.
 */
export function useWindows<T>(
	read: (
		range?: Partial<BlockRange>,
	) => Promise<Page & { items: readonly T[] }>,
	trigger: unknown,
) {
	const [windows, setWindows] = useState<readonly Window<T>[]>([]);
	const [older, setOlder] = useState<BlockRange>();
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string>();
	const [settled, setSettled] = useState(false);
	const newest = useRef<bigint | undefined>(undefined);
	/** The read in flight, so a refresh of the same source waits for it and another's does not. */
	const running = useRef<typeof read | undefined>(undefined);
	const current = useRef(read);

	const refresh = useCallback(async () => {
		if (running.current === read) return;
		running.current = read;
		setLoading(true);
		try {
			const from = newest.current;
			const page = await read(
				from === undefined ? undefined : { fromBlock: from + 1n },
			);
			if (current.current !== read) return;
			const window = {
				fromBlock: page.fromBlock,
				toBlock: page.toBlock,
				items: page.items,
			};
			if (from === undefined) {
				setWindows([window]);
				setOlder(page.older);
			} else if (page.toBlock > from) {
				setWindows((loaded) => [window, ...loaded]);
			}
			if (from === undefined || page.toBlock > from)
				newest.current = page.toBlock;
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
		setOlder(undefined);
		setSettled(false);
		setError(undefined);
	}, [read]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `trigger` is a trigger: read the new blocks with every console refresh
	useEffect(() => {
		void refresh();
	}, [refresh, trigger]);

	const lookFurther = useCallback(async () => {
		if (!older) return;
		setLoading(true);
		try {
			const page = await read(older);
			setWindows((loaded) => [
				...loaded,
				{ fromBlock: page.fromBlock, toBlock: page.toBlock, items: page.items },
			]);
			setOlder(page.older);
			setError(undefined);
		} catch (cause) {
			setError(describeError(cause));
		} finally {
			setLoading(false);
		}
	}, [read, older]);

	const items = useMemo(
		() => windows.flatMap((window) => window.items),
		[windows],
	);
	const range =
		windows.length > 0
			? {
					fromBlock: windows[windows.length - 1].fromBlock,
					toBlock: windows[0].toBlock,
				}
			: undefined;

	return {
		windows,
		items,
		range,
		older,
		loading,
		error,
		settled,
		refresh,
		lookFurther,
	};
}
