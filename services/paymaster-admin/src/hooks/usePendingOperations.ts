import {
	DEFAULT_LOG_WINDOW,
	type GianoTimelockClient,
	type TimelockOperation,
} from "@appliedblockchain/giano-paymaster-sdk";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { describeError } from "../lib/format";
import { type QueuedChange, queuedChanges } from "../lib/queued";

/** Windows of blocks the first read goes back when the timelock's delays are not known. */
export const INITIAL_WINDOWS = 5;

/** The most windows a first read takes, whatever the delays: a slow chain would otherwise ask for hundreds. */
const MAX_WINDOWS = 40;

export type TimelockOperationsState = {
	/** Every operation in the blocks read, newest first. */
	operations: readonly TimelockOperation[];
	/** Those waiting or ready. */
	pending: readonly TimelockOperation[];
	/** What the pending operations will change, for the markers where each change lands. */
	changes: readonly QueuedChange[];
	range: { fromBlock: bigint; toBlock: bigint } | undefined;
	hasOlder: boolean;
	loading: boolean;
	/** Set when the last read failed; what the one before it found stays. */
	error: string | undefined;
	/** True once a read has finished, either way. */
	settled: boolean;
	/**
	 * True once a read has succeeded. Until then `pending` is empty because nothing was read, not
	 * because nothing is queued, so no count may be shown from it.
	 */
	read: boolean;
	reload: () => Promise<void>;
	lookFurther: () => Promise<void>;
};

/**
 * The timelock's operations, read once per console refresh and shared (openspec N7, K5).
 *
 * The first read goes back far enough to cover the longest delay, so anything still waiting has its
 * scheduling in the blocks read. After that each refresh reads only the blocks since the last one,
 * merges what they say into what is known, and re-reads the state of whatever is still pending —
 * rather than re-reading every window on every poll.
 */
export function usePendingOperations(
	timelock: GianoTimelockClient | undefined,
	/** Bumped by every console refresh; a new value reads the new blocks. */
	lastUpdated: Date | undefined,
	/**
	 * The longest delay the timelock enforces: sizes the first read, which waits for it. `null` when
	 * it could not be read, and the first read goes back a fixed number of windows instead.
	 */
	longestDelay: bigint | null | undefined,
): TimelockOperationsState {
	const [operations, setOperations] = useState<readonly TimelockOperation[]>(
		[],
	);
	const [range, setRange] = useState<TimelockOperationsState["range"]>();
	const [older, setOlder] = useState<{ fromBlock: bigint; toBlock: bigint }>();
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string>();
	const [settled, setSettled] = useState(false);
	const [read, setRead] = useState(false);
	/** What has been read, for the next read to start from, without re-creating `reload` on each change. */
	const known = useRef<{
		operations: readonly TimelockOperation[];
		toBlock?: bigint;
	}>({ operations: [] });
	const running = useRef(false);
	/** The read in flight, poll or "Look further back", so the other waits for it rather than racing. */
	const inflight = useRef<Promise<void>>(Promise.resolve());
	/**
	 * Bumped whenever the timelock changes. A read started for an earlier one finishes into nothing:
	 * without it, a read still in flight when the client was rebuilt (connecting a wallet rebuilds it)
	 * would publish into the state just reset, and block the new client's first read.
	 */
	const generation = useRef(0);

	// A different timelock is a different list: nothing read from the last one carries over.
	// biome-ignore lint/correctness/useExhaustiveDependencies: `timelock` is a trigger: a new one resets what was read
	useEffect(() => {
		generation.current += 1;
		running.current = false;
		known.current = { operations: [] };
		setOperations([]);
		setRange(undefined);
		setOlder(undefined);
		setError(undefined);
		setSettled(false);
		setRead(false);
	}, [timelock]);

	const publish = useCallback((next: readonly TimelockOperation[]) => {
		const sorted = [...next].sort((a, b) => Number(latest(b) - latest(a)));
		known.current.operations = sorted;
		setOperations(sorted);
	}, []);

	const reload = useCallback(async () => {
		if (!timelock || running.current) return;
		if (known.current.toBlock === undefined && longestDelay === undefined)
			return;
		running.current = true;
		const run = generation.current;
		const stale = () => run !== generation.current;
		setLoading(true);
		let done = () => {};
		inflight.current = new Promise((resolve) => {
			done = resolve;
		});
		try {
			const from = known.current.toBlock;
			if (from === undefined) {
				const windows = await firstReadWindows(timelock, longestDelay);
				const page = await timelock.getOperations({ windows });
				if (stale()) return;
				publish(page.operations);
				known.current.toBlock = page.toBlock;
				setRange({ fromBlock: page.fromBlock, toBlock: page.toBlock });
				setOlder(page.older);
			} else {
				// Every block since the last read, a window at a time. One request from there to the head
				// would be narrowed by a capped node to its newest blocks, and the rest never read.
				const page = await readForward(timelock, from + 1n);
				const merged = merge(known.current.operations, page.operations);
				// What the new blocks did not mention may still have moved on: waiting becomes ready
				// with time alone, and the contract, not the logs, says so.
				// Those the new blocks mentioned were read with their state just now.
				const fresh = new Set(page.operations.map((operation) => operation.id));
				const refreshed = await Promise.all(
					merged.map(async (operation) => {
						if (
							fresh.has(operation.id) ||
							(operation.state !== "waiting" && operation.state !== "ready")
						)
							return operation;
						const state = await timelock.getOperationState(operation.id);
						return state === operation.state
							? operation
							: { ...operation, state };
					}),
				);
				if (stale()) return;
				publish(refreshed);
				if (page.toBlock >= from) {
					known.current.toBlock = page.toBlock;
					setRange(
						(current) => current && { ...current, toBlock: page.toBlock },
					);
				}
			}
			setError(undefined);
			setRead(true);
		} catch (cause) {
			if (stale()) return;
			setError(describeError(cause));
			console.error("[paymaster-admin] Could not read the timelock", cause);
		} finally {
			done();
			if (!stale()) {
				running.current = false;
				setLoading(false);
				setSettled(true);
			}
		}
	}, [timelock, longestDelay, publish]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `lastUpdated` is a trigger: every console refresh reads the new blocks
	useEffect(() => {
		void reload();
	}, [reload, lastUpdated]);

	/** One more window, older than anything read: what is found there is merged in, never re-read. */
	const lookFurther = useCallback(async () => {
		if (!timelock || !older) return;
		const run = generation.current;
		// A poll in flight merges from its own copy of what is known and would publish over this
		// window's operations: wait for it, and hold the next one off until this is merged.
		while (running.current) await inflight.current;
		if (run !== generation.current) return;
		running.current = true;
		let done = () => {};
		inflight.current = new Promise((resolve) => {
			done = resolve;
		});
		setLoading(true);
		try {
			const page = await timelock.getOperations({ range: older });
			if (run !== generation.current) return;
			publish(merge(page.operations, known.current.operations));
			setRange(
				(current) => current && { ...current, fromBlock: page.fromBlock },
			);
			setOlder(page.older);
			setError(undefined);
		} catch (cause) {
			if (run === generation.current) setError(describeError(cause));
		} finally {
			done();
			if (run === generation.current) {
				running.current = false;
				setLoading(false);
			}
		}
	}, [timelock, older, publish]);

	const pending = useMemo(
		() =>
			operations.filter(
				(operation) =>
					operation.state === "waiting" || operation.state === "ready",
			),
		[operations],
	);
	const changes = useMemo(() => queuedChanges(pending), [pending]);

	return {
		operations,
		pending,
		changes,
		range,
		hasOlder: older !== undefined,
		loading,
		error,
		settled,
		read,
		reload,
		lookFurther,
	};
}

/**
 * The operations in every block from `fromBlock` to the head, read forward a window at a time.
 *
 * A node that refuses a window's span narrows it to its newest blocks (`readWindow`), so each window
 * is read until its first block is covered: what the narrowed read skipped is read next, with the
 * narrower span. The result covers every block in between, oldest window merged first.
 */
export async function readForward(
	timelock: Pick<GianoTimelockClient, "getOperations" | "publicClient">,
	fromBlock: bigint,
): Promise<{ toBlock: bigint; operations: TimelockOperation[] }> {
	const head = await timelock.publicClient.getBlockNumber();
	let operations: TimelockOperation[] = [];
	let width = DEFAULT_LOG_WINDOW;
	for (let start = fromBlock; start <= head; ) {
		const end = start + width - 1n < head ? start + width - 1n : head;
		const pages: (readonly TimelockOperation[])[] = [];
		for (let to = end; to >= start; ) {
			const page = await timelock.getOperations({
				range: { fromBlock: start, toBlock: to },
			});
			pages.unshift(page.operations);
			if (page.fromBlock <= start) break;
			// Narrowed: keep the span the node accepts, and read what it left out.
			width = page.toBlock - page.fromBlock + 1n;
			to = page.fromBlock - 1n;
		}
		for (const found of pages) operations = merge(operations, found);
		start = end + 1n;
	}
	return { toBlock: head, operations };
}

/**
 * Enough windows to reach back past the longest delay, so a pending operation's scheduling is in the
 * blocks read: the delay over the chain's recent seconds per block, in windows, plus one. Never
 * fewer than {@link INITIAL_WINDOWS}: an operation that became ready long ago and was never
 * executed, or one scheduled with more than the minimum delay, is older than the delay alone.
 */
async function firstReadWindows(
	timelock: GianoTimelockClient,
	longestDelay: bigint | null | undefined,
): Promise<number> {
	if (longestDelay === undefined || longestDelay === null)
		return INITIAL_WINDOWS;
	const client = timelock.publicClient;
	const head = await client.getBlock();
	const span = head.number > 1000n ? 1000n : head.number;
	if (span === 0n) return 1;
	const earlier = await client.getBlock({ blockNumber: head.number - span });
	const secondsPerBlock = Math.max(
		Number(head.timestamp - earlier.timestamp) / Number(span),
		0.1,
	);
	const blocks = Number(longestDelay) / secondsPerBlock;
	return Math.min(
		Math.max(
			Math.ceil(blocks / Number(DEFAULT_LOG_WINDOW)) + 1,
			INITIAL_WINDOWS,
		),
		MAX_WINDOWS,
	);
}

/**
 * Folds what `newer` logs say into `known`. An operation already known keeps the calls, salt and
 * scheduling it was read with; the newer read brings its state and whatever happened to it since.
 */
export function merge(
	known: readonly TimelockOperation[],
	newer: readonly TimelockOperation[],
): TimelockOperation[] {
	const byId = new Map(known.map((operation) => [operation.id, operation]));
	for (const update of newer) {
		const existing = byId.get(update.id);
		if (!existing) {
			byId.set(update.id, update);
			continue;
		}
		// A cancelled operation scheduled again (same calls, salt and predecessor, so the same id) is a
		// new scheduling: it keeps nothing of the cancelled one, not its cancel nor who proposed it.
		const rescheduled =
			existing.cancelledBlock !== undefined &&
			update.scheduledBlock !== undefined &&
			update.scheduledBlock > existing.cancelledBlock;
		if (rescheduled) {
			byId.set(update.id, update);
			continue;
		}
		const base = existing.complete || !update.complete ? existing : update;
		byId.set(update.id, {
			...base,
			state: update.state,
			readyAt: update.readyAt ?? base.readyAt,
			executedBlock: update.executedBlock ?? base.executedBlock,
			executedTransaction:
				update.executedTransaction ?? base.executedTransaction,
			cancelledBlock: update.cancelledBlock ?? base.cancelledBlock,
			cancelledTransaction:
				update.cancelledTransaction ?? base.cancelledTransaction,
		});
	}
	return [...byId.values()];
}

function latest(operation: TimelockOperation): bigint {
	return (
		operation.cancelledBlock ??
		operation.executedBlock ??
		operation.scheduledBlock ??
		0n
	);
}
