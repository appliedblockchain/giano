import type {
	GianoTimelockClient,
	TimelockOperation,
} from "@appliedblockchain/giano-paymaster-sdk";
import { useCallback, useEffect, useMemo, useState } from "react";
import { describeError } from "../lib/format";
import { type QueuedChange, queuedChanges } from "../lib/queued";

/** Windows of blocks the first read goes back; "Look further back" doubles it. */
export const INITIAL_WINDOWS = 5;

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
	reload: () => Promise<void>;
	lookFurther: () => void;
};

/**
 * The timelock's operations, read once per console refresh and shared (openspec N7).
 *
 * The status line, the Timelock tab's count, the queued markers on every tab and the Overview all
 * ask the same question; one read answers them all, so none of them can disagree about what is
 * queued. Nothing is read without a timelock.
 */
export function usePendingOperations(
	timelock: GianoTimelockClient | undefined,
	/** Bumped by every console refresh; a new value re-reads. */
	lastUpdated: Date | undefined,
): TimelockOperationsState {
	const [operations, setOperations] = useState<readonly TimelockOperation[]>(
		[],
	);
	const [range, setRange] = useState<TimelockOperationsState["range"]>();
	const [windows, setWindows] = useState(INITIAL_WINDOWS);
	const [hasOlder, setHasOlder] = useState(false);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string>();
	const [settled, setSettled] = useState(false);

	// A different timelock is a different list: nothing read from the last one carries over.
	// biome-ignore lint/correctness/useExhaustiveDependencies: `timelock` is a trigger: a new one resets what was read
	useEffect(() => {
		setOperations([]);
		setRange(undefined);
		setWindows(INITIAL_WINDOWS);
		setHasOlder(false);
		setError(undefined);
		setSettled(false);
	}, [timelock]);

	const reload = useCallback(async () => {
		if (!timelock) return;
		setLoading(true);
		try {
			const page = await timelock.getOperations({ windows });
			setOperations(page.operations);
			setRange({ fromBlock: page.fromBlock, toBlock: page.toBlock });
			setHasOlder(page.older !== undefined);
			setError(undefined);
		} catch (cause) {
			setError(describeError(cause));
			console.error("[paymaster-admin] Could not read the timelock", cause);
		} finally {
			setLoading(false);
			setSettled(true);
		}
	}, [timelock, windows]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `lastUpdated` is a trigger: every console refresh re-reads the timelock too
	useEffect(() => {
		void reload();
	}, [reload, lastUpdated]);

	const pending = useMemo(
		() =>
			operations.filter(
				(operation) =>
					operation.state === "waiting" || operation.state === "ready",
			),
		[operations],
	);
	const changes = useMemo(() => queuedChanges(pending), [pending]);
	// Doubling, so an operation scheduled long ago is reached in a few reads rather than dozens.
	const lookFurther = useCallback(() => setWindows((count) => count * 2), []);

	return {
		operations,
		pending,
		changes,
		range,
		hasOlder,
		loading,
		error,
		settled,
		reload,
		lookFurther,
	};
}
