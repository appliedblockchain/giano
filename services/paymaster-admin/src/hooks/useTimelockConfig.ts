import type { TimelockConfig } from "@appliedblockchain/giano-paymaster-sdk";
import { useCallback, useEffect, useRef, useState } from "react";
import { describeError } from "../lib/format";
import { useConsole } from "../shell/ConsoleContext";

export type TimelockAccess = {
	config: TimelockConfig | undefined;
	/**
	 * Whether the connected wallet may execute a ready operation: executors open, or it holds
	 * EXECUTOR_ROLE. Undefined until that is known.
	 */
	mayExecute: boolean | undefined;
	error: string | undefined;
	reload: () => Promise<void>;
};

/**
 * The timelock's delays and who may execute, read once per timelock and wallet. Not per refresh:
 * changing either is itself a timelocked operation, which the queued markers already show.
 */
export function useTimelockConfig(): TimelockAccess {
	const { timelock, wallet } = useConsole();
	const [config, setConfig] = useState<TimelockConfig>();
	const [executor, setExecutor] = useState<boolean>();
	const [error, setError] = useState<string>();
	// A read for the previous timelock or wallet can land after a newer one: only the latest counts.
	const generation = useRef(0);

	const reload = useCallback(async () => {
		if (!timelock) return;
		const current = ++generation.current;
		// Apart, so a failed role check costs only the role, not the delays.
		const [next, holds] = await Promise.allSettled([
			timelock.getConfig(),
			wallet
				? timelock.hasRole("EXECUTOR_ROLE", wallet.address)
				: Promise.resolve(false),
		]);
		if (generation.current !== current) return;
		if (next.status === "fulfilled") setConfig(next.value);
		setExecutor(holds.status === "fulfilled" ? holds.value : undefined);
		const failed = [next, holds].find(
			(result): result is PromiseRejectedResult => result.status === "rejected",
		);
		setError(failed ? describeError(failed.reason) : undefined);
	}, [timelock, wallet]);

	useEffect(() => {
		setConfig(undefined);
		setExecutor(undefined);
		void reload();
	}, [reload]);

	// Open executors settle it whatever the role check says; otherwise it waits for that check.
	let mayExecute: boolean | undefined;
	if (config?.executorsOpen) mayExecute = true;
	else if (config !== undefined) mayExecute = executor;
	return { config, mayExecute, error, reload };
}
