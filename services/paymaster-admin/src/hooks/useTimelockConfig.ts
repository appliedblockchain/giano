import type { TimelockConfig } from "@appliedblockchain/giano-paymaster-sdk";
import { useCallback, useEffect, useState } from "react";
import { describeError } from "../lib/format";
import { useConsole } from "../shell/ConsoleContext";

export type TimelockAccess = {
	config: TimelockConfig | undefined;
	/** Whether the connected wallet may execute a ready operation: executors open, or it holds EXECUTOR_ROLE. */
	mayExecute: boolean;
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
	const [executor, setExecutor] = useState(false);
	const [error, setError] = useState<string>();

	const reload = useCallback(async () => {
		if (!timelock) return;
		try {
			const [next, holds] = await Promise.all([
				timelock.getConfig(),
				wallet ? timelock.hasRole("EXECUTOR_ROLE", wallet.address) : false,
			]);
			setConfig(next);
			setExecutor(holds);
			setError(undefined);
		} catch (cause) {
			setError(describeError(cause));
		}
	}, [timelock, wallet]);

	useEffect(() => {
		setConfig(undefined);
		void reload();
	}, [reload]);

	return {
		config,
		mayExecute: config !== undefined && (config.executorsOpen || executor),
		error,
		reload,
	};
}
