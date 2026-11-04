import type {
	GianoTimelockClient,
	TimelockConfig,
} from "@appliedblockchain/giano-paymaster-sdk";
import { useCallback, useEffect, useState } from "react";
import type { ConnectedWallet } from "../lib/chain";
import { describeError } from "../lib/format";

export type TimelockAccess = {
	config: TimelockConfig | undefined;
	/** The connected wallet holds PROPOSER_ROLE: it can schedule (and, as OpenZeppelin grants both, cancel). */
	mayPropose: boolean;
	/** The connected wallet holds CANCELLER_ROLE. */
	mayCancel: boolean;
	/** Executors are open, or the connected wallet holds EXECUTOR_ROLE. */
	mayExecute: boolean;
	/** The longest delay any timelocked function waits: how far back the operations list must read. */
	longestDelay: bigint | undefined;
	error: string | undefined;
	reload: () => Promise<void>;
};

/**
 * The timelock's delays and what the connected wallet may do on it, read once per timelock and
 * wallet for the whole console. Not per refresh: changing either is itself a timelocked operation,
 * which the queued markers already show; Reload re-reads after one executes.
 */
export function useTimelockAccess(
	timelock: GianoTimelockClient | undefined,
	wallet: ConnectedWallet | undefined,
): TimelockAccess {
	const [config, setConfig] = useState<TimelockConfig>();
	const [held, setHeld] = useState({
		propose: false,
		cancel: false,
		execute: false,
	});
	const [error, setError] = useState<string>();

	const reload = useCallback(async () => {
		if (!timelock) return;
		try {
			const no = Promise.resolve(false);
			const [next, propose, cancel, execute] = await Promise.all([
				timelock.getConfig(),
				wallet ? timelock.hasRole("PROPOSER_ROLE", wallet.address) : no,
				wallet ? timelock.hasRole("CANCELLER_ROLE", wallet.address) : no,
				wallet ? timelock.hasRole("EXECUTOR_ROLE", wallet.address) : no,
			]);
			setConfig(next);
			setHeld({ propose, cancel, execute });
			setError(undefined);
		} catch (cause) {
			setError(describeError(cause));
		}
	}, [timelock, wallet]);

	useEffect(() => {
		setConfig(undefined);
		setHeld({ propose: false, cancel: false, execute: false });
		void reload();
	}, [reload]);

	const longestDelay = config
		? config.functions.reduce(
				(longest, entry) =>
					entry.effectiveDelay > longest ? entry.effectiveDelay : longest,
				config.minDelay,
			)
		: undefined;

	return {
		config,
		mayPropose: held.propose,
		mayCancel: held.cancel,
		mayExecute: config !== undefined && (config.executorsOpen || held.execute),
		longestDelay,
		error,
		reload,
	};
}
