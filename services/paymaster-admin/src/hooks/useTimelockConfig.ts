import type {
	GianoTimelockClient,
	TimelockConfig,
} from "@appliedblockchain/giano-paymaster-sdk";
import { useCallback, useEffect, useRef, useState } from "react";
import type { ConnectedWallet } from "../lib/chain";
import { describeError } from "../lib/format";

export type TimelockAccess = {
	config: TimelockConfig | undefined;
	/** The connected wallet holds PROPOSER_ROLE: it can schedule (and, as OpenZeppelin grants both, cancel). */
	mayPropose: boolean;
	/** The connected wallet holds CANCELLER_ROLE. */
	mayCancel: boolean;
	/**
	 * Executors are open, or the connected wallet holds EXECUTOR_ROLE. Undefined until that is known,
	 * so a control can say the executors are unread rather than that they are closed.
	 */
	mayExecute: boolean | undefined;
	/** The longest delay any timelocked function waits: how far back the operations list must read. */
	longestDelay: bigint | undefined;
	error: string | undefined;
	/** The last config read failed: `config`, if any, is from an earlier read. */
	configError: string | undefined;
	reload: () => Promise<void>;
};

type Held = {
	propose: boolean | undefined;
	cancel: boolean | undefined;
	execute: boolean | undefined;
};
const UNKNOWN: Held = {
	propose: undefined,
	cancel: undefined,
	execute: undefined,
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
	const [held, setHeld] = useState<Held>(UNKNOWN);
	const [error, setError] = useState<string>();
	const [configError, setConfigError] = useState<string>();
	// A read for the previous timelock or wallet can land after a newer one: only the latest counts.
	const generation = useRef(0);

	const reload = useCallback(async () => {
		if (!timelock) return;
		const current = ++generation.current;
		const holds = (
			role: "PROPOSER_ROLE" | "CANCELLER_ROLE" | "EXECUTOR_ROLE",
		) =>
			wallet ? timelock.hasRole(role, wallet.address) : Promise.resolve(false);
		// Apart, so a failed role check costs only that role, not the delays.
		const results = await Promise.allSettled([
			timelock.getConfig(),
			holds("PROPOSER_ROLE"),
			holds("CANCELLER_ROLE"),
			holds("EXECUTOR_ROLE"),
		] as const);
		if (generation.current !== current) return;
		const [next, propose, cancel, execute] = results;
		if (next.status === "fulfilled") setConfig(next.value);
		setConfigError(
			next.status === "rejected" ? describeError(next.reason) : undefined,
		);
		const value = (result: PromiseSettledResult<boolean>) =>
			result.status === "fulfilled" ? result.value : undefined;
		setHeld({
			propose: value(propose),
			cancel: value(cancel),
			execute: value(execute),
		});
		const failed = results.find(
			(result): result is PromiseRejectedResult => result.status === "rejected",
		);
		setError(failed ? describeError(failed.reason) : undefined);
	}, [timelock, wallet]);

	useEffect(() => {
		setConfig(undefined);
		setConfigError(undefined);
		setHeld(UNKNOWN);
		void reload();
	}, [reload]);

	const longestDelay = config
		? config.functions.reduce(
				(longest, entry) =>
					entry.effectiveDelay > longest ? entry.effectiveDelay : longest,
				config.minDelay,
			)
		: undefined;

	// Open executors settle it whatever the role check says; otherwise it waits for that check.
	let mayExecute: boolean | undefined;
	if (config?.executorsOpen) mayExecute = true;
	else if (config !== undefined) mayExecute = held.execute;

	return {
		config,
		mayPropose: held.propose === true,
		mayCancel: held.cancel === true,
		mayExecute,
		longestDelay,
		error,
		configError,
		reload,
	};
}
