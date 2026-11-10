import type {
	GianoTimelockClient,
	PaymasterPublicClient,
	PaymasterRoleName,
} from "@appliedblockchain/giano-paymaster-sdk";
import {
	createContext,
	type ReactNode,
	useContext,
	useEffect,
	useState,
} from "react";
import type { Address } from "viem";
import type { Deployment } from "../config";
import type { TimelockOperationsState } from "../hooks/usePendingOperations";
import type { TimelockAccess } from "../hooks/useTimelockConfig";
import type { ConnectedWallet } from "../lib/chain";
import type { Propose } from "../lib/proposals";

/**
 * What every write control and every address on the page needs to know about the console around
 * it: the deployment, the wallet and its roles, the timelock and what is queued in it, and the names
 * of addresses. Provided once by the console, so a primitive deep in a tab does not need half a
 * dozen props threaded down to it.
 */
export type ConsoleContextValue = {
	deployment: Deployment;
	wallet: ConnectedWallet | undefined;
	myRoles: readonly PaymasterRoleName[];
	/** The paymaster proxy, once the client has resolved it. */
	paymaster: Address | undefined;
	timelock: GianoTimelockClient | undefined;
	/** Opens the proposal dialog. Undefined without a timelock. */
	propose: Propose | undefined;
	/** The console's refresh: what a write calls once it is mined. */
	refresh: () => Promise<void>;
	/** The block the last refresh read the paymaster at. */
	block: bigint | undefined;
	/**
	 * When the last refresh finished: it changes with every refresh, where `block` stays the same on
	 * an idle chain or a failed head read. What re-reads with each refresh keys on this.
	 */
	lastUpdated: Date | undefined;
	timelockOperations: TimelockOperationsState;
	/** The timelock's delays and what the connected wallet may do on it. */
	timelockAccess: TimelockAccess;
	/** Threshold and owners of each configured Safe, by lowercase address. */
	safes: Readonly<Record<string, SafeInfo>>;
};

const ConsoleContext = createContext<ConsoleContextValue | undefined>(
	undefined,
);

export function ConsoleProvider({
	value,
	children,
}: {
	value: ConsoleContextValue;
	children: ReactNode;
}) {
	return (
		<ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>
	);
}

export function useConsole(): ConsoleContextValue {
	const value = useContext(ConsoleContext);
	if (!value) throw new Error("useConsole outside the console");
	return value;
}

export type SafeInfo =
	| { threshold: bigint; owners: number }
	/** The read failed: the label is shown without a threshold. */
	| { failed: true };

const SAFE_ABI = [
	{
		type: "function",
		name: "getThreshold",
		stateMutability: "view",
		inputs: [],
		outputs: [{ type: "uint256" }],
	},
	{
		type: "function",
		name: "getOwners",
		stateMutability: "view",
		inputs: [],
		outputs: [{ type: "address[]" }],
	},
] as const;

/**
 * Each configured Safe's threshold and owner count, read once per deployment (openspec D9). Once,
 * not per refresh: a Safe's threshold changes by a transaction its owners sign, rarely, and a label
 * a minute stale costs nothing.
 */
export function useSafes(
	deployment: Deployment,
	publicClient: PaymasterPublicClient | undefined,
): Readonly<Record<string, SafeInfo>> {
	const [safes, setSafes] = useState<Record<string, SafeInfo>>({});

	useEffect(() => {
		setSafes({});
		if (!publicClient) return;
		const addresses = Object.entries(deployment.addresses)
			.filter(([, known]) => known.kind === "safe")
			.map(([address]) => address as Address);
		if (addresses.length === 0) return;

		let cancelled = false;
		void Promise.all(
			addresses.map(async (address): Promise<[string, SafeInfo]> => {
				try {
					const [threshold, owners] = await Promise.all([
						publicClient.readContract({
							address,
							abi: SAFE_ABI,
							functionName: "getThreshold",
						}),
						publicClient.readContract({
							address,
							abi: SAFE_ABI,
							functionName: "getOwners",
						}),
					]);
					return [address, { threshold, owners: owners.length }];
				} catch (cause) {
					console.error(
						`[paymaster-admin] Could not read the Safe at ${address}`,
						cause,
					);
					return [address, { failed: true }];
				}
			}),
		).then((entries) => {
			if (!cancelled) setSafes(Object.fromEntries(entries));
		});
		return () => {
			cancelled = true;
		};
	}, [deployment, publicClient]);

	return safes;
}

/**
 * The names the console knows for an address, most specific first: a configured label (with a
 * Safe's threshold), then what it is to this deployment, then whether it is the connected wallet.
 */
export function addressNames(
	address: string,
	context: Pick<
		ConsoleContextValue,
		"deployment" | "wallet" | "paymaster" | "safes"
	>,
): string[] {
	const key = address.toLowerCase();
	const { deployment, wallet, paymaster, safes } = context;
	const names: string[] = [];

	const known = deployment.addresses[key];
	if (known) {
		const safe = safes[key];
		names.push(
			safe && "threshold" in safe
				? `${known.label} · ${safe.threshold} of ${safe.owners}`
				: known.label,
		);
	}
	if (deployment.timelockAddress?.toLowerCase() === key)
		names.push("the timelock");
	if (paymaster?.toLowerCase() === key) names.push("the paymaster");
	if (wallet?.address.toLowerCase() === key) names.push("you");
	return names;
}
