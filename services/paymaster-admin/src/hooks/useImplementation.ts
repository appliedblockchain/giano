import type { GianoPaymasterClient } from "@appliedblockchain/giano-paymaster-sdk";
import { useCallback, useEffect, useState } from "react";
import type { Address } from "viem";
import { describeError } from "../lib/format";

/**
 * The implementation behind the paymaster proxy, from the ERC-1967 slot, re-read with every console
 * refresh: an executed upgrade changes it, and nothing else announces that.
 */
export function useImplementation(
	client: GianoPaymasterClient,
	/** A trigger: a new value re-reads. */
	block: bigint | undefined,
) {
	const [implementation, setImplementation] = useState<Address>();
	const [error, setError] = useState<string>();

	const read = useCallback(async () => {
		try {
			setImplementation(await client.getImplementation());
			setError(undefined);
		} catch (cause) {
			setError(describeError(cause));
		}
	}, [client]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `block` is a trigger: re-read with every console refresh
	useEffect(() => {
		void read();
	}, [read, block]);

	return { implementation, error, read };
}
