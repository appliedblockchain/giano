import {
	assessHealth,
	type GianoPaymasterClient,
	type PaymasterOverview,
	type TimelockConfig,
	timelockDelays,
} from "@appliedblockchain/giano-paymaster-sdk";
import { useEffect, useMemo, useRef, useState } from "react";
import { type Address, type Hex, zeroAddress } from "viem";
import type { Deployment } from "../config";
import { describeError } from "../lib/format";
import { type ConsoleHealth, withReads } from "../lib/health";

type Implementation = { address: Address; code: Hex | undefined };

/**
 * The deployment's health: `assessHealth` over the overview on screen, with what an overview
 * cannot say (B2). The timelock comes from the deployment's config and the console's one read of
 * it; the implementation's code is matched to a contracts release.
 *
 * The implementation's address is re-read with every refresh, as an executed upgrade changes it
 * and nothing announces that; its code, the size of a contract, only when the address changes.
 *
 * A check whose input has not been read is `pending`, and one whose read failed is a warning: never
 * left out, so Health cannot say "every check passes" about something it did not check.
 */
export function useHealth({
	client,
	overview,
	block,
	deployment,
	timelockConfig,
	timelockError,
}: {
	client: GianoPaymasterClient | undefined;
	overview: PaymasterOverview | undefined;
	block: bigint | undefined;
	deployment: Deployment;
	timelockConfig: TimelockConfig | undefined;
	timelockError: string | undefined;
}): ConsoleHealth | undefined {
	const [implementation, setImplementation] = useState<Implementation>();
	const [implementationError, setImplementationError] = useState<string>();
	const known = useRef<Address>(undefined);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `client` is a trigger: another deployment's implementation is not this one's
	useEffect(() => {
		known.current = undefined;
		setImplementation(undefined);
		setImplementationError(undefined);
	}, [client]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `block` is a trigger: re-read with every console refresh
	useEffect(() => {
		if (!client) return;
		let live = true;
		void (async () => {
			try {
				// The slot as it is: an empty one is a finding (not a UUPS proxy), not a failed read.
				const address = await client.readImplementationSlot();
				if (address === known.current) {
					if (live) setImplementationError(undefined);
					return;
				}
				const code =
					address === zeroAddress
						? undefined
						: await client.publicClient.getCode({ address });
				if (!live) return;
				known.current = address;
				setImplementation({ address, code });
				setImplementationError(undefined);
			} catch (cause) {
				if (live) setImplementationError(describeError(cause));
			}
		})();
		return () => {
			live = false;
		};
	}, [client, block]);

	return useMemo(() => {
		if (!overview) return undefined;
		const { timelockAddress, timelockDelays: expected } = deployment;
		const report = assessHealth(overview, {
			timelock:
				timelockAddress && timelockConfig
					? {
							address: timelockAddress,
							delays: timelockDelays(timelockConfig),
							expected,
						}
					: undefined,
			implementation,
		});
		return withReads(report, {
			implementationRead: implementation !== undefined,
			implementationError,
			timelockConfigured: timelockAddress !== undefined,
			timelockRead: timelockConfig !== undefined,
			timelockError,
		});
	}, [
		overview,
		deployment,
		timelockConfig,
		timelockError,
		implementation,
		implementationError,
	]);
}
