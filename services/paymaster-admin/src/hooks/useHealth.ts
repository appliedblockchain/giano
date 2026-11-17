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

/** `source: "logs"`: read from the proxy's Upgraded logs, which Health reports as a warning. */
type Implementation = {
	address: Address;
	code: Hex | undefined;
	source: "slot" | "logs";
};

/**
 * The deployment's health: `assessHealth` over the overview on screen, with what an overview
 * cannot say (B2). The timelock comes from the deployment's config and the console's one read of
 * it; the implementation's code is matched to a contracts release.
 *
 * The implementation's address is re-read with every refresh, as an executed upgrade changes it
 * and nothing announces that; its code, the size of a contract, only when the address changes. An
 * address read from the proxy's Upgraded logs, on an RPC that refuses eth_getStorageAt, is not
 * verified: the implementation check is then a warning, not a pass.
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
	timelockConfigError,
}: {
	client: GianoPaymasterClient | undefined;
	overview: PaymasterOverview | undefined;
	block: bigint | undefined;
	deployment: Deployment;
	timelockConfig: TimelockConfig | undefined;
	timelockError: string | undefined;
	/** The last config read failed (useTimelockAccess's configError). */
	timelockConfigError?: string;
}): ConsoleHealth | undefined {
	const [implementation, setImplementation] = useState<Implementation>();
	const [implementationError, setImplementationError] = useState<string>();
	const known = useRef<{ address: Address; source: "slot" | "logs" }>(
		undefined,
	);

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
				const { address, source } = await client.readImplementationWithSource();
				if (
					address === known.current?.address &&
					source === known.current.source
				) {
					if (live) setImplementationError(undefined);
					return;
				}
				const code =
					address === zeroAddress
						? undefined
						: await client.publicClient.getCode({ address });
				if (!live) return;
				known.current = { address, source };
				setImplementation({ address, code, source });
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
			timelockStaleError: timelockConfigError,
		});
	}, [
		timelockConfigError,
		overview,
		deployment,
		timelockConfig,
		timelockError,
		implementation,
		implementationError,
	]);
}
