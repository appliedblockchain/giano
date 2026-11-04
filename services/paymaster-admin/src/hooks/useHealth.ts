import {
	assessHealth,
	type GianoPaymasterClient,
	type HealthReport,
	type PaymasterOverview,
	type TimelockConfig,
	timelockDelays,
} from "@appliedblockchain/giano-paymaster-sdk";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Address, Hex } from "viem";
import type { Deployment } from "../config";

/**
 * The deployment's health: `assessHealth` over the overview on screen, with what an overview
 * cannot say (B2). The timelock comes from the deployment's config and the console's one read of
 * it; the implementation's code is matched to a contracts release.
 *
 * The implementation's address is re-read with every refresh, as an executed upgrade changes it
 * and nothing announces that; its code, the size of a contract, only when the address changes.
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
}): HealthReport | undefined {
	const [implementation, setImplementation] = useState<{
		address: Address;
		code: Hex | undefined;
	}>();
	const known = useRef<Address>(undefined);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `client` is a trigger: another deployment's implementation is not this one's
	useEffect(() => {
		known.current = undefined;
		setImplementation(undefined);
	}, [client]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: `block` is a trigger: re-read with every console refresh
	useEffect(() => {
		if (!client) return;
		let live = true;
		void (async () => {
			try {
				const address = await client.getImplementation();
				if (address === known.current) return;
				const code = await client.publicClient.getCode({ address });
				if (!live) return;
				known.current = address;
				setImplementation({ address, code });
			} catch {
				// The Overview's configuration card reports a failed read; Health keeps what it had.
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
		// A configured timelock not read yet is not "no timelock": until it is, there is no verdict.
		if (!timelockAddress || timelockConfig) return report;
		const checks = report.checks.filter((check) => check.id !== "timelock");
		if (timelockError)
			checks.push({
				id: "timelock-read",
				level: "warn",
				label: "could not read the timelock",
				detail: timelockError,
				remedy:
					"The timelocked roles and delays are not checked until it is read. Reload it on the Timelock tab.",
			});
		const level = checks.some((check) => check.level === "fail")
			? "fail"
			: checks.some((check) => check.level === "warn")
				? "warn"
				: "ok";
		return { level, checks };
	}, [overview, deployment, timelockConfig, timelockError, implementation]);
}
