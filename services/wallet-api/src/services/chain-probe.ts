import type { FastifyBaseLogger } from "fastify";
import {
	type ChainVerification,
	type ChainVerificationFailure,
	describeFailure,
	isFatalFailure,
	verifyChain,
} from "./chain-verify.js";
import type { ChainServices } from "./chains.js";

/**
 * What the prober found, kept on each chain's registry entry (specs/PLATFORM-ADMIN-SPECS.md §10.2,
 * B3), so `GET /v1/platform/chains` can say when a chain was last checked and what the checks said,
 * rather than only the verdict. Deployment state the registry already holds, not tenant state.
 */

/** The last full verification: at boot, or when a chain came back. */
export type ChainVerificationRecord = {
	checkedAt: Date;
	failures: ChainVerificationFailure[];
};

/** The last reachability probe, every {@link CHAIN_PROBE_INTERVAL_MS} for every chain. */
export type ChainProbeRecord = { at: Date; ok: boolean; detail?: string };

export const CHAIN_PROBE_INTERVAL_MS = 15_000;

/** Keeps a full verification's outcome; a full verification is also a reachability probe. */
export function recordVerification(
	chain: ChainServices,
	verification: ChainVerification,
	at = new Date(),
): void {
	chain.verification = { checkedAt: at, failures: verification.failures };
	chain.lastProbe = {
		at,
		ok: verification.reachable,
		...(verification.reachable
			? {}
			: {
					detail: verification.failures.find(
						(failure) => failure.kind === "unreachable",
					)?.detail,
				}),
	};
}

/**
 * One round of the background prober for one chain (MC-54). A ready chain is probed for
 * reachability only: a factory that ceases to match canonical is a page (MC-104), never a silent
 * flip to `unavailable`. An unavailable chain must pass the full structural verification before it
 * is served again: it may have missed the boot-time gate, and an endpoint swapped out during the
 * outage must not slip in unverified. Either way the outcome is recorded on the entry.
 */
export async function probeChain(
	chain: ChainServices,
	options: {
		log: FastifyBaseLogger;
		onStatus: (chain: ChainServices) => void;
		verify?: typeof verifyChain;
	},
): Promise<void> {
	const { log, onStatus } = options;
	const verify = options.verify ?? verifyChain;
	if (chain.status === "ready") {
		try {
			const reported = await chain.publicClient.getChainId();
			if (reported !== chain.chainId) {
				log.error(
					{ chainId: chain.chainId, reported },
					"ALERT: chain endpoint reports a different chain id than declared",
				);
				chain.status = "unavailable";
				chain.lastProbe = {
					at: new Date(),
					ok: false,
					detail: `the endpoint reports chain ${reported}`,
				};
			} else chain.lastProbe = { at: new Date(), ok: true };
		} catch (error) {
			log.warn(
				{ chainId: chain.chainId, error: (error as Error).message },
				"chain became unreachable",
			);
			chain.status = "unavailable";
			chain.lastProbe = {
				at: new Date(),
				ok: false,
				detail: (error as Error).message,
			};
		}
		onStatus(chain);
		return;
	}
	try {
		const verification = await verify(chain.descriptor, chain.publicClient);
		recordVerification(chain, verification);
		const fatalFailures = verification.failures.filter(isFatalFailure);
		if (verification.reachable && fatalFailures.length === 0) {
			log.info(
				{ chainId: chain.chainId },
				"chain is reachable and verified — serving it again",
			);
			chain.status = "ready";
		} else if (verification.reachable) {
			for (const failure of fatalFailures)
				log.error(
					{ chainId: chain.chainId, failure },
					`ALERT: ${describeFailure(chain.chainId, failure)}`,
				);
		}
	} catch (error) {
		chain.lastProbe = {
			at: new Date(),
			ok: false,
			detail: (error as Error).message,
		};
	}
	onStatus(chain);
}
