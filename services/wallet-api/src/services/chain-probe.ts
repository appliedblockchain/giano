import type { FastifyBaseLogger } from "fastify";
import {
	type ChainVerification,
	type ChainVerificationFailure,
	describeFailure,
	isFatalFailure,
	recoveryDivergence,
	recoveryVerified,
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

/**
 * The last reachability probe, every {@link CHAIN_PROBE_INTERVAL_MS} for every chain. `detail` is a
 * fixed category ({@link probeFailureCategory}), never an error's message: viem's messages carry
 * the node's URL, and a provider key in its path with it.
 */
export type ChainProbeRecord = { at: Date; ok: boolean; detail?: string };

/**
 * What kind of failure `error` is, in words that can be shown to anyone: `timeout`, `http 429`,
 * `connection refused`, `rpc error -32000` or `unreachable`. Never the message, which for viem's
 * `HttpRequestError` and `TimeoutError` includes `URL: <the node's URL>` (keys in the path stay).
 */
export function probeFailureCategory(error: unknown): string {
	for (
		let current: unknown = error, depth = 0;
		current && typeof current === "object" && depth < 5;
		current = (current as { cause?: unknown }).cause, depth++
	) {
		const { name, status, code } = current as {
			name?: unknown;
			status?: unknown;
			code?: unknown;
		};
		if (
			name === "TimeoutError" ||
			code === "ETIMEDOUT" ||
			code === "UND_ERR_CONNECT_TIMEOUT"
		)
			return "timeout";
		if (typeof status === "number") return `http ${status}`;
		if (code === "ECONNREFUSED") return "connection refused";
		if (code === "ENOTFOUND" || code === "EAI_AGAIN")
			return "name not resolved";
		if (typeof code === "number") return `rpc error ${code}`;
	}
	return "unreachable";
}

/** A verification's failures as the registry keeps them: `unreachable` with a category, not a message. */
function withoutMessages(
	failures: readonly ChainVerificationFailure[],
): ChainVerificationFailure[] {
	return failures.map((failure) =>
		failure.kind === "unreachable"
			? { kind: "unreachable", detail: "unreachable" }
			: failure,
	);
}

export const CHAIN_PROBE_INTERVAL_MS = 15_000;

/** Keeps a full verification's outcome; a full verification is also a reachability probe. */
export function recordVerification(
	chain: ChainServices,
	verification: ChainVerification,
	at = new Date(),
): void {
	chain.verification = {
		checkedAt: at,
		failures: withoutMessages(verification.failures),
	};
	chain.lastProbe = {
		at,
		ok: verification.reachable,
		...(verification.reachable ? {} : { detail: "unreachable" }),
	};
}

/**
 * One round of the background prober for one chain (MC-54). A ready chain is probed for
 * reachability only: a factory that ceases to match canonical is a page (MC-104), never a silent
 * flip to `unavailable`. An unavailable chain must pass the full structural verification before it
 * is served again: it may have missed the boot-time gate, and an endpoint swapped out during the
 * outage must not slip in unverified. Its probe address must also match the served chains' and
 * the one it was admitted with (MC-22, `servedProbes`). Either way the outcome is recorded on the
 * entry.
 */
export async function probeChain(
	chain: ChainServices,
	options: {
		log: FastifyBaseLogger;
		onStatus: (chain: ChainServices) => void;
		/** The probe address each admitted chain's factory derives (index.ts keeps it). */
		servedProbes?: Map<number, string>;
		verify?: typeof verifyChain;
	},
): Promise<void> {
	const { log, onStatus } = options;
	const servedProbes = options.servedProbes ?? new Map<number, string>();
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
				detail: probeFailureCategory(error),
			};
		}
		onStatus(chain);
		return;
	}
	try {
		const verification = await verify(chain.descriptor, chain.publicClient);
		recordVerification(chain, verification);
		const fatalFailures = verification.failures.filter(isFatalFailure);
		// MC-22 holds for every admission: a chain unreachable at boot never met the boot-time probe
		// comparison, so it meets it here.
		const divergence =
			verification.probeAddress &&
			recoveryDivergence(
				servedProbes,
				chain.chainId,
				verification.probeAddress,
			);
		if (divergence) {
			log.error(
				{
					chainId: chain.chainId,
					probeAddress: verification.probeAddress,
					servedProbes: Object.fromEntries(servedProbes),
				},
				`ALERT: ${divergence} — chain ${chain.chainId} stays unavailable`,
			);
		} else if (recoveryVerified(verification)) {
			servedProbes.set(chain.chainId, verification.probeAddress.toLowerCase());
			log.info(
				{ chainId: chain.chainId },
				"chain is reachable and verified — serving it again",
			);
			chain.status = "ready";
		} else if (fatalFailures.length > 0) {
			for (const failure of fatalFailures)
				log.error(
					{ chainId: chain.chainId, failure },
					`ALERT: ${describeFailure(chain.chainId, failure)}`,
				);
		} else if (verification.reachable) {
			// Reachable, but the verification did not complete: not admitted until one does.
			log.warn(
				{ chainId: chain.chainId, failures: verification.failures },
				"chain answered but its verification did not complete — it stays unavailable",
			);
		}
	} catch (error) {
		chain.lastProbe = {
			at: new Date(),
			ok: false,
			detail: probeFailureCategory(error),
		};
	}
	onStatus(chain);
}
