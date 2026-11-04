import {
	ENTRY_POINT_ADDRESS,
	gianoSmartWalletAbi,
	gianoSmartWalletFactoryAbi,
	isCanonicalEntryPointCode,
	isEntryPointAddress,
	proxyImplementation,
	type ReleaseContractName,
	releaseOf,
} from "@appliedblockchain/giano-contracts";
import {
	getAddress,
	type Hex,
	keccak256,
	type PublicClient,
	zeroAddress,
} from "viem";
import type { ResolvedChain } from "../config.js";

/**
 * Boot-time (and on-demand) verification of one configured chain, per
 * specs/MULTICHAIN_SPECS.md §3.5 and §4.2. Returns a structured result rather than
 * throwing, so the caller decides which failures are fatal (S7):
 *
 * - every failure kind EXCEPT `unreachable` is a structural misconfiguration — the platform admin
 *   pointed at the wrong endpoint, deployed the wrong contracts, or is serving a chain whose
 *   factory diverges — and none of them is fixed by waiting, so they refuse start-up (MC-49,
 *   MC-92);
 * - nothing is compared with a fixed address: a chain's contracts are wherever its configuration
 *   or the contracts registry says. What is checked is that the code there is a release's
 *   (releaseOf, by release fingerprint), and that the immutables the fingerprints mask hold the
 *   chain's own addresses: the factory clones the chain's wallet implementation, and the paymaster
 *   proxy points at paymaster release code. Address identity across chains is the probe check
 *   (MC-22, {@link probeDivergence});
 * - `unreachable` is not fatal: the deployment starts, marks the chain unavailable, serves
 *   its other chains and retries in the background (MC-54).
 */

export type ChainVerificationFailure =
	| { kind: "unreachable"; detail: string } // NOT fatal
	| { kind: "chain-id-mismatch"; declared: number; reported: number }
	| { kind: "entrypoint-missing"; address: `0x${string}` }
	| {
			kind: "entrypoint-not-canonical";
			address: `0x${string}`;
			reason: "address" | "code";
	  }
	| { kind: "factory-missing"; address: `0x${string}` }
	| {
			/** The factory clones a wallet implementation other than the chain's resolved one. */
			kind: "implementation-mismatch";
			expected: `0x${string}`;
			found: `0x${string}`;
	  }
	| {
			/** The code at a contract's address matches no release's fingerprint for that contract. */
			kind: "code-not-release";
			contract: VerifiedContract;
			address: `0x${string}`;
			codehash: `0x${string}`;
	  }
	| {
			/** The wallet implementation is bound to a different EntryPoint than the chain is configured with. */
			kind: "implementation-entrypoint-mismatch";
			implementation: `0x${string}`;
			expected: `0x${string}`;
			found: `0x${string}`;
	  }
	| { kind: "paymaster-missing"; address: `0x${string}` };

/** The contracts verifyChain checks the code of, and the release contract each must be. */
export const VERIFIED_CONTRACTS = {
	factory: "GianoSmartWalletFactory",
	implementation: "GianoSmartWallet",
	paymaster: "ERC1967Proxy",
	"paymaster-implementation": "GianoPaymaster",
} as const satisfies Record<string, ReleaseContractName>;
export type VerifiedContract = keyof typeof VERIFIED_CONTRACTS;

export type ChainVerification = {
	chainId: number;
	reachable: boolean;
	reportedChainId?: number;
	entryPointPresent?: boolean;
	factoryPresent?: boolean;
	/** The release the factory's code matched. */
	factoryRelease?: string;
	/** The wallet implementation the chain's factory clones. */
	implementationAddress?: `0x${string}`;
	/**
	 * True when the chain has no resolved implementation (no `walletApi.implementation`, no
	 * registry entry) to compare the factory's with. Its code and EntryPoint are still checked.
	 */
	implementationUnchecked?: boolean;
	paymasterPresent?: boolean;
	/** The address the chain's own factory derives for the probe owner (MC-22). */
	probeAddress?: `0x${string}`;
	failures: ChainVerificationFailure[];
};

/** True for a failure that must prevent the deployment from serving this chain. */
export function isFatalFailure(failure: ChainVerificationFailure): boolean {
	return failure.kind !== "unreachable";
}

/**
 * A fixed, well-known 64-byte owner blob that is never a real credential, used for the
 * live factory cross-check: every served chain's factory must derive the same address for
 * it (MC-22) — which is what catches a factory at the right address running different code.
 */
export const PROBE_OWNER = `0x${"11".repeat(64)}` as const;

/**
 * Which release `code` is of `contract`, or undefined if none (releaseOf). A parameter only so
 * tests can stand in for code they cannot produce.
 */
export type ReleaseCheck = (
	contract: ReleaseContractName,
	code: Hex,
	address: `0x${string}`,
) => { release: string } | undefined;

export async function verifyChain(
	descriptor: ResolvedChain,
	client: PublicClient,
	releaseCheck: ReleaseCheck = releaseOf,
): Promise<ChainVerification> {
	const result: ChainVerification = {
		chainId: descriptor.chainId,
		reachable: false,
		failures: [],
	};
	/** The release `code` is of `contract`; records code-not-release when it is none. */
	const releaseAt = (
		contract: VerifiedContract,
		address: `0x${string}`,
		code: Hex | undefined,
	): string | undefined => {
		// The address too: a UUPS implementation's masked `__self` must be the address it sits at.
		const match =
			code && code !== "0x"
				? releaseCheck(VERIFIED_CONTRACTS[contract], code, address)
				: undefined;
		if (!match)
			result.failures.push({
				kind: "code-not-release",
				contract,
				address,
				codehash: keccak256(code ?? "0x"),
			});
		return match?.release;
	};

	let reported: number;
	try {
		reported = await client.getChainId();
	} catch (error) {
		result.failures.push({
			kind: "unreachable",
			detail: (error as Error).message,
		});
		return result;
	}
	result.reachable = true;
	result.reportedChainId = reported;

	// MC-49: an endpoint that reports a different chain than declared is the exact failure
	// this work exists to eliminate. Fatal, never warned past.
	if (reported !== descriptor.chainId) {
		result.failures.push({
			kind: "chain-id-mismatch",
			declared: descriptor.chainId,
			reported,
		});
		return result;
	}

	try {
		const [entryPointCode, factoryCode] = await Promise.all([
			client.getCode({ address: descriptor.entryPoint }),
			client.getCode({ address: descriptor.factory }),
		]);

		result.entryPointPresent = !!entryPointCode && entryPointCode !== "0x";
		if (!result.entryPointPresent) {
			result.failures.push({
				kind: "entrypoint-missing",
				address: descriptor.entryPoint,
			});
		} else if (!isEntryPointAddress(descriptor.entryPoint)) {
			// Every hash the relay and the paymaster compute is a v0.9 hash; any other EntryPoint
			// would record useropHashes that never match what lands on chain.
			result.failures.push({
				kind: "entrypoint-not-canonical",
				address: descriptor.entryPoint,
				reason: "address",
			});
		} else if (!isCanonicalEntryPointCode(entryPointCode, descriptor.chainId)) {
			result.failures.push({
				kind: "entrypoint-not-canonical",
				address: descriptor.entryPoint,
				reason: "code",
			});
		}

		result.factoryPresent = !!factoryCode && factoryCode !== "0x";
		if (!result.factoryPresent) {
			result.failures.push({
				kind: "factory-missing",
				address: descriptor.factory,
			});
		}

		if (result.factoryPresent) {
			result.factoryRelease = releaseAt(
				"factory",
				descriptor.factory,
				factoryCode,
			);
		}
		if (result.factoryRelease) {
			const implementation = (await client.readContract({
				address: descriptor.factory,
				abi: gianoSmartWalletFactoryAbi,
				functionName: "implementation",
			})) as `0x${string}`;
			result.implementationAddress = implementation;
			// The factory's implementation is an immutable the fingerprint masks: it must be the chain's
			// own wallet implementation (GIANO_CHAINS walletApi.implementation, else the registry).
			if (!descriptor.implementation) {
				result.implementationUnchecked = true;
			} else if (
				implementation.toLowerCase() !== descriptor.implementation.toLowerCase()
			) {
				result.failures.push({
					kind: "implementation-mismatch",
					expected: descriptor.implementation,
					found: implementation,
				});
			}
			const implementationCode = await client.getCode({
				address: implementation,
			});
			if (releaseAt("implementation", implementation, implementationCode)) {
				// Each release hardcodes its own EntryPoint: an earlier release (v0.7) is release code
				// and still rejects every v0.9 operation. Ask the implementation which one it serves.
				const boundEntryPoint = (await client.readContract({
					address: implementation,
					abi: gianoSmartWalletAbi,
					functionName: "entryPoint",
				})) as `0x${string}`;
				if (
					boundEntryPoint.toLowerCase() !== descriptor.entryPoint.toLowerCase()
				) {
					result.failures.push({
						kind: "implementation-entrypoint-mismatch",
						implementation,
						expected: descriptor.entryPoint,
						found: boundEntryPoint,
					});
				}
			}

			// MC-22: the live cross-check — ask the chain's own factory to derive an address for
			// the probe owner. The caller compares this across chains; the derivation has no
			// chain-dependent term (MC-18), so it must be identical everywhere.
			result.probeAddress = (await client.readContract({
				address: descriptor.factory,
				abi: gianoSmartWalletFactoryAbi,
				functionName: "getAddress",
				args: [[PROBE_OWNER], 0n],
			})) as `0x${string}`;
		}

		if (descriptor.sponsorshipPaymaster) {
			const paymaster = descriptor.sponsorshipPaymaster;
			const paymasterCode = await client.getCode({ address: paymaster });
			result.paymasterPresent = !!paymasterCode && paymasterCode !== "0x";
			if (!result.paymasterPresent) {
				result.failures.push({ kind: "paymaster-missing", address: paymaster });
			} else if (releaseAt("paymaster", paymaster, paymasterCode)) {
				// A stock ERC1967Proxy proves nothing about what it delegates to: the implementation
				// slot must hold paymaster release code.
				// An empty slot delegates to nothing: reported as no release code at the zero address.
				const implementation =
					(await proxyImplementation(client, paymaster)) ?? zeroAddress;
				releaseAt(
					"paymaster-implementation",
					implementation,
					implementation === zeroAddress
						? undefined
						: await client.getCode({ address: implementation }),
				);
			}
		}
	} catch (error) {
		result.failures.push({
			kind: "unreachable",
			detail: (error as Error).message,
		});
	}

	return result;
}

/** One line per failure, naming the chain and what to do about it. */
export function describeFailure(
	chainId: number,
	failure: ChainVerificationFailure,
): string {
	switch (failure.kind) {
		case "unreachable":
			return `chain ${chainId}: endpoint unreachable (${failure.detail}) — will start unavailable and retry`;
		case "chain-id-mismatch":
			return `chain ${chainId}: the RPC endpoint reports chain ${failure.reported}, not ${failure.declared} — the endpoint and the declaration disagree; fix the configuration`;
		case "entrypoint-missing":
			return `chain ${chainId}: no EntryPoint at ${failure.address} — deploy EntryPoint v0.9 at its canonical address before any Giano contract (adoption checklist step 2)`;
		case "entrypoint-not-canonical":
			return failure.reason === "address"
				? `chain ${chainId}: entryPoint ${failure.address} is not EntryPoint v0.9 (${ENTRY_POINT_ADDRESS}) — Giano computes v0.9 operation hashes only; fix the chain's entryPoint configuration`
				: `chain ${chainId}: the code at ${failure.address} is not the canonical EntryPoint v0.9 runtime — do not serve this chain`;
		case "factory-missing":
			return `chain ${chainId}: no account factory at ${failure.address} — deploy the Giano contracts, or fix the chain's factory address (adoption checklist step 4)`;
		case "implementation-mismatch":
			return `chain ${chainId}: the factory clones wallet implementation ${failure.found}, not the chain's registered ${failure.expected} — fix walletApi.implementation or the registry; otherwise the factory is not this deployment's`;
		case "code-not-release":
			return `chain ${chainId}: the ${failure.contract} at ${failure.address} runs code that matches no release's ${VERIFIED_CONTRACTS[failure.contract]} (codehash ${failure.codehash}) — redeploy from a release (MC-19)`;
		case "implementation-entrypoint-mismatch":
			return `chain ${chainId}: implementation ${failure.implementation} is bound to EntryPoint ${failure.found}, not ${failure.expected} — the chain still runs an earlier release; upgrade it before serving`;
		case "paymaster-missing":
			return `chain ${chainId}: sponsorship is configured but there is no paymaster at ${failure.address}`;
	}
}

/**
 * MC-22: every served chain's factory must derive the SAME account for the probe owner. Returns
 * the refusal to log, naming every chain and the address it derived, or null when they agree.
 * Contract addresses may differ per chain; a different derivation may not, and there is no
 * fallback to per-chain wallet addresses (MC-23).
 */
export function probeDivergence(
	probes: ReadonlyMap<number, string>,
): string | null {
	if (new Set([...probes.values()].map((a) => a.toLowerCase())).size <= 1)
		return null;
	const listed = [...probes.entries()]
		.map(([chainId, address]) => `chain ${chainId} → ${address}`)
		.join(", ");
	return `address-identity violation: the served chains derive DIFFERENT account addresses for the same owner (${listed}) (MC-16, MC-22)`;
}

/**
 * Whether a chain coming back after being unavailable completed its verification: reachable, with
 * no failure at all, and with the probe address. An `unreachable` failure is not fatal at boot, but
 * on recovery it means the verification aborted part-way (a timeout on the implementation's code or
 * on the probe), so the structural checks and the MC-22 comparison never ran; such a chain stays
 * unavailable until a later probe completes.
 */
export function recoveryVerified(
	verification: ChainVerification,
): verification is ChainVerification & { probeAddress: `0x${string}` } {
	return (
		verification.reachable &&
		verification.failures.length === 0 &&
		verification.probeAddress !== undefined
	);
}

/**
 * MC-22 for a chain coming back after being unavailable: its probe address must equal the served
 * chains'. Returns the refusal, or null when it may be served. On null the caller records the probe
 * in `served`, so the first chain admitted sets the reference and recoveries that come back together
 * are compared with each other (the check and the update run in one synchronous step).
 */
export function recoveryDivergence(
	served: ReadonlyMap<number, string>,
	chainId: number,
	probeAddress: string,
): string | null {
	return probeDivergence(
		new Map([...served, [chainId, probeAddress.toLowerCase()]]),
	);
}
