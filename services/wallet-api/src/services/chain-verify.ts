import { CANONICAL_FACTORY, CANONICAL_IMPLEMENTATION, gianoSmartWalletFactoryAbi } from '@appliedblockchain/giano-contracts';
import type { PublicClient } from 'viem';
import type { ResolvedChain } from '../config.js';

/**
 * Boot-time (and on-demand) verification of one configured chain, per
 * specs/MULTICHAIN_SPECS.md §3.5 and §4.2. Returns a structured result rather than
 * throwing, so the caller decides which failures are fatal (S7):
 *
 * - every failure kind EXCEPT `unreachable` is a structural misconfiguration — the operator
 *   pointed at the wrong endpoint, deployed the wrong contracts, or is serving a chain whose
 *   factory diverges — and none of them is fixed by waiting, so they refuse start-up (MC-49,
 *   MC-92);
 * - `unreachable` is not fatal: the deployment starts, marks the chain unavailable, serves
 *   its other chains and retries in the background (MC-54).
 */

export type ChainVerificationFailure =
  | { kind: 'unreachable'; detail: string } // NOT fatal
  | { kind: 'chain-id-mismatch'; declared: number; reported: number }
  | { kind: 'entrypoint-missing'; address: `0x${string}` }
  | { kind: 'factory-missing'; address: `0x${string}` }
  | { kind: 'factory-not-canonical'; expected: `0x${string}`; found: `0x${string}` }
  | { kind: 'implementation-mismatch'; expected: `0x${string}`; found: `0x${string}` }
  | { kind: 'paymaster-missing'; address: `0x${string}` };

export type ChainVerification = {
  chainId: number;
  reachable: boolean;
  reportedChainId?: number;
  entryPointPresent?: boolean;
  factoryPresent?: boolean;
  factoryAddressCanonical?: boolean;
  implementationAddress?: `0x${string}`;
  paymasterPresent?: boolean;
  /** The address the chain's own factory derives for the probe owner (MC-22). */
  probeAddress?: `0x${string}`;
  failures: ChainVerificationFailure[];
};

/** True for a failure that must prevent the deployment from serving this chain. */
export function isFatalFailure(failure: ChainVerificationFailure): boolean {
  return failure.kind !== 'unreachable';
}

/**
 * A fixed, well-known 64-byte owner blob that is never a real credential, used for the
 * live factory cross-check: every served chain's factory must derive the same address for
 * it (MC-22) — which is what catches a factory at the right address running different code.
 */
export const PROBE_OWNER = `0x${'11'.repeat(64)}` as const;

export async function verifyChain(descriptor: ResolvedChain, client: PublicClient): Promise<ChainVerification> {
  const result: ChainVerification = { chainId: descriptor.chainId, reachable: false, failures: [] };

  let reported: number;
  try {
    reported = await client.getChainId();
  } catch (error) {
    result.failures.push({ kind: 'unreachable', detail: (error as Error).message });
    return result;
  }
  result.reachable = true;
  result.reportedChainId = reported;

  // MC-49: an endpoint that reports a different chain than declared is the exact failure
  // this work exists to eliminate. Fatal, never warned past.
  if (reported !== descriptor.chainId) {
    result.failures.push({ kind: 'chain-id-mismatch', declared: descriptor.chainId, reported });
    return result;
  }

  try {
    const [entryPointCode, factoryCode] = await Promise.all([
      client.getCode({ address: descriptor.entryPoint }),
      client.getCode({ address: descriptor.factory }),
    ]);

    result.entryPointPresent = !!entryPointCode && entryPointCode !== '0x';
    if (!result.entryPointPresent) {
      result.failures.push({ kind: 'entrypoint-missing', address: descriptor.entryPoint });
    }

    result.factoryPresent = !!factoryCode && factoryCode !== '0x';
    if (!result.factoryPresent) {
      result.failures.push({ kind: 'factory-missing', address: descriptor.factory });
    }

    // MC-19: the admission gate. Canonical is the frozen constant exported by the contracts
    // package — never "whatever some reference chain happens to have" (S13).
    result.factoryAddressCanonical = descriptor.factory.toLowerCase() === CANONICAL_FACTORY.toLowerCase();
    if (!result.factoryAddressCanonical) {
      result.failures.push({ kind: 'factory-not-canonical', expected: CANONICAL_FACTORY, found: descriptor.factory });
    }

    if (result.factoryPresent) {
      // The implementation is implied by a matching factory address (it is a constructor
      // argument baked into the factory's creation code), and checked anyway: a cheap direct
      // check beats an implication when the consequence is funds at the wrong address.
      const implementation = (await client.readContract({
        address: descriptor.factory,
        abi: gianoSmartWalletFactoryAbi,
        functionName: 'implementation',
      })) as `0x${string}`;
      result.implementationAddress = implementation;
      if (implementation.toLowerCase() !== CANONICAL_IMPLEMENTATION.toLowerCase()) {
        result.failures.push({ kind: 'implementation-mismatch', expected: CANONICAL_IMPLEMENTATION, found: implementation });
      }

      // MC-22: the live cross-check — ask the chain's own factory to derive an address for
      // the probe owner. The caller compares this across chains; the derivation has no
      // chain-dependent term (MC-18), so it must be identical everywhere.
      result.probeAddress = (await client.readContract({
        address: descriptor.factory,
        abi: gianoSmartWalletFactoryAbi,
        functionName: 'getAddress',
        args: [[PROBE_OWNER], 0n],
      })) as `0x${string}`;
    }

    if (descriptor.sponsorshipPaymaster) {
      const paymasterCode = await client.getCode({ address: descriptor.sponsorshipPaymaster });
      result.paymasterPresent = !!paymasterCode && paymasterCode !== '0x';
      if (!result.paymasterPresent) {
        result.failures.push({ kind: 'paymaster-missing', address: descriptor.sponsorshipPaymaster });
      }
    }
  } catch (error) {
    result.failures.push({ kind: 'unreachable', detail: (error as Error).message });
  }

  return result;
}

/** One line per failure, naming the chain and what to do about it. */
export function describeFailure(chainId: number, failure: ChainVerificationFailure): string {
  switch (failure.kind) {
    case 'unreachable':
      return `chain ${chainId}: endpoint unreachable (${failure.detail}) — will start unavailable and retry`;
    case 'chain-id-mismatch':
      return `chain ${chainId}: the RPC endpoint reports chain ${failure.reported}, not ${failure.declared} — the endpoint and the declaration disagree; fix the configuration`;
    case 'entrypoint-missing':
      return `chain ${chainId}: no EntryPoint at ${failure.address} — deploy EntryPoint v0.7 at its canonical address before any Giano contract (adoption checklist step 2)`;
    case 'factory-missing':
      return `chain ${chainId}: no account factory at ${failure.address} — deploy the canonical contracts (adoption checklist step 4)`;
    case 'factory-not-canonical':
      return `chain ${chainId}: factory ${failure.found} is not the canonical ${failure.expected} — this chain cannot be served without breaking address identity (MC-19)`;
    case 'implementation-mismatch':
      return `chain ${chainId}: implementation ${failure.found} is not the canonical ${failure.expected} — the factory at the canonical address is running a different build`;
    case 'paymaster-missing':
      return `chain ${chainId}: sponsorship is configured but there is no paymaster at ${failure.address}`;
  }
}
