import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import type { Address, Hex, PublicClient } from 'viem';
import { encodeAbiParameters, encodeFunctionData, size, slice } from 'viem';
import { ownerFingerprint } from './fingerprint';

/**
 * On-chain owner-set enumeration (WM-01, WM-02, D1: the chain IS the owner set — the
 * credential registry is a cache joined on owner bytes, never authority).
 */

export type OwnerKind = 'passkey' | 'address';

export type OnChainOwner = {
  /** The storage index — needed for removal, but NEVER used for matching (WM-02). */
  index: number;
  /** The owner's canonical on-chain encoding: what owners are matched by. */
  ownerBytes: Hex;
  kind: OwnerKind;
  /** Present for kind 'address'. */
  address?: Address;
  /** Present for kind 'passkey'. */
  publicKey?: { x: Hex; y: Hex };
  /** Stable human-comparable identifier derived from the owner bytes (WM-03). */
  fingerprint: string;
};

export type OwnerSet = {
  /** The account has code on this chain; without it there is no owner set to read. */
  deployed: boolean;
  owners: OnChainOwner[];
};

/** The 64-byte on-chain encoding of a P-256 public-key owner: abi.encode(x, y). */
export function publicKeyOwnerBytes(x: Hex, y: Hex): Hex {
  return encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }], [x, y]);
}

/** The 32-byte on-chain encoding of an Ethereum-address owner: abi.encode(address). */
export function addressOwnerBytes(address: Address): Hex {
  return encodeAbiParameters([{ type: 'address' }], [address]);
}

export function classifyOwnerBytes(index: number, ownerBytes: Hex): OnChainOwner {
  const bytes = size(ownerBytes);
  if (bytes === 64) {
    return {
      index,
      ownerBytes,
      kind: 'passkey',
      publicKey: { x: slice(ownerBytes, 0, 32), y: slice(ownerBytes, 32, 64) },
      fingerprint: ownerFingerprint(ownerBytes),
    };
  }
  if (bytes === 32) {
    return {
      index,
      ownerBytes,
      kind: 'address',
      address: slice(ownerBytes, 12, 32) as Address,
      fingerprint: ownerFingerprint(ownerBytes),
    };
  }
  // The contract admits only the two encodings; anything else would be a contract change.
  return { index, ownerBytes, kind: 'address', fingerprint: ownerFingerprint(ownerBytes) };
}

/**
 * Reads the owner set from the account contract on ONE chain.
 *
 * Walks to `nextOwnerIndex` and skips removed indices — indices are never reused, so
 * enumeration must tolerate holes (WM-02). Throws when the chain cannot be read: the
 * caller must render that as its own state, never as an empty set (WM-05).
 */
export async function readOwnerSet(client: PublicClient, wallet: Address): Promise<OwnerSet> {
  const code = await client.getCode({ address: wallet });
  if (!code || code === '0x') {
    return { deployed: false, owners: [] };
  }
  const nextOwnerIndex = await client.readContract({
    address: wallet,
    abi: gianoSmartWalletAbi,
    functionName: 'nextOwnerIndex',
  });
  const reads = await Promise.all(
    Array.from({ length: Number(nextOwnerIndex) }, (_, index) =>
      client.readContract({ address: wallet, abi: gianoSmartWalletAbi, functionName: 'ownerAtIndex', args: [BigInt(index)] }),
    ),
  );
  const owners = reads
    .map((ownerBytes, index) => ({ ownerBytes: ownerBytes as Hex, index }))
    .filter(({ ownerBytes }) => ownerBytes && ownerBytes !== '0x')
    .map(({ ownerBytes, index }) => classifyOwnerBytes(index, ownerBytes));
  return { deployed: true, owners };
}

/** True when two chains' owner sets differ — surfaced as a problem, not a list (WM-06, MC-37). */
export function ownerSetsDiverge(a: OwnerSet, b: OwnerSet): boolean {
  if (!a.deployed || !b.deployed) return false; // an undeployed chain has no set to diverge
  const key = (set: OwnerSet) => set.owners.map((owner) => owner.ownerBytes.toLowerCase()).sort().join(',');
  return key(a) !== key(b);
}

// ── The self-calls an owner change is made of (D4: an ordinary consented UserOperation) ──

export function encodeAddOwnerPublicKey(x: Hex, y: Hex): Hex {
  return encodeFunctionData({ abi: gianoSmartWalletAbi, functionName: 'addOwnerPublicKey', args: [x, y] });
}

export function encodeAddOwnerAddress(owner: Address): Hex {
  return encodeFunctionData({ abi: gianoSmartWalletAbi, functionName: 'addOwnerAddress', args: [owner] });
}

/**
 * Removal names both the index AND the exact owner bytes — the contract reverts with
 * `WrongOwnerAtIndex` if they disagree, so the index must be read from the chain
 * immediately before constructing the operation (WM-29).
 */
export function encodeRemoveOwnerAtIndex(index: number, ownerBytes: Hex): Hex {
  return encodeFunctionData({ abi: gianoSmartWalletAbi, functionName: 'removeOwnerAtIndex', args: [BigInt(index), ownerBytes] });
}
