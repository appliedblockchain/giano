import { decodeFunctionData, encodeAbiParameters, pad } from 'viem';
import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import { describe, expect, it } from 'vitest';
import {
  addressOwnerBytes,
  classifyOwnerBytes,
  encodeAddOwnerAddress,
  encodeAddOwnerPublicKey,
  encodeRemoveOwnerAtIndex,
  ownerFingerprint,
  ownerSetsDiverge,
  publicKeyOwnerBytes,
  type OwnerSet,
} from '../src/management';

const X = pad('0x11', { size: 32 });
const Y = pad('0x22', { size: 32 });
const EOA = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266' as const;

describe('owner bytes', () => {
  it('encodes a public-key owner exactly as the contract does (abi.encode(x, y))', () => {
    expect(publicKeyOwnerBytes(X, Y)).toBe(encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }], [X, Y]));
  });

  it('classifies 64-byte owners as passkeys and 32-byte owners as addresses', () => {
    const passkey = classifyOwnerBytes(0, publicKeyOwnerBytes(X, Y));
    expect(passkey.kind).toBe('passkey');
    expect(passkey.publicKey).toEqual({ x: X, y: Y });

    const address = classifyOwnerBytes(1, addressOwnerBytes(EOA));
    expect(address.kind).toBe('address');
    expect(address.address?.toLowerCase()).toBe(EOA.toLowerCase());
  });
});

describe('fingerprint (WM-03, WM-20)', () => {
  it('is stable, short, and derived from the owner bytes alone', () => {
    const fingerprint = ownerFingerprint(publicKeyOwnerBytes(X, Y));
    expect(fingerprint).toMatch(/^[0-9A-Z]{3}-[0-9A-Z]{3}$/);
    expect(ownerFingerprint(publicKeyOwnerBytes(X, Y))).toBe(fingerprint);
    // never contains the confusable characters
    expect(fingerprint).not.toMatch(/[ILOU]/);
  });

  it('differs between two keys — a substituted key cannot share the displayed fingerprint', () => {
    const a = ownerFingerprint(publicKeyOwnerBytes(X, Y));
    const b = ownerFingerprint(publicKeyOwnerBytes(Y, X));
    expect(a).not.toBe(b);
  });
});

describe('management calldata (D4)', () => {
  it('encodes addOwnerPublicKey / addOwnerAddress / removeOwnerAtIndex against the wallet ABI', () => {
    const add = decodeFunctionData({ abi: gianoSmartWalletAbi, data: encodeAddOwnerPublicKey(X, Y) });
    expect(add.functionName).toBe('addOwnerPublicKey');
    expect(add.args).toEqual([X, Y]);

    const addAddress = decodeFunctionData({ abi: gianoSmartWalletAbi, data: encodeAddOwnerAddress(EOA) });
    expect(addAddress.functionName).toBe('addOwnerAddress');

    const remove = decodeFunctionData({ abi: gianoSmartWalletAbi, data: encodeRemoveOwnerAtIndex(3, publicKeyOwnerBytes(X, Y)) });
    expect(remove.functionName).toBe('removeOwnerAtIndex');
    expect(remove.args?.[0]).toBe(3n);
  });
});

describe('divergence (WM-06)', () => {
  const set = (owners: `0x${string}`[], deployed = true): OwnerSet => ({
    deployed,
    owners: owners.map((ownerBytes, index) => classifyOwnerBytes(index, ownerBytes)),
  });

  it('flags owner sets that differ between deployed chains, ignoring order and index', () => {
    const one = publicKeyOwnerBytes(X, Y);
    const two = addressOwnerBytes(EOA);
    expect(ownerSetsDiverge(set([one, two]), set([two, one]))).toBe(false);
    expect(ownerSetsDiverge(set([one]), set([one, two]))).toBe(true);
    // an undeployed chain has no set to diverge — deployment is lazy and per chain
    expect(ownerSetsDiverge(set([one]), set([], false))).toBe(false);
  });
});
