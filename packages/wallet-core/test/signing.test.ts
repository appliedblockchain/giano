import { decodeAbiParameters, hashTypedData, parseGwei, size, slice } from 'viem';
import { describe, expect, it } from 'vitest';
import { toReplaySafeTypedData, wrapSignature } from '../src/account/toGianoSmartAccount';
import { resolveUserOpFees } from '../src/provider';

const ADDRESS = '0x1111111111111111111111111111111111111234' as const;
const HASH = `0x${'ab'.repeat(32)}` as const;

describe('toReplaySafeTypedData', () => {
  it('binds the wallet address, chain id and message hash', () => {
    const typedData = toReplaySafeTypedData({ address: ADDRESS, chainId: 84532, hash: HASH });
    expect(typedData.domain).toEqual({
      chainId: 84532,
      name: 'Giano Smart Wallet',
      verifyingContract: ADDRESS,
      version: '1',
    });
    expect(typedData.message.hash).toBe(HASH);
    expect(typedData.primaryType).toBe('GianoSmartWalletMessage');
  });

  it('produces chain- and wallet-distinct digests (replay safety)', () => {
    const digest = (chainId: number, address: `0x${string}`) => hashTypedData(toReplaySafeTypedData({ address, chainId, hash: HASH }));
    expect(digest(1, ADDRESS)).not.toBe(digest(84532, ADDRESS));
    expect(digest(1, ADDRESS)).not.toBe(digest(1, '0x2222222222222222222222222222222222222222'));
  });
});

describe('wrapSignature', () => {
  const OWNER_BYTES = `0x${'11'.repeat(32)}${'22'.repeat(32)}` as const; // 64-byte x||y

  const decode = (wrapped: `0x${string}`) =>
    decodeAbiParameters(
      [{ components: [{ name: 'ownerBytes', type: 'bytes' }, { name: 'signatureData', type: 'bytes' }], type: 'tuple' }],
      wrapped,
    )[0];

  it('passes non-65-byte signatures (WebAuthn envelopes) through unchanged', () => {
    const webauthnSig = `0x${'cd'.repeat(100)}` as const;
    const decoded = decode(wrapSignature({ ownerBytes: OWNER_BYTES, signature: webauthnSig }));
    expect(decoded.ownerBytes).toBe(OWNER_BYTES);
    expect(decoded.signatureData).toBe(webauthnSig);
  });

  it('re-packs 65-byte ECDSA signatures with v ∈ {27,28}', () => {
    const r = `0x${'aa'.repeat(32)}`;
    const s = `0x${'bb'.repeat(32)}`;
    const sig65 = `0x${r.slice(2)}${s.slice(2)}00` as const; // yParity 0
    const decoded = decode(wrapSignature({ ownerBytes: OWNER_BYTES, signature: sig65 }));
    expect(size(decoded.signatureData)).toBe(65);
    expect(slice(decoded.signatureData, 0, 32)).toBe(r);
    expect(slice(decoded.signatureData, 32, 64)).toBe(s);
    expect(Number(slice(decoded.signatureData, 64, 65))).toBe(27);
  });
});

describe('resolveUserOpFees (userop prep)', () => {
  const fallback = { maxFeePerGas: parseGwei('200'), maxPriorityFeePerGas: parseGwei('2') };

  it('prefers explicit request fees, then bundler-prepared, then fallback', () => {
    expect(resolveUserOpFees({ maxFeePerGas: 5n, maxPriorityFeePerGas: 3n }, { maxFeePerGas: 9n }, fallback)).toEqual({
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 3n,
    });
    expect(resolveUserOpFees({}, { maxFeePerGas: 9n, maxPriorityFeePerGas: 4n }, fallback)).toEqual({
      maxFeePerGas: 9n,
      maxPriorityFeePerGas: 4n,
    });
    expect(resolveUserOpFees({}, {}, fallback)).toEqual(fallback);
  });

  it('fallback defaults are not inverted (regression: priority 400 gwei > max 200 gwei)', () => {
    const fees = resolveUserOpFees({}, {}, fallback);
    expect(fees.maxPriorityFeePerGas <= fees.maxFeePerGas).toBe(true);
  });
});
