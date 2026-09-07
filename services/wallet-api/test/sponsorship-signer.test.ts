import type { Address, Hex } from 'viem';
import { keccak256, recoverTypedDataAddress, size, slice } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { describe, expect, it } from 'vitest';
import {
  PAYMASTER_DATA_VERSION,
  encodePaymasterData,
  encodeStubPaymasterData,
  tenantIdToBytes16,
} from '../src/services/paymaster-contract.js';
import {
  AUTHORISATION_TYPES,
  authorisationDomain,
  createLocalSponsorshipSigner,
  toTypedDataMessage,
  type AuthorisationPayload,
} from '../src/services/sponsorship-signer.js';
import { packUints } from '../src/services/sponsorship-service.js';

const KEY = '0x0000000000000000000000000000000000000000000000000000000000005160' as Hex;
const PAYMASTER = '0x15a2075f2407427C5dd0BDe9d1966c48BD70E2f2' as Address;
const SENDER = '0x1111111111111111111111111111111111111234' as Address;
const TENANT_UUID = '11111111-2222-3333-4444-555555555555';

const payload: AuthorisationPayload = {
  chainId: 31337,
  paymaster: PAYMASTER,
  sender: SENDER,
  nonce: 7n,
  callData: '0xdeadbeef',
  accountGasLimits: packUints(500_000n, 200_000n),
  preVerificationGas: 50_000n,
  gasFees: packUints(1_000_000_000n, 2_000_000_000n),
  paymasterVerificationGasLimit: 150_000n,
  paymasterPostOpGasLimit: 100_000n,
  tenantId: tenantIdToBytes16(TENANT_UUID),
  validUntil: 1_800_000_000,
  validAfter: 0,
  feeWei: 100_000_000_000_000n,
};

describe('tenant id', () => {
  // The contract keys on a 16-byte id, and `tenants.id` is already immutable, unique and never
  // reused — so it is used directly rather than introducing a second identifier to keep in step.
  it('is the tenant UUID with its dashes removed', () => {
    expect(tenantIdToBytes16(TENANT_UUID)).toBe('0x11111111222233334444555555555555');
    expect(size(tenantIdToBytes16(TENANT_UUID))).toBe(16);
  });

  it('refuses anything that is not a UUID', () => {
    expect(() => tenantIdToBytes16('alpha')).toThrow();
    expect(() => tenantIdToBytes16('0x1234')).toThrow();
  });
});

describe('paymasterData layout', () => {
  const signature = `0x${'ab'.repeat(65)}` as Hex;
  const signerAddress = privateKeyToAccount(KEY).address;
  const encoded = encodePaymasterData({
    tenantId: tenantIdToBytes16(TENANT_UUID),
    validUntil: payload.validUntil,
    validAfter: payload.validAfter,
    feeWei: payload.feeWei,
    signer: signerAddress,
    signature,
  });

  // These offsets are the contract's OFFSET_* constants. A mismatch here is the single most
  // likely place for a cross-language bug, and on chain it would surface as BadPaymasterData.
  it('places every field at the offset the contract reads it from', () => {
    expect(slice(encoded, 0, 1)).toBe('0x01');
    expect(PAYMASTER_DATA_VERSION).toBe(1);
    expect(slice(encoded, 1, 17)).toBe('0x11111111222233334444555555555555');
    expect(BigInt(slice(encoded, 17, 23))).toBe(BigInt(payload.validUntil));
    expect(BigInt(slice(encoded, 23, 29))).toBe(0n);
    expect(BigInt(slice(encoded, 29, 45))).toBe(payload.feeWei);
    expect(slice(encoded, 45, 65).toLowerCase()).toBe(signerAddress.toLowerCase());
    expect(slice(encoded, 65)).toBe(signature);
  });

  it("is exactly 130 bytes for an ECDSA signature — the contract's minimum length", () => {
    expect(size(encoded)).toBe(130);
  });

  // Gas estimation runs against the stub, so a stub shorter than the real thing would produce a
  // preVerificationGas too low for the operation that eventually lands.
  it('produces a stub of the same length as a real authorisation', () => {
    const stub = encodeStubPaymasterData({
      tenantId: tenantIdToBytes16(TENANT_UUID),
      validUntil: payload.validUntil,
      validAfter: payload.validAfter,
      feeWei: payload.feeWei,
      signer: signerAddress,
    });
    expect(size(stub)).toBe(size(encoded));
    expect(slice(stub, 65)).toBe(`0x${'00'.repeat(65)}`);
  });
});

describe('the local signer', () => {
  const signer = createLocalSponsorshipSigner(KEY, 'test-key');

  it('reports the address the contract must have in its signer set', async () => {
    expect(await signer.address()).toBe(privateKeyToAccount(KEY).address);
  });

  it('signs the EIP-712 authorisation so it recovers to that address', async () => {
    const signature = await signer.signAuthorisation(payload);
    const recovered = await recoverTypedDataAddress({
      domain: authorisationDomain(payload.chainId, payload.paymaster),
      types: AUTHORISATION_TYPES,
      primaryType: 'SponsorshipAuthorisation',
      message: toTypedDataMessage(payload, keccak256(payload.callData)),
      signature,
    });
    expect(recovered).toBe(await signer.address());
  });

  it('produces a 65-byte signature, which is what the layout budgets for', async () => {
    expect(size(await signer.signAuthorisation(payload))).toBe(65);
  });

  describe('what the signature binds', () => {
    // Each of these is something the user controls, so anything the backend does not sign is
    // something the user could otherwise choose freely.
    const cases: Array<[string, Partial<AuthorisationPayload>]> = [
      ['the chain', { chainId: 1 }],
      ['the paymaster address', { paymaster: '0x2222222222222222222222222222222222222222' as Address }],
      ['the sender', { sender: '0x3333333333333333333333333333333333333333' as Address }],
      ['the nonce', { nonce: 8n }],
      ['the calldata', { callData: '0xbeefdead' }],
      ['the gas limits', { accountGasLimits: packUints(500_001n, 200_000n) }],
      ['the fees', { gasFees: packUints(1_000_000_000n, 3_000_000_000n) }],
      ['the paymaster gas limits', { paymasterPostOpGasLimit: 100_001n }],
      ['the tenant that pays', { tenantId: tenantIdToBytes16('99999999-2222-3333-4444-555555555555') }],
      ['the validity window', { validUntil: 1_800_000_001 }],
      ['the fee charged', { feeWei: 1n }],
    ];

    it.each(cases)('binds %s', async (_label, change) => {
      const original = await signer.signAuthorisation(payload);
      const altered = await signer.signAuthorisation({ ...payload, ...change });
      expect(altered).not.toBe(original);
    });
  });

  it('reports itself healthy', async () => {
    expect(await signer.health()).toBe('ok');
  });
});

describe('packUints', () => {
  it('packs two 128-bit values the way the EntryPoint does', () => {
    expect(packUints(1n, 2n)).toBe(`0x${'0'.repeat(31)}1${'0'.repeat(31)}2`);
    expect(size(packUints(0n, 0n))).toBe(32);
  });
});
