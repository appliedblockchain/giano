import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_CREDENTIAL_MEDIATION_REQUIREMENT,
  DEFAULT_RESIDENT_KEY_REQUIREMENT,
  DEFAULT_USER_VERIFICATION_REQUIREMENT,
  assertCredentialInfo,
  assertDecodedUserId,
  assertHex,
  assertHexAddress,
  assertHexHash,
  assertNonEmptyBufferSource,
  assertXYVector,
  createWalletApiInjection,
  isBufferSource,
  isGianoProviderInjection,
  isNonEmptyBufferSource,
  type GianoProviderInjection,
} from '../src/provider-injection';
import { assertBaseCredentialInfo } from '../src/provider-injection/types/credential-info/base-credential-info';
import { assertCredentialMediationRequirement } from '../src/provider-injection/types/credential-info/credential-mediation-requirement';
import { assertResidentKeyRequirement } from '../src/provider-injection/types/credential-info/resident-key-requirement';
import { assertUserVerificationRequirement } from '../src/provider-injection/types/credential-info/user-verification-requirement';
import { getHexAssertionLength, getHexAssertionLengthMessage } from '../src/provider-injection/types/hex/length';
import { withValidation } from '../src/provider-injection/_with-validation';
import {
  fromBase64Url,
  serializeAuthenticationCredential,
  serializeRegistrationCredential,
  serializeUserOperation,
  toBase64Url,
} from '../src/provider-injection/wallet-api/serialization';
import { MockAuthenticator, installWebAuthnMock, type InstalledWebAuthnMock } from './webauthn-mock';
import { createMockInjection, FACTORY_ADDRESS } from './helpers';

const HEX32 = `0x${'ab'.repeat(32)}` as const;
const ADDR = '0x000000000000000000000000000000000000abcd' as const;

// ---------------------------------------------------------------------------
// hex assertions
// ---------------------------------------------------------------------------

describe('hex assertions', () => {
  it('assertHex accepts valid hex and enforces length', () => {
    expect(() => assertHex('0xabcd')).not.toThrow();
    expect(() => assertHex(HEX32, { bytes: 32 })).not.toThrow();
    expect(() => assertHex('0xabcd', { digits: 4 })).not.toThrow();
    expect(() => assertHex('0xabcd', { bytes: 32, descriptor: 'thing' })).toThrow(/thing must be a valid 32-byte hex/);
    expect(() => assertHex('nothex')).toThrow(/valid hex/);
    expect(() => assertHex(123)).toThrow();
  });

  it('assertHexAddress and assertHexHash enforce 20/32 bytes', () => {
    expect(() => assertHexAddress(ADDR)).not.toThrow();
    expect(() => assertHexAddress(HEX32)).toThrow();
    expect(() => assertHexHash(HEX32)).not.toThrow();
    expect(() => assertHexHash(ADDR)).toThrow();
  });

  it('getHexAssertionLength handles digits, bytes, none and bad input', () => {
    expect(getHexAssertionLength({ digits: 8 })).toEqual({ digits: 8, originalUnit: 'digit' });
    expect(getHexAssertionLength({ bytes: 4 })).toEqual({ digits: 8, originalUnit: 'byte' });
    expect(getHexAssertionLength({})).toBeUndefined();
    expect(() => getHexAssertionLength({ digits: 'x' as never })).toThrow(/digits.*number/);
    expect(() => getHexAssertionLength({ bytes: 'x' as never })).toThrow(/bytes.*number/);
  });

  it('getHexAssertionLengthMessage formats units', () => {
    expect(getHexAssertionLengthMessage(undefined)).toBe('hex');
    expect(getHexAssertionLengthMessage({ digits: 8, originalUnit: 'digit' })).toBe('8-digit hex');
    expect(getHexAssertionLengthMessage({ digits: 8, originalUnit: 'byte' })).toBe('4-byte hex');
  });
});

// ---------------------------------------------------------------------------
// buffer source
// ---------------------------------------------------------------------------

describe('BufferSource guards', () => {
  it('recognises typed arrays, ArrayBuffer and DataView', () => {
    expect(isBufferSource(new Uint8Array(1))).toBe(true);
    expect(isBufferSource(new ArrayBuffer(1))).toBe(true);
    expect(isBufferSource(new DataView(new ArrayBuffer(1)))).toBe(true);
    expect(isBufferSource(new Float64Array(1))).toBe(true);
    expect(isBufferSource('nope')).toBe(false);
  });

  it('distinguishes empty from non-empty', () => {
    expect(isNonEmptyBufferSource(new Uint8Array(0))).toBe(false);
    expect(isNonEmptyBufferSource(new Uint8Array(1))).toBe(true);
    expect(() => assertNonEmptyBufferSource(new Uint8Array(0), { descriptor: 'challenge' })).toThrow(/challenge.*non-empty BufferSource/);
    expect(() => assertNonEmptyBufferSource('x')).toThrow(/non-empty BufferSource/);
  });
});

// ---------------------------------------------------------------------------
// xy vector + decoded user id
// ---------------------------------------------------------------------------

describe('assertXYVector', () => {
  it('requires two 32-byte hex coordinates', () => {
    expect(() => assertXYVector({ x: HEX32, y: HEX32 })).not.toThrow();
    expect(() => assertXYVector(null)).toThrow(/must be an object/);
    expect(() => assertXYVector({ x: '0x00', y: HEX32 })).toThrow(/X-coordinate/);
  });
});

describe('assertDecodedUserId', () => {
  // No chainId field: the handle is chain-independent by design (MC-78).
  const valid = { userId: 'abc', walletFactoryAddress: ADDR, chainType: 0 };
  it('accepts a well-formed decoded id', () => {
    expect(() => assertDecodedUserId(valid)).not.toThrow();
  });
  it('rejects malformed ids', () => {
    expect(() => assertDecodedUserId(null)).toThrow(/must be an object/);
    expect(() => assertDecodedUserId({ ...valid, userId: '' })).toThrow(/userId/);
    expect(() => assertDecodedUserId({ ...valid, walletFactoryAddress: '0x00' })).toThrow(/walletFactoryAddress/);
    expect(() => assertDecodedUserId({ ...valid, chainType: 99 })).toThrow(/chainType/);
  });
});

// ---------------------------------------------------------------------------
// credential info requirements
// ---------------------------------------------------------------------------

describe('requirement literals', () => {
  it('validate mediation / resident-key / user-verification enums', () => {
    expect(() => assertCredentialMediationRequirement('silent')).not.toThrow();
    expect(() => assertCredentialMediationRequirement('bogus')).toThrow(/Credential Mediation/);
    expect(() => assertCredentialMediationRequirement('bogus', { descriptor: 'm' })).toThrow(/^m must be/);
    expect(() => assertResidentKeyRequirement('preferred')).not.toThrow();
    expect(() => assertResidentKeyRequirement('bogus')).toThrow(/Resident Key/);
    expect(() => assertUserVerificationRequirement('required')).not.toThrow();
    expect(() => assertUserVerificationRequirement('bogus')).toThrow(/User Verification/);
  });

  it('exposes sane defaults', () => {
    expect(DEFAULT_CREDENTIAL_MEDIATION_REQUIREMENT).toBe('optional');
    expect(DEFAULT_RESIDENT_KEY_REQUIREMENT).toBe('preferred');
    expect(DEFAULT_USER_VERIFICATION_REQUIREMENT).toBe('required');
  });
});

describe('assertBaseCredentialInfo / assertCredentialInfo', () => {
  const challenge = new Uint8Array([1, 2, 3]);
  it('validates the base shape', () => {
    expect(() => assertBaseCredentialInfo({ challenge })).not.toThrow();
    expect(() => assertBaseCredentialInfo({ challenge, userVerification: 'required', mediation: 'silent' })).not.toThrow();
    expect(() => assertBaseCredentialInfo(null)).toThrow(/must be an object/);
    expect(() => assertBaseCredentialInfo({ challenge, userVerification: 'bad' })).toThrow();
    expect(() => assertBaseCredentialInfo({ challenge, mediation: 'bad' })).toThrow();
    expect(() => assertBaseCredentialInfo({})).toThrow(/challenge/);
  });

  it('validates every credentialId variant', () => {
    expect(() => assertCredentialInfo({ challenge, credentialId: null })).not.toThrow();
    expect(() => assertCredentialInfo({ challenge, credentialId: null, residentKey: 'required' })).not.toThrow();
    expect(() => assertCredentialInfo({ challenge, credentialId: null, residentKey: 'bad' })).toThrow(/residentKey/);
    expect(() => assertCredentialInfo({ challenge, credentialId: 'user-pick' })).not.toThrow();
    expect(() => assertCredentialInfo({ challenge, credentialId: new Uint8Array([1]) })).not.toThrow();
    expect(() => assertCredentialInfo({ challenge, credentialId: [new Uint8Array([1]), new Uint8Array([2])] })).not.toThrow();
    expect(() => assertCredentialInfo({ challenge, credentialId: 42 })).toThrow(/credentialId/);
    expect(() => assertCredentialInfo(null)).toThrow(/must be an object/);
  });
});

// ---------------------------------------------------------------------------
// injection guard + withValidation
// ---------------------------------------------------------------------------

describe('isGianoProviderInjection', () => {
  let mock: InstalledWebAuthnMock;
  beforeEach(() => (mock = installWebAuthnMock()));
  afterEach(() => mock.uninstall());

  it('accepts a complete injection and rejects incomplete ones', () => {
    const injection = createMockInjection(mock.authenticator);
    expect(isGianoProviderInjection(injection)).toBe(true);
    expect(isGianoProviderInjection(null)).toBe(false);
    expect(isGianoProviderInjection({ ...injection, encodeUserId: undefined })).toBe(false);
    // submitUserOperation is optional
    expect(isGianoProviderInjection({ ...injection, submitUserOperation: undefined })).toBe(true);
    expect(isGianoProviderInjection({ ...injection, submitUserOperation: 'x' })).toBe(false);
  });
});

describe('withValidation', () => {
  let mock: InstalledWebAuthnMock;
  beforeEach(() => (mock = installWebAuthnMock()));
  afterEach(() => mock.uninstall());

  it('throws on an invalid implementation', () => {
    expect(() => withValidation({} as never)).toThrow(/Invalid Giano provider injection/);
  });

  it('leaves optional undefined hooks undefined and wraps the rest', async () => {
    const injection = createMockInjection(mock.authenticator); // no submitUserOperation
    const wrapped = withValidation(injection);
    expect(wrapped.submitUserOperation).toBeUndefined();
    expect(await wrapped.getNameForCredential()).toBe('Test Passkey');
    expect(wrapped.implementation).toBe(injection);
  });

  it('enforces each hook contract on the wrapped result', async () => {
    const base = createMockInjection(mock.authenticator);
    // withValidation's inferred type collapses hook signatures; cast back to the interface.
    const wrapped = withValidation({
      ...base,
      getNameForCredential: () => '',
      onCredentialCreated: async () => '0xnotanaddress' as never,
      onCredentialSignedIn: async () => 'yes' as never,
      submitUserOperation: async () => '0xshort' as never,
    }) as unknown as GianoProviderInjection;
    await expect(wrapped.getNameForCredential()).rejects.toThrow(/non-empty string/);
    await expect(wrapped.onCredentialCreated('n', new Uint8Array([1]), {} as never)).rejects.toThrow(/wallet address/);
    await expect(wrapped.onCredentialSignedIn({} as never)).rejects.toThrow(/must return a boolean/);
    await expect(wrapped.submitUserOperation!({} as never)).rejects.toThrow(/User operation hash/);
  });

  it('passes valid hook returns through, including a null onCredentialCreated and onCredentialKey', async () => {
    const wrapped = withValidation(createMockInjection(mock.authenticator)) as unknown as GianoProviderInjection;
    expect(await wrapped.onCredentialCreated('n', new Uint8Array([1]), {} as never)).toBeNull();
    expect(await wrapped.onCredentialKey(new Uint8Array([1]).buffer, { x: HEX32, y: HEX32 })).toBeUndefined();
    expect(await wrapped.decodeUserId(new Uint8Array([1]))).toMatchObject({ chainType: 0 });
  });
});

// ---------------------------------------------------------------------------
// wallet-api serialization
// ---------------------------------------------------------------------------

describe('base64url', () => {
  it('round-trips arbitrary bytes without padding', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 255, 128, 64]);
    const encoded = toBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect([...fromBase64Url(encoded)]).toEqual([...bytes]);
  });
});

describe('credential serialization (real mock credentials)', () => {
  it('serializes a registration credential to WebAuthn JSON', async () => {
    const authenticator = new MockAuthenticator();
    const credential = await authenticator.create({
      publicKey: { rp: { id: 'localhost', name: 'g' }, user: { id: new Uint8Array([1]), name: 'a', displayName: 'a' }, challenge: new Uint8Array([1, 2]), pubKeyCredParams: [] },
    } as CredentialCreationOptions);
    const json = serializeRegistrationCredential(credential);
    expect(json.type).toBe('public-key');
    expect(json.response.attestationObject).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(json.response.transports).toEqual(['internal']);
    expect(json.authenticatorAttachment).toBe('platform');
  });

  it('serializes an authentication credential to WebAuthn JSON', async () => {
    const authenticator = new MockAuthenticator();
    const created = await authenticator.create({
      publicKey: { rp: { id: 'localhost', name: 'g' }, user: { id: new Uint8Array([1]), name: 'a', displayName: 'a' }, challenge: new Uint8Array([1]), pubKeyCredParams: [] },
    } as CredentialCreationOptions);
    const assertion = await authenticator.get({ publicKey: { challenge: new Uint8Array([2]), allowCredentials: [{ type: 'public-key', id: created.rawId }] } } as CredentialRequestOptions);
    const json = serializeAuthenticationCredential(assertion);
    expect(json.response.authenticatorData).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(json.response.signature).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(json.response.userHandle).toBeTypeOf('string');
  });

  it('serializes a user operation to hex quantities and includes factory/paymaster only when present', () => {
    const base = {
      sender: ADDR,
      nonce: 1n,
      callData: '0xabcd',
      callGasLimit: 100n,
      verificationGasLimit: 200n,
      preVerificationGas: 300n,
      maxFeePerGas: 400n,
      maxPriorityFeePerGas: 500n,
      signature: '0xsig',
    };
    const plain = serializeUserOperation({ ...base });
    expect(plain.nonce).toBe('0x1');
    expect(plain.callGasLimit).toBe('0x64');
    expect('factory' in plain).toBe(false);
    expect('paymaster' in plain).toBe(false);

    const full = serializeUserOperation({
      ...base,
      factory: ADDR,
      factoryData: '0xdead',
      paymaster: ADDR,
      paymasterData: '0xbeef',
      paymasterVerificationGasLimit: 10n,
      paymasterPostOpGasLimit: 20n,
    });
    expect(full.factory).toBe(ADDR);
    expect(full.paymaster).toBe(ADDR);
    expect(full.paymasterVerificationGasLimit).toBe('0xa');
  });
});

// ---------------------------------------------------------------------------
// createWalletApiInjection
// ---------------------------------------------------------------------------

describe('createWalletApiInjection', () => {
  const makeFetch = (routes: Record<string, unknown>) =>
    vi.fn(async (url: string) => {
      const path = url.split('?')[0];
      const key = Object.keys(routes).find((route) => path.endsWith(route));
      if (key === undefined) return { ok: false, status: 404, json: async () => ({ message: 'not found' }) } as Response;
      return { ok: true, status: 200, json: async () => routes[key] } as Response;
    });

  it('exposes session helpers and defaults', () => {
    const injection = createWalletApiInjection({ apiUrl: 'https://wallet.test/api/', externalUserId: 'u1' });
    expect(injection.getSessionToken()).toBeNull();
    expect(injection.getNameForCredential()).toBe('Giano Passkey');
  });

  it('gets credential info, registers, signs in, fetches keys and submits userops', async () => {
    const authenticator = new MockAuthenticator();
    const created = await authenticator.create({
      publicKey: { rp: { id: 'localhost', name: 'g' }, user: { id: new Uint8Array([1]), name: 'a', displayName: 'a' }, challenge: new Uint8Array([1]), pubKeyCredParams: [] },
    } as CredentialCreationOptions);
    const { x, y } = authenticator.getPublicKeyXY(created.rawId);
    const credIdParam = encodeURIComponent(toBase64Url(new Uint8Array(created.rawId)));

    const onSessionChanged = vi.fn();
    const fetchImpl = makeFetch({
      '/v1/webauthn/options': { kind: 'authentication', challenge: toBase64Url(new Uint8Array([9, 9, 9])), credentialIds: [toBase64Url(new Uint8Array([7, 7]))] },
      '/v1/webauthn/registration/verify': { walletAddress: ADDR, session: { token: 'tok-reg' } },
      '/v1/webauthn/authentication/verify': { verified: true, session: { token: 'tok-auth' } },
      [`/v1/me/credentials/${credIdParam}/public-key`]: { x, y },
      '/v1/userops': { userOperationHash: HEX32 },
    });

    const grant = vi.fn(async () => ({ 'x-grant': 'yes' }));
    const injection = createWalletApiInjection({
      apiUrl: 'https://wallet.test/api',
      externalUserId: 'user-1',
      getRegistrationGrant: grant,
      onSessionChanged,
      fetch: fetchImpl as never,
    });

    const info = await injection.getCredentialInfo();
    expect(info.credentialId).toBeInstanceOf(Uint8Array);
    expect(grant).toHaveBeenCalled();

    expect(await injection.onCredentialCreated('n', new Uint8Array([1]), created as never)).toBeNull();
    expect(injection.getSessionToken()).toBe('tok-reg');
    expect(onSessionChanged).toHaveBeenCalledWith('tok-reg');

    const assertion = await authenticator.get({ publicKey: { challenge: new Uint8Array([3]), allowCredentials: [{ type: 'public-key', id: created.rawId }] } } as CredentialRequestOptions);
    expect(await injection.onCredentialSignedIn(assertion)).toBe(true);
    expect(injection.getSessionToken()).toBe('tok-auth');

    const key = await injection.getPublicKeyByCredentialId(created.rawId);
    expect(key).toEqual({ x, y });

    const hash = await injection.submitUserOperation!({ sender: ADDR, nonce: 0n, callData: '0x', callGasLimit: 1n, verificationGasLimit: 1n, preVerificationGas: 1n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, signature: '0x' } as never);
    expect(hash).toBe(HEX32);

    await injection.onCredentialKey(created.rawId, { x, y }); // no-op, server already stored the key
  });

  it('round-trips encodeUserId / decodeUserId — the handle carries no chain id (MC-78)', async () => {
    const injection = createWalletApiInjection({ apiUrl: 'https://wallet.test/api', externalUserId: 'u' });
    const encoded = await injection.encodeUserId('11223344556677889900aabbccddeeff', FACTORY_ADDRESS, 0);
    // id(16) + factory(20) + chainType(1): every field is chain-independent by design
    expect((encoded as Uint8Array).byteLength).toBe(37);
    const decoded = await injection.decodeUserId(encoded);
    expect(decoded.walletFactoryAddress.toLowerCase()).toBe(FACTORY_ADDRESS.toLowerCase());
    expect(decoded.chainType).toBe(0);
    expect('chainId' in decoded).toBe(false);
  });

  it('throws a helpful error when the API responds non-ok', async () => {
    const fetchImpl = vi.fn(async () => ({ ok: false, status: 500, json: async () => ({ error: 'boom' }) } as Response));
    const injection = createWalletApiInjection({ apiUrl: 'https://wallet.test/api', externalUserId: 'u', fetch: fetchImpl as never });
    await expect(injection.getCredentialInfo()).rejects.toThrow(/wallet-api .* failed: boom/);
  });

  it('requires a session for authenticated calls and clears it on logout', async () => {
    const fetchImpl = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({}) } as Response));
    const injection = createWalletApiInjection({ apiUrl: 'https://wallet.test/api', externalUserId: 'u', fetch: fetchImpl as never });
    await expect(injection.getPublicKeyByCredentialId(new ArrayBuffer(2))).rejects.toThrow(/requires a session/);

    const withSession = createWalletApiInjection({ apiUrl: 'https://wallet.test/api', externalUserId: 'u', sessionToken: 'tok', fetch: fetchImpl as never });
    expect(withSession.getSessionToken()).toBe('tok');
    await withSession.logout();
    expect(withSession.getSessionToken()).toBeNull();
  });
});
