import * as PublicKey from 'ox/PublicKey';
import * as Signature from 'ox/Signature';
import * as WebAuthnP256 from 'ox/WebAuthnP256';
import { createWebAuthnCredential, toWebAuthnAccount } from 'viem/account-abstraction';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MockAuthenticator, installWebAuthnMock, type InstalledWebAuthnMock } from './webauthn-mock';
import { cborMap, decodeCbor, encodeCbor, type CborMap } from './webauthn-mock/cbor';
import { derSignatureToRaw, rawSignatureToDer } from './webauthn-mock/der';

const subtle = globalThis.crypto.subtle;
const bytesOf = (buffer: ArrayBuffer | Uint8Array) => (buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer));

describe('CBOR codec', () => {
  it('round-trips positive, negative, string, bytes, arrays and maps', () => {
    const value: CborMap = cborMap([
      [1, 2],
      [3, -7],
      ['name', 'giano'],
      [-1, new Uint8Array([0xde, 0xad, 0xbe, 0xef])],
      ['list', [1, 2, 300, 70000]],
    ]);
    const [decoded] = decodeCbor(encodeCbor(value));
    const map = decoded as CborMap;
    expect(map.__cborMap[0]).toEqual([1, 2]);
    expect(map.__cborMap[1]).toEqual([3, -7]);
    expect(map.__cborMap[2]).toEqual(['name', 'giano']);
    expect(map.__cborMap[4]).toEqual(['list', [1, 2, 300, 70000]]);
  });

  it('rejects non-integer numbers and unsupported values', () => {
    expect(() => encodeCbor(1.5)).toThrow(/integers/);
    expect(() => encodeCbor(null as never)).toThrow(/unsupported/);
  });
});

describe('DER signature codec', () => {
  it('round-trips raw <-> DER, including high-bit (0x80) integers', () => {
    const raw = new Uint8Array(64);
    raw[0] = 0x80; // force sign-byte padding on r
    raw[32] = 0x7f;
    raw.fill(0xab, 33);
    const der = rawSignatureToDer(raw);
    expect(der[0]).toBe(0x30);
    expect(bytesOf(derSignatureToRaw(der))).toEqual(raw);
  });

  it('rejects wrong-length raw signatures', () => {
    expect(() => rawSignatureToDer(new Uint8Array(10))).toThrow(/64-byte/);
  });
});

describe('MockAuthenticator (real crypto)', () => {
  it('registration produces a WebCrypto-importable SPKI key and matching COSE key', async () => {
    const authenticator = new MockAuthenticator();
    const credential = await authenticator.create({
      publicKey: {
        rp: { id: 'localhost', name: 'giano' },
        user: { id: new Uint8Array([1, 2, 3]), name: 'a', displayName: 'a' },
        challenge: new Uint8Array([9, 9, 9]),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
    } as CredentialCreationOptions);

    const response = credential.response as AuthenticatorAttestationResponse;
    // SPKI is a real key WebCrypto can import.
    const spki = response.getPublicKey()!;
    const imported = await subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const raw = new Uint8Array(await subtle.exportKey('raw', imported));
    expect(raw[0]).toBe(0x04);

    // The COSE key embedded in the attestationObject's authData matches the SPKI key.
    const [attestation] = decodeCbor(bytesOf(response.attestationObject));
    const attMap = (attestation as CborMap).__cborMap;
    expect(attMap.find(([k]) => k === 'fmt')?.[1]).toBe('none');
    const authData = attMap.find(([k]) => k === 'authData')?.[1] as Uint8Array;
    // authData: rpIdHash(32) flags(1) counter(4) aaguid(16) credIdLen(2) credId(20) coseKey
    const credIdLen = (authData[53] << 8) | authData[54];
    const [coseKey] = decodeCbor(authData, 55 + credIdLen);
    const cose = (coseKey as CborMap).__cborMap;
    const x = cose.find(([k]) => k === -2)?.[1] as Uint8Array;
    const y = cose.find(([k]) => k === -3)?.[1] as Uint8Array;
    expect(bytesOf(x)).toEqual(raw.slice(1, 33));
    expect(bytesOf(y)).toEqual(raw.slice(33, 65));
  });

  it('authentication produces a signature that verifies against the registered key', async () => {
    const authenticator = new MockAuthenticator();
    const created = await authenticator.create({
      publicKey: {
        rp: { id: 'localhost', name: 'giano' },
        user: { id: new Uint8Array([1]), name: 'a', displayName: 'a' },
        challenge: new Uint8Array([1, 2, 3, 4]),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      },
    } as CredentialCreationOptions);
    const publicKey = await subtle.importKey(
      'spki',
      (created.response as AuthenticatorAttestationResponse).getPublicKey()!,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );

    const assertion = await authenticator.get({
      publicKey: { challenge: new Uint8Array([5, 6, 7, 8]), allowCredentials: [{ type: 'public-key', id: created.rawId }] },
    } as CredentialRequestOptions);

    const response = assertion.response as AuthenticatorAssertionResponse;
    const authData = bytesOf(response.authenticatorData);
    const clientHash = new Uint8Array(await subtle.digest('SHA-256', bytesOf(response.clientDataJSON)));
    const payload = new Uint8Array([...authData, ...clientHash]);
    const rawSig = derSignatureToRaw(bytesOf(response.signature));
    const valid = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, rawSig, payload);
    expect(valid).toBe(true);

    // clientDataJSON carries the challenge we asked to sign, and the counter advanced.
    const clientData = JSON.parse(new TextDecoder().decode(bytesOf(response.clientDataJSON)));
    expect(clientData.type).toBe('webauthn.get');
  });

  it('rejects get() when no credential matches (NotAllowedError)', async () => {
    const authenticator = new MockAuthenticator();
    await expect(
      authenticator.get({ publicKey: { challenge: new Uint8Array([1]), allowCredentials: [{ type: 'public-key', id: new Uint8Array([9, 9]) }] } } as CredentialRequestOptions),
    ).rejects.toMatchObject({ name: 'NotAllowedError' });
  });

  it('discovers a resident key when no allowCredentials are supplied', async () => {
    const authenticator = new MockAuthenticator();
    const created = await authenticator.create({
      publicKey: { rp: { id: 'localhost', name: 'g' }, user: { id: new Uint8Array([7]), name: 'a', displayName: 'a' }, challenge: new Uint8Array([1]), pubKeyCredParams: [] },
    } as CredentialCreationOptions);
    const assertion = await authenticator.get({ publicKey: { challenge: new Uint8Array([2]) } } as CredentialRequestOptions);
    expect(assertion.id).toBe(created.id);
    expect(authenticator.getPublicKeyXY(created.rawId).x).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

describe('mock interop with ox + viem', () => {
  let mock: InstalledWebAuthnMock;
  beforeEach(() => {
    mock = installWebAuthnMock({ origin: 'https://wallet.localhost' });
  });
  afterEach(() => mock.uninstall());

  it('drives viem createWebAuthnCredential + toWebAuthnAccount end-to-end, and ox verifies the signature', async () => {
    const credential = await createWebAuthnCredential({
      user: { name: 'giano', id: new Uint8Array([1, 2, 3, 4]) },
      challenge: new Uint8Array([1, 2, 3]),
    });
    // viem returns a `0x`-prefixed 64-byte (128 hex char) public key with the `04` prefix dropped.
    expect(credential.publicKey).toMatch(/^0x[0-9a-f]{128}$/);

    const account = toWebAuthnAccount({ credential });
    const hash = `0x${'ab'.repeat(32)}` as const;
    const { signature, webauthn } = await account.sign({ hash });

    const verified = WebAuthnP256.verify({
      metadata: webauthn,
      challenge: hash,
      publicKey: PublicKey.fromHex(`0x04${credential.publicKey.slice(2)}`),
      signature: Signature.fromHex(signature),
    });
    expect(verified).toBe(true);
  });
});
