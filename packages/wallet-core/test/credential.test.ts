import { toHex } from 'viem';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getCredential } from '../src/account/get-credential';
import { getWebAuthnAccount } from '../src/account/get-web-authn-account';
import * as pkg from '../src';
import { createMockInjection } from './helpers';
import { MockAuthenticator, installWebAuthnMock, type InstalledWebAuthnMock } from './webauthn-mock';

let mock: InstalledWebAuthnMock;
beforeEach(() => (mock = installWebAuthnMock()));
afterEach(() => mock.uninstall());

async function seedCredential(authenticator: MockAuthenticator) {
  return authenticator.create({
    publicKey: { rp: { id: 'localhost', name: 'g' }, user: { id: new Uint8Array([1]), name: 'a', displayName: 'a' }, challenge: new Uint8Array([1]), pubKeyCredParams: [{ type: 'public-key', alg: -7 }] },
  } as CredentialCreationOptions);
}

describe('getCredential', () => {
  it('discovers a resident credential for user-pick (no allowCredentials)', async () => {
    await seedCredential(mock.authenticator);
    const getSpy = vi.spyOn(globalThis.navigator.credentials, 'get');
    const credential = await getCredential({ credentialId: 'user-pick', challenge: new Uint8Array([2]) });
    expect(credential).not.toBeNull();
    expect(getSpy.mock.calls[0][0]!.publicKey!.allowCredentials).toBeUndefined();
  });

  it('scopes to a single credential id', async () => {
    const created = await seedCredential(mock.authenticator);
    const getSpy = vi.spyOn(globalThis.navigator.credentials, 'get');
    await getCredential({ credentialId: new Uint8Array(created.rawId), challenge: new Uint8Array([2]) });
    expect(getSpy.mock.calls[0][0]!.publicKey!.allowCredentials).toHaveLength(1);
  });

  it('scopes to an array of credential ids', async () => {
    const created = await seedCredential(mock.authenticator);
    const getSpy = vi.spyOn(globalThis.navigator.credentials, 'get');
    await getCredential({ credentialId: [new Uint8Array(created.rawId), new Uint8Array([9, 9])], challenge: new Uint8Array([2]) });
    expect(getSpy.mock.calls[0][0]!.publicKey!.allowCredentials).toHaveLength(2);
  });

  it('applies the default mediation and user-verification requirements', async () => {
    await seedCredential(mock.authenticator);
    const getSpy = vi.spyOn(globalThis.navigator.credentials, 'get');
    await getCredential({ credentialId: 'user-pick', challenge: new Uint8Array([2]) });
    expect(getSpy.mock.calls[0][0]!.mediation).toBe('optional');
    expect(getSpy.mock.calls[0][0]!.publicKey!.userVerification).toBe('required');
  });
});

describe('getWebAuthnAccount', () => {
  it('returns a WebAuthn account for a valid, signed-in credential', async () => {
    const created = await seedCredential(mock.authenticator);
    const injection = createMockInjection(mock.authenticator, { credentialId: new Uint8Array(created.rawId) });
    const account = await getWebAuthnAccount(
      { credentialId: new Uint8Array(created.rawId), challenge: new Uint8Array([2]) },
      injection,
    );
    expect(account?.type).toBe('webAuthn');
    expect(account?.publicKey).toMatch(/^0x[0-9a-f]{128}$/);
  });

  it('returns null when the ceremony is declined (NotAllowedError)', async () => {
    const injection = createMockInjection(mock.authenticator);
    // No matching credential → mock throws NotAllowedError → swallowed to null.
    const account = await getWebAuthnAccount(
      { credentialId: new Uint8Array([9, 9, 9]), challenge: new Uint8Array([2]) },
      injection,
    );
    expect(account).toBeNull();
  });

  it('returns null when navigator resolves no credential', async () => {
    vi.spyOn(globalThis.navigator.credentials, 'get').mockResolvedValueOnce(null);
    const injection = createMockInjection(mock.authenticator);
    const account = await getWebAuthnAccount({ credentialId: 'user-pick', challenge: new Uint8Array([2]) }, injection);
    expect(account).toBeNull();
  });

  it('throws when sign-in verification fails', async () => {
    const created = await seedCredential(mock.authenticator);
    const injection = createMockInjection(mock.authenticator, { credentialId: new Uint8Array(created.rawId), onCredentialSignedIn: async () => false });
    await expect(
      getWebAuthnAccount({ credentialId: new Uint8Array(created.rawId), challenge: new Uint8Array([2]) }, injection),
    ).rejects.toThrow(/Failed to sign in/);
  });

  it('throws when the credential id is unknown to the backend (zero public key)', async () => {
    const created = await seedCredential(mock.authenticator);
    const injection = createMockInjection(mock.authenticator, {
      credentialId: new Uint8Array(created.rawId),
      getPublicKeyByCredentialId: async () => ({ x: toHex(0, { size: 32 }), y: toHex(0, { size: 32 }) }),
    });
    await expect(
      getWebAuthnAccount({ credentialId: new Uint8Array(created.rawId), challenge: new Uint8Array([2]) }, injection),
    ).rejects.toThrow(/Unknown credential ID/);
  });
});

describe('package entrypoint', () => {
  it('re-exports the public surface', () => {
    expect(pkg.createGianoProvider).toBeTypeOf('function');
    expect(pkg.toGianoSmartAccount).toBeTypeOf('function');
    expect(pkg.GianoError).toBeTypeOf('function');
    expect(pkg.createWalletApiInjection).toBeTypeOf('function');
    expect(pkg.defaultGianoLogger).toBeTypeOf('object');
  });
});
