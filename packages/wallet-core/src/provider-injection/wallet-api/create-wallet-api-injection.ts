import type { Hash, Hex } from 'viem';
import type { ChainType } from '../../provider';
import type { GianoProviderInjection } from '../injection';
import type { XYVector } from '../types';
import {
  fromBase64Url,
  serializeAuthenticationCredential,
  serializeRegistrationCredential,
  serializeUserOperation,
  toBase64Url,
} from './serialization';

export type CreateWalletApiInjectionOptions = {
  /** Base URL of the giano-wallet-api deployment, e.g. https://wallet.example.com/api */
  apiUrl: string;
  /** The client project's user id — the R6a binding point between app auth and credentials. */
  externalUserId: string;
  /** Display name for newly created passkeys. */
  credentialName?: string;
  /**
   * Production hook: returns headers authorizing the ceremony-options call for this
   * user (e.g. an admin-key-backed grant minted by the client project's backend).
   * Not needed when the wallet-api runs with OPEN_REGISTRATION=true (demos).
   */
  getRegistrationGrant?: () => Promise<Record<string, string>> | Record<string, string>;
  /** Called whenever a session token is issued or cleared — persist it if you want session resume. */
  onSessionChanged?: (token: string | null) => void;
  /**
   * Called when authentication reveals the credential belongs to a DIFFERENT external user
   * id than the one this injection was constructed with — which is what happens when a
   * device signs in with a passkey created through a cross-device addition (WM-18): the
   * device's own random id has never seen the credential, but the server knows whose it is.
   * Persist the adopted id so later ceremonies and silent restores list the credential.
   */
  onExternalUserIdChanged?: (externalUserId: string) => void;
  /** Initial session token (e.g. restored from storage). */
  sessionToken?: string | null;
  fetch?: typeof fetch;
};

export type WalletApiInjection = GianoProviderInjection & {
  /** Current wallet-api session bearer token (null when signed out). */
  getSessionToken(): string | null;
  /** The external user id currently in force (may have been adopted at sign-in). */
  getExternalUserId(): string;
  logout(): Promise<void>;
  /**
   * Signs in with a DISCOVERABLE passkey — no allowCredentials, so the authenticator
   * offers whatever resident credentials it holds for this RP. This is how a device that
   * has never seen this wallet before (its credential was added through a cross-device
   * pending addition) opens a session for it (WM-33): the server resolves the credential,
   * scopes the session to its wallet, and this injection adopts the canonical external
   * user id so ordinary flows work from then on.
   */
  signInWithExistingPasskey(): Promise<{ walletAddress: Hex; externalUserId: string; credentialId: string }>;
};

/**
 * Reference implementation of the `GianoProviderInjection` seam backed by the
 * giano-wallet-api service: full server-side @simplewebauthn verification, DB-backed
 * credentials and sessions, and policied user-operation relay — replacing the demo's
 * in-memory, unauthenticated storage API.
 *
 * The seam already passes complete `PublicKeyCredential` objects, so this is a pure
 * client of the existing interface — no connector/provider changes required.
 */
export function createWalletApiInjection(options: CreateWalletApiInjectionOptions): WalletApiInjection {
  const {
    apiUrl,
    credentialName = 'Giano Passkey',
    getRegistrationGrant,
    onSessionChanged,
    onExternalUserIdChanged,
    fetch: fetchImpl = globalThis.fetch.bind(globalThis),
  } = options;
  const base = apiUrl.replace(/\/$/, '');

  let sessionToken: string | null = options.sessionToken ?? null;
  // Mutable: authentication may reveal the credential's canonical external user id (a
  // credential bound to this wallet on another device), which this injection then adopts.
  let externalUserId = options.externalUserId;

  const setSession = (token: string | null) => {
    sessionToken = token;
    onSessionChanged?.(token);
  };

  const adoptExternalUserId = (id: string | undefined) => {
    if (id && id !== externalUserId) {
      externalUserId = id;
      onExternalUserIdChanged?.(id);
    }
  };

  async function api<T>(path: string, init: RequestInit & { auth?: boolean } = {}): Promise<T> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      ...(init.headers as Record<string, string> | undefined),
    };
    if (init.auth) {
      if (!sessionToken) throw new Error(`wallet-api: ${path} requires a session — sign in first`);
      headers.authorization = `Bearer ${sessionToken}`;
    }
    const response = await fetchImpl(`${base}${path}`, { ...init, headers });
    if (!response.ok) {
      let message = `${response.status}`;
      try {
        const body = (await response.json()) as { message?: string; error?: string };
        message = body.message ?? body.error ?? message;
      } catch {
        // non-JSON error body
      }
      throw new Error(`wallet-api ${path} failed: ${message}`);
    }
    return (await response.json()) as T;
  }

  return {
    getSessionToken: () => sessionToken,
    getExternalUserId: () => externalUserId,

    signInWithExistingPasskey: async () => {
      const grantHeaders = getRegistrationGrant ? await getRegistrationGrant() : {};
      const options_ = await api<{ challenge: string }>('/v1/webauthn/options', {
        method: 'POST',
        headers: grantHeaders,
        body: JSON.stringify({ externalUserId, kind: 'authentication' }),
      });
      // No allowCredentials: the authenticator surfaces its resident credentials for this
      // RP, which is the only way a device can use a credential the local storage has
      // never heard of. The single passkey prompt IS the ceremony.
      const credential = (await navigator.credentials.get({
        publicKey: { challenge: fromBase64Url(options_.challenge) as BufferSource, userVerification: 'required' },
      })) as PublicKeyCredential | null;
      if (!credential) throw new Error('no passkey was selected');
      const result = await api<{ walletAddress: Hex; externalUserId: string; credentialId: string; session: { token: string } }>(
        '/v1/webauthn/authentication/verify',
        { method: 'POST', body: JSON.stringify({ response: serializeAuthenticationCredential(credential) }) },
      );
      setSession(result.session.token);
      adoptExternalUserId(result.externalUserId);
      return { walletAddress: result.walletAddress, externalUserId: result.externalUserId, credentialId: result.credentialId };
    },

    logout: async () => {
      if (sessionToken) {
        await api('/v1/sessions/logout', { method: 'POST', auth: true }).catch(() => undefined);
      }
      setSession(null);
    },

    getNameForCredential: () => credentialName,

    getCredentialInfo: async () => {
      const grantHeaders = getRegistrationGrant ? await getRegistrationGrant() : {};
      const result = await api<{ kind: string; challenge: string; credentialIds: string[] }>('/v1/webauthn/options', {
        method: 'POST',
        headers: grantHeaders,
        body: JSON.stringify({ externalUserId }),
      });
      const [firstCredential] = result.credentialIds;
      return {
        credentialId: firstCredential ? fromBase64Url(firstCredential) : null,
        challenge: fromBase64Url(result.challenge),
      };
    },

    onCredentialCreated: async (name, _challenge, credential) => {
      const result = await api<{ walletAddress: Hex; session: { token: string } }>('/v1/webauthn/registration/verify', {
        method: 'POST',
        body: JSON.stringify({
          externalUserId,
          credentialName: name,
          response: serializeRegistrationCredential(credential),
        }),
      });
      setSession(result.session.token);
      // Phase 2: no server-side wallet deployment — returning null lets the provider
      // keep the counterfactual first-userop factory/factoryData deployment path.
      return null;
    },

    onCredentialSignedIn: async (credential) => {
      const result = await api<{ verified: boolean; externalUserId?: string; session: { token: string } }>('/v1/webauthn/authentication/verify', {
        method: 'POST',
        body: JSON.stringify({ response: serializeAuthenticationCredential(credential) }),
      });
      setSession(result.session.token);
      adoptExternalUserId(result.externalUserId);
      return result.verified;
    },

    getPublicKeyByCredentialId: async (rawId): Promise<XYVector> => {
      const credentialId = encodeURIComponent(toBase64Url(rawId));
      const result = await api<{ x: Hex; y: Hex }>(`/v1/me/credentials/${credentialId}/public-key`, { auth: true });
      return { x: result.x, y: result.y };
    },

    onCredentialKey: async () => {
      // The server already derived and stored the public key during registration verify.
    },

    // Layout: id(16) ‖ factory(20) ‖ chainType(1) = 37 bytes. Deliberately NO chain id
    // (MC-78): the credential is valid on every served chain, and the handle is written
    // into the authenticator at registration and can never be rewritten — a chain stamped
    // in would be misleading by construction.
    encodeUserId: (id: string, factoryAddress: string, chainType: ChainType) => {
      const strip = (hex: string) => hex.replace(/^0x/, '');
      const pad = (hex: string, bytes: number) => strip(hex).padStart(bytes * 2, '0');
      const packed = pad(id, 16) + pad(factoryAddress, 20) + pad(chainType.toString(16), 1);
      const out = new Uint8Array(packed.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(packed.slice(i * 2, i * 2 + 2), 16);
      return out;
    },

    decodeUserId: (userId: BufferSource) => {
      const bytes = userId instanceof Uint8Array ? userId : new Uint8Array(userId as ArrayBuffer);
      const hex = (slice: Uint8Array) => Array.from(slice, (b) => b.toString(16).padStart(2, '0')).join('');
      const idHex = hex(bytes.slice(0, 16));
      return {
        userId: [idHex.slice(0, 8), idHex.slice(8, 12), idHex.slice(12, 16), idHex.slice(16, 20), idHex.slice(20)].join('-'),
        walletFactoryAddress: `0x${hex(bytes.slice(16, 36))}`,
        chainType: parseInt(hex(bytes.slice(36, 37)), 16) as ChainType,
      };
    },

    submitUserOperation: async (signedUserOp, chainId): Promise<Hash> => {
      const result = await api<{ userOperationHash: Hash }>('/v1/userops', {
        method: 'POST',
        auth: true,
        // chainId names the chain the op was signed for; the backend validates it against
        // its closed registry and computes the hash from the RESOLVED chain (MC-51, MC-57).
        body: JSON.stringify({ chainId, userOperation: serializeUserOperation(signedUserOp as unknown as Record<string, unknown>) }),
      });
      return result.userOperationHash;
    },
  };
}
