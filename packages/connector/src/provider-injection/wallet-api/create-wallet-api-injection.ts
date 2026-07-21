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
  /** Initial session token (e.g. restored from storage). */
  sessionToken?: string | null;
  fetch?: typeof fetch;
};

export type WalletApiInjection = GianoProviderInjection & {
  /** Current wallet-api session bearer token (null when signed out). */
  getSessionToken(): string | null;
  logout(): Promise<void>;
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
    externalUserId,
    credentialName = 'Giano Passkey',
    getRegistrationGrant,
    onSessionChanged,
    fetch: fetchImpl = globalThis.fetch.bind(globalThis),
  } = options;
  const base = apiUrl.replace(/\/$/, '');

  let sessionToken: string | null = options.sessionToken ?? null;

  const setSession = (token: string | null) => {
    sessionToken = token;
    onSessionChanged?.(token);
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
      const result = await api<{ verified: boolean; session: { token: string } }>('/v1/webauthn/authentication/verify', {
        method: 'POST',
        body: JSON.stringify({ response: serializeAuthenticationCredential(credential) }),
      });
      setSession(result.session.token);
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

    encodeUserId: (id: string, factoryAddress: string, chainId: string, chainType: ChainType) => {
      const strip = (hex: string) => hex.replace(/^0x/, '');
      const pad = (hex: string, bytes: number) => strip(hex).padStart(bytes * 2, '0');
      const packed = pad(id, 16) + pad(factoryAddress, 20) + pad(chainId, 4) + pad(chainType.toString(16), 1);
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
        chainId: parseInt(hex(bytes.slice(36, 40)), 16),
        chainType: parseInt(hex(bytes.slice(40, 41)), 16) as ChainType,
      };
    },

    submitUserOperation: async (signedUserOp): Promise<Hash> => {
      const result = await api<{ userOperationHash: Hash }>('/v1/userops', {
        method: 'POST',
        auth: true,
        body: JSON.stringify({ userOperation: serializeUserOperation(signedUserOp as unknown as Record<string, unknown>) }),
      });
      return result.userOperationHash;
    },
  };
}
