import type { Hex } from 'viem';
import { serializeRegistrationCredential } from '../provider-injection/wallet-api/serialization';

/**
 * Client for the wallet-api's wallet-management surface: the pending-addition lifecycle
 * (D8), credential naming and removal. This is plain fetch against documented endpoints —
 * no Giano-specific privilege — so a bring-your-own-UI tenant drives exactly the same
 * calls the stock interface does (WM-60).
 */

export type PendingAdditionStatus = 'open' | 'filled' | 'consumed' | 'declined' | 'expired';

export type PendingAddition = {
  id: string;
  status: PendingAdditionStatus;
  expiresAt: string;
  publicKey: { x: Hex; y: Hex } | null;
};

export type RegistryCredential = {
  credentialId: string;
  walletAddress: string;
  name: string | null;
  publicKeyX: Hex;
  publicKeyY: Hex;
  transports: string[] | null;
  createdAt: string;
  removedAt: string | null;
};

/**
 * Carries the machine-readable error code, so a caller can tell `pending-expired` from a
 * network failure (WM-23) and key its copy off the code rather than the prose.
 */
export class WalletManagementApiError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = 'WalletManagementApiError';
  }
}

export type CreateWalletManagementApiOptions = {
  /** Base URL of the wallet-api (e.g. '/api' when proxied same-origin). */
  apiUrl: string;
  /** Session bearer for the authenticated endpoints; claim/fill need none by design (WM-19). */
  getSessionToken?: () => string | null;
  fetch?: typeof fetch;
};

export function createWalletManagementApi(options: CreateWalletManagementApiOptions) {
  const base = options.apiUrl.replace(/\/$/, '');
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);

  async function api<T>(path: string, init: RequestInit & { auth?: boolean } = {}): Promise<T> {
    const headers: Record<string, string> = { 'content-type': 'application/json', ...(init.headers as Record<string, string> | undefined) };
    if (init.auth) {
      const token = options.getSessionToken?.();
      if (!token) throw new WalletManagementApiError('no-session', `${path} requires a session — sign in first`, 401);
      headers.authorization = `Bearer ${token}`;
    }
    const response = await fetchImpl(`${base}${path}`, { ...init, headers });
    if (!response.ok) {
      let code = String(response.status);
      let message = `${path} failed with ${response.status}`;
      try {
        const body = (await response.json()) as { error?: string; message?: string };
        code = body.error ?? code;
        message = body.message ?? message;
      } catch {
        // non-JSON error body
      }
      throw new WalletManagementApiError(code, message, response.status);
    }
    return (await response.json()) as T;
  }

  return {
    me: () => api<{ externalUserId: string; walletAddress: Hex; credentialId: string }>('/v1/me', { auth: true }),

    listCredentials: async () => (await api<{ credentials: RegistryCredential[] }>('/v1/me/credentials', { auth: true })).credentials,

    renameCredential: (credentialId: string, name: string | null) =>
      api<{ ok: true; name: string | null }>(`/v1/me/credentials/${encodeURIComponent(credentialId)}`, {
        method: 'PATCH',
        auth: true,
        body: JSON.stringify({ name }),
      }),

    /** Tells the registry an owner key was removed on-chain; it verifies before believing. */
    markCredentialRemoved: (credentialId: string) =>
      api<{ ok: true; removedCurrentSession: boolean }>(`/v1/me/credentials/${encodeURIComponent(credentialId)}/removed`, {
        method: 'POST',
        auth: true,
      }),

    // ── Pending additions — the authorising device's side (session-bound, WM-19) ──

    openPendingAddition: () =>
      api<{ id: string; claimCode: string; expiresAt: string }>('/v1/wallet/pending-additions', { method: 'POST', auth: true }),

    getPendingAddition: (id: string) => api<PendingAddition>(`/v1/wallet/pending-additions/${id}`, { auth: true }),

    declinePendingAddition: (id: string) =>
      api<{ ok: true }>(`/v1/wallet/pending-additions/${id}/decline`, { method: 'POST', auth: true }),

    completePendingAddition: (id: string, body: { chainIds: number[]; name?: string }) =>
      api<{ ok: true; credentialId: string }>(`/v1/wallet/pending-additions/${id}/complete`, {
        method: 'POST',
        auth: true,
        body: JSON.stringify(body),
      }),

    // ── Pending additions — the new device's side (the claim code only routes) ──

    claimPendingAddition: (claimCode: string) =>
      api<{ rpId: string; challenge: string; pendingAdditionId: string }>('/v1/wallet/pending-additions/claim', {
        method: 'POST',
        body: JSON.stringify({ claimCode }),
      }),

    fillPendingAddition: (claimCode: string, credential: Omit<PublicKeyCredential, 'toJSON'>) =>
      api<{ ok: true; publicKey: { x: Hex; y: Hex } }>('/v1/wallet/pending-additions/claim/fill', {
        method: 'POST',
        body: JSON.stringify({ claimCode, response: serializeRegistrationCredential(credential) }),
      }),

    // ── Audit for owner changes the registry has no row for (WM-50) ──

    recordOwnerEvent: (body: {
      action: 'owner-added' | 'owner-removed' | 'owner-change-refused';
      ownerKind: 'address' | 'passkey';
      owner: string;
      chainIds: number[];
      detail?: string;
    }) => api<{ ok: true }>('/v1/wallet/owner-events', { method: 'POST', auth: true, body: JSON.stringify(body) }),
  };
}

export type WalletManagementApi = ReturnType<typeof createWalletManagementApi>;
