/**
 * A thin client over wallet-api's platform tier (specs/PLATFORM-ADMIN-SPECS.md §7), reached
 * through this console's own `/api` proxy — same origin, and the proxy drops the Origin header the
 * platform admin routes refuse.
 *
 * Types are written by hand against `services/wallet-api/openapi/openapi.json`, which CI keeps
 * honest on the API side; there are few enough routes that a generator would be more machinery
 * than it saves (§11.1). A refused call never throws: it comes back as a typed {@link ApiError}
 * carrying the API's own code and detail, because every refusal here has something specific to
 * show — the field an issue is on, the tenant that holds an origin, the balance blocking a delete.
 * The one exception is 401, which means the session is gone and is raised as
 * {@link PlatformUnauthorized} so the session layer can drop it wherever it happens.
 */

export type TenantStatus = 'active' | 'suspended' | 'deleted';

export type PlatformTenant = {
  id: string;
  slug: string;
  status: TenantStatus;
  version: number;
  walletOrigin: string;
  rpId: string;
  rpName: string;
  expectedOrigins: string[];
  allowedDappOrigins: string[];
  corsOrigins: string[];
  openRegistration: boolean;
  policy: Record<string, unknown>;
  branding: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  statusChangedAt: string | null;
};

export type TenantSummary = PlatformTenant & { users: number };

export type AdminKeyInfo = { id: string; label: string | null; hashPrefix: string; createdBy: string; createdAt: string };
export type IssuedAdminKey = { id: string; label: string; key: string };

export type TenantDetail = {
  tenant: PlatformTenant;
  adminKeys: AdminKeyInfo[];
  users: number;
  credentials: number;
  lastUseropAt: string | null;
  ledger: { chainId: number; balanceWei: string; deficitWei: string; lastSyncedBlock: string | null }[];
};

export type HistoryEntry = {
  id: string;
  action: string;
  actor: string;
  platformSessionId: string | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  detail: Record<string, unknown> | null;
  createdAt: string;
};

export type SignedInAdmin = { token: string; expiresAt: string; admin: { id: string; address: string } };

/** What a create sends. Origins are lists; the API validates every field and every invariant. */
export type TenantCreateInput = {
  slug: string;
  walletOrigin: string;
  rpName: string;
  expectedOrigins?: string[];
  allowedDappOrigins?: string[];
  corsOrigins?: string[];
  openRegistration?: boolean;
  adminKeys?: { label: string }[];
  id?: string;
};

export type TenantPatchInput = Partial<
  Pick<PlatformTenant, 'rpName' | 'expectedOrigins' | 'allowedDappOrigins' | 'corsOrigins' | 'openRegistration' | 'policy' | 'branding'>
>;

/** A refusal, exactly as the API stated it: `error` is its code, the rest is its detail. */
export type ApiError = {
  status: number;
  error: string;
  message: string;
  /** Present on a 400: one per violated field, `path` a JSON pointer such as `/expectedOrigins`. */
  issues?: { path: string; message: string }[];
  [detail: string]: unknown;
};

export type ApiResult<T> = { ok: true; value: T } | { ok: false; error: ApiError };

/** The session is gone — expired, revoked, or its platform admin removed. Never a reason to retry. */
export class PlatformUnauthorized extends Error {
  constructor() {
    super('platform admin session ended');
    this.name = 'PlatformUnauthorized';
  }
}

const BASE = '/api/v1/platform';

async function request<T>(method: string, path: string, { token, body, headers = {} }: { token?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<ApiResult<T>> {
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store',
  });
  if (response.status === 401 && token) throw new PlatformUnauthorized();
  if (response.status === 204) return { ok: true, value: undefined as T };
  const text = await response.text();
  const json = text ? (JSON.parse(text) as unknown) : undefined;
  if (response.ok) return { ok: true, value: json as T };
  const refusal = (json && typeof json === 'object' ? json : {}) as Partial<ApiError>;
  return {
    ok: false,
    error: { ...refusal, status: response.status, error: refusal.error ?? 'request', message: refusal.message ?? `${response.status} ${response.statusText}` },
  };
}

const slugPath = (slug: string) => `/tenants/${encodeURIComponent(slug)}`;

/** Sign-in: not authenticated, so a 401 here is an answer ("not a platform admin"), not a lost session. */
export const platformAuth = {
  challenge: (address: string, chainId: number) => request<{ message: string }>('POST', '/auth/challenge', { body: { address, chainId } }),
  verify: (message: string, signature: string) => request<SignedInAdmin>('POST', '/auth/verify', { body: { message, signature } }),
  logout: (token: string) => request<void>('POST', '/auth/logout', { token }),
};

/** Every authenticated platform admin route the console uses, bound to one session token. */
export function platformApi(token: string) {
  const call = <T>(method: string, path: string, body?: unknown, headers?: Record<string, string>) => request<T>(method, path, { token, body, headers });
  return {
    list: (status?: TenantStatus) => call<{ tenants: TenantSummary[] }>('GET', `/tenants${status ? `?status=${status}` : ''}`),
    detail: (slug: string) => call<TenantDetail>('GET', slugPath(slug)),
    create: (input: TenantCreateInput) => call<{ tenant: PlatformTenant; adminKeys: IssuedAdminKey[] }>('POST', '/tenants', input),
    update: (slug: string, version: number, patch: TenantPatchInput) => call<PlatformTenant>('PATCH', slugPath(slug), patch, { 'if-match': `"${version}"` }),
    suspend: (slug: string, reason: string) => call<PlatformTenant>('POST', `${slugPath(slug)}/suspend`, { reason }),
    resume: (slug: string) => call<PlatformTenant>('POST', `${slugPath(slug)}/resume`),
    remove: (slug: string) => call<void>('DELETE', slugPath(slug)),
    issueKey: (slug: string, label: string) => call<IssuedAdminKey>('POST', `${slugPath(slug)}/admin-keys`, { label }),
    revokeKey: (slug: string, keyId: string) => call<void>('DELETE', `${slugPath(slug)}/admin-keys/${encodeURIComponent(keyId)}`),
    history: (slug: string, before?: string) =>
      call<{ entries: HistoryEntry[]; next: string | null }>('GET', `${slugPath(slug)}/history${before ? `?before=${encodeURIComponent(before)}` : ''}`),
    admins: () => call<{ admins: PlatformAdminRow[] }>('GET', '/admins'),
    addAdmin: (id: string, address: string) => call<PlatformAdminRow>('POST', '/admins', { id, address }),
    removeAdmin: (id: string) => call<void>('DELETE', `/admins/${encodeURIComponent(id)}`),
    platformAdminHistory: () => call<{ entries: PlatformAdminHistoryEntry[] }>('GET', '/admins/history'),
  };
}

export type PlatformApi = ReturnType<typeof platformApi>;

/** A platform admin, as GET /v1/platform/admins lists them. */
export type PlatformAdminRow = { id: string; address: string; addedBy: string; createdAt: string };
export type PlatformAdminHistoryEntry = { id: string; adminId: string; address: string; action: 'bootstrap' | 'add' | 'remove'; actor: string; createdAt: string };
