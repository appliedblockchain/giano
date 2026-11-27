## Why

A wallet session is the bearer token a wallet sends to wallet-api after a passkey ceremony (G5, production readiness report item B6). It cannot move funds on its own, but it gives the user's identity and credential list, relays signed operations, and spends the tenant's sponsorship and RPC budgets. Today one token stays valid for a fixed 24 hours however it is used. Nobody can end all of a user's sessions: not the user, not the tenant, not Giano. A script can also pile up any number of valid tokens. The lifecycle is the control that makes a stolen token stop working, so it has to be in place before 1.0.

## What Changes

- **Idle timeout.** A session that goes unused for `SESSION_IDLE_TIMEOUT_SECONDS` (default 3600) stops resolving, as well as at its absolute expiry (`SESSION_TTL_SECONDS`, unchanged at 24h). wallet-api records when each session was last used, writing at most once a minute per session.
- **Sign out everywhere.** New `POST /v1/sessions/logout-all`: a signed-in user revokes every session they hold, the calling one included.
- **Admin revocation.** A tenant admin key can revoke the sessions of one of its own users (`POST /v1/admin/sessions/revoke`), and a platform admin can do the same for any tenant's user (`POST /v1/platform/tenants/:slug/sessions/revoke`). The user is selected by `externalUserId` or by wallet address. Both write a tenant history entry.
- **Live sessions per user are capped.** `SESSION_MAX_PER_USER` (default 10): a new sign-in that would go over the cap revokes the user's oldest live sessions.
- **CORS no longer allows credentials.** `credentials: true` is removed. Authentication uses bearer headers only, and nothing in the repo sends credentialed requests.
- **The client treats a 401 as the end of the session.** wallet-core's injection clears the stored token and signals that the session ended, instead of keeping a dead token and throwing a generic error. Every client that sends the session (wallet-api calls, the management API, the paymaster client, the bundler and RPC transport) goes through the same path. The injection gains `logoutAll()`, and wallet-web's Manage view offers "Sign out everywhere".
- **R5 decision: the token stays a bearer token in `localStorage`** on the wallet origin. The decision and its XSS trade-off are recorded in `design.md` and `specs/ARCHITECTURE.md`. An HttpOnly cookie would make every BYO wallet and every cross-origin `walletApiUrl` proxy `/api` same-origin and would change the injection contract. The wallet origin's CSP (report item X3) is the mitigation.
- **BREAKING (behavior):** a wallet left unused for an hour needs a passkey sign-in again. Wallets that send a session on a request wallet-api answers with 401 lose that session client-side.

**Non-goals.**
- A purge job for expired and revoked sessions: that is database retention, ticket G34 (report item O9).
- A console UI for revocation: support tooling, report item A6.
- An idle timeout per tenant. It can live in `tenants.policy` later if a tenant asks for one.
- Idle timeout for platform-admin sessions: the A1 work (#207) owns them.
- A "your sessions" list for wallet users.
- Moving the token to a cookie.

## Capabilities

### New Capabilities
- `wallet-sessions`: wallet-api's wallet sessions. Covers how they are issued, the absolute and idle expiry, the per-user cap, sign-out (one or every session), revocation by a tenant admin key or a platform admin, and the CORS stance of bearer auth.
- `wallet-session-client`: how the wallet client (wallet-core injection, wallet-kit, wallet-web) stores the session, reacts when wallet-api ends it, and offers sign-out everywhere.

### Modified Capabilities
- `tenant-administration`: the tenant history also records revocations of a user's sessions, with a new action and a new actor form for tenant admin keys.

## Impact

- **wallet-api:** migration `0011` adds `sessions.last_used_at` and a live-session index, and extends the `tenant_history` action check. Changes `services/sessions.ts` (idle check, touch, cap, revoke by user or wallet), `plugins/auth.ts` (`requireAdmin` exposes the key id), `routes/credentials.ts` (logout-all), `routes/admin.ts` and `routes/platform-tenants.ts` (revocation), `app.ts` (CORS), `config.ts` (two new variables), OpenAPI and tests. It stays `0011` whichever of it and the A1 stack's `0010_usage_indexes` (#210) merges first: the runner applies unapplied files in filename order, and the two are independent.
- **wallet-core:** `create-wallet-api-injection.ts`, `management/api.ts`, `paymaster/erc7677-client.ts` and the session transport in wallet-kit's `runtimes.ts` all react to a 401 the same way. New `logoutAll()` and a typed session-ended error. Changeset for `@appliedblockchain/giano-wallet-core` and `@appliedblockchain/giano-wallet-kit`.
- **wallet-web:** `views/Manage.tsx` gets "Sign out everywhere". A session that ends mid-flow returns the user to sign-in.
- **e2e:** new cases for sign-out everywhere and admin revocation as the user sees them. The idle timeout is covered in wallet-api's database tests by backdating `last_used_at`, because its 300-second minimum is too slow for e2e.
- **Docs:** `specs/ARCHITECTURE.md` (session model and R5), the wallet-api README and env reference.
- **Overlaps:** #220, #221, #224 and #200 add settings to `config.ts` or edit `webauthn.ts`, which means code-level conflicts only.
