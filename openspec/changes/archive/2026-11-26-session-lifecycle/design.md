## Context

See proposal.md for the motivation. Wallet sessions today (all on `main`):

- `services/wallet-api/src/services/sessions.ts`: `create`, `resolve`, `revoke`, `revokeAllForUser` (never called) and `revokeAllForCredential`. `resolve` is one indexed lookup by `token_hash` joined to `users`, with `revoked_at IS NULL AND expires_at > now()`.
- `plugins/auth.ts`: `requireSession` resolves the token, then checks the tenant against the `Origin`. `requireAdmin` resolves a tenant admin key by hash, and `getByAdminKeyHash` returns the tenant but not the key id.
- The `sessions` table has no tenant column (a session's tenant is its user's) and no `last_used_at`. Its indexes are on `user_id`, `expires_at` and `credential_id`.
- Client: `createWalletApiInjection` holds the token, and `onSessionChanged` lets wallet-kit persist it in `localStorage`. Its `api()` throws `Error("wallet-api <path> failed: <message>")` on any non-2xx and keeps the token. Three other clients send the token on their own: `management/api.ts`, `paymaster/erc7677-client.ts` and wallet-kit's `sessionHttp` viem transport, which carries the bundler and RPC relay.
- wallet-web's Manage view has "Log out (revoke session)", which calls `injection.logout()`.
- Platform-admin sessions live in a separate table and service and are out of scope. #207 (A1 stack, open) adds listing and ending them, and this design copies its rules: ending something already ended succeeds and changes nothing, and only live sessions count.

## Goals / Non-Goals

**Goals:**
- Keep `resolve()` to one indexed read on the hot path, plus at most one write per session per minute.
- One way to end a session on the client, whichever request found out.
- Revocation that a tenant can do on its own, without Giano.

**Non-Goals:**
- Rotating or refreshing tokens. Once a session goes idle, the user signs in with a passkey again. That is the control.
- Device names or user agents on sessions. They would come with a "your sessions" list, which is not part of this change.

## Decisions

### D1. Idle check in SQL, touch throttled by a guarded UPDATE
`resolve()` adds `last_used_at > now() - make_interval(secs => $idle)` to its `WHERE`. A session idle too long fails the same predicate as an expired one and gets the same 401. `resolve()` writes nothing: it says whether a refresh is due, and `requireSession` calls `touch()` only after the cross-tenant and suspended-tenant checks pass, so a request wallet-api refuses never keeps a session from going idle. `touch()` is:
`UPDATE sessions SET last_used_at = now() WHERE id = $1 AND last_used_at < now() - interval '60 seconds'`.
It writes only when the stored value is more than a minute old, so a busy session costs one write a minute. Concurrent requests race harmlessly: the guard makes the second update a no-op.
The new column is `last_used_at timestamptz NOT NULL DEFAULT now()`. The migration sets it to `created_at` for existing rows, so sessions issued before the deploy go idle an hour after issue. That is the safe direction.
- *Alternative:* compute idle from the most recent `userop_log` or request log. Rejected: not every authenticated call writes a log row, and it would make the hot path read a growing table.
- *Alternative:* touch in an `onResponse` hook. Rejected: the touch would land after the response, so a failed write would be invisible, and it needs a second resolve.
- *Alternative:* a sliding `expires_at`. Rejected: one column would then mean both "absolute" and "idle", and the absolute cap must never move.

### D2. One idle timeout for the deployment, from configuration
`SESSION_IDLE_TIMEOUT_SECONDS` (default 3600, minimum 300, at most `SESSION_TTL_SECONDS`) is a wallet-api environment variable. `loadConfig` enforces the bounds. A per-tenant override (`tenants.policy.sessionIdleTimeoutSeconds`) is left for later: it would also need validation in the tenant writer and a console field, and no tenant has asked for it. Because `resolve()` already joins `users`, the override can be added later by joining `tenants` too, with no change to the spec's other requirements.
Why 60 minutes: an operation that moves funds needs a passkey signature anyway, so an expired session costs one extra passkey prompt before the signing prompt. 60 minutes covers a normal dApp visit. 30 minutes would interrupt users reading a long review.

### D3. Cap enforced at issue, in the same transaction
`create()` becomes a transaction:
1. `SELECT … FROM users WHERE id = $user FOR UPDATE`. This serialises concurrent sign-ins of one user, so two of them cannot both see 9 live sessions and insert. The lock is on a row that is otherwise only read.
2. Insert the new session.
3. Revoke the live sessions beyond the newest `SESSION_MAX_PER_USER`, ordered by `last_used_at DESC, created_at DESC`.

"Live" uses the same predicate as `resolve()`, so idle and expired sessions never count and are never touched. A partial index `sessions_user_live_idx ON sessions (user_id, last_used_at) WHERE revoked_at IS NULL` keeps step 3 and the revocations by user cheap, and `sessions_wallet_live_idx ON sessions (lower(wallet_address)) WHERE revoked_at IS NULL` does the same for an admin revoking by wallet, which matches ignoring case. Both indexes leave out revoked rows only. An expired or idle session stays in them until retention (G34) deletes it, and the query's `live()` predicate filters it out: a small cost, bounded by one user's or one wallet's sessions.
- *Alternative:* refuse the new sign-in at the cap. Rejected: it locks out the legitimate user, which is exactly what a script holding 10 tokens would want.

### D4. Revocation is one service method with two selectors
`revokeLive({ tenantId, selector })` with `selector = { userId } | { externalUserId } | { walletAddress }`. It updates the live sessions matching the selector within the tenant (joining `users` for `tenant_id`) and returns the count. `revokeAllForUser` becomes `revokeLive({ userId })`. The wallet selector compares `lower(sessions.wallet_address) = lower($1)`. The input is validated as a 20-byte hex address first, so an obviously malformed address gets a 400 instead of a silent 0.

Routes:
- `POST /v1/sessions/logout-all` in `routes/credentials.ts`, next to `logout`, behind `requireSession`. It answers `{ ok: true, revoked }`.
- `POST /v1/admin/sessions/revoke` in `routes/admin.ts`, behind `requireAdmin`. To attribute the history entry, `getByAdminKeyHash` also returns the key id, and `requireAdmin` sets `request.adminKeyId`. That adds one field to the request decoration and no extra query.
- `POST /v1/platform/tenants/:slug/sessions/revoke` in `routes/platform-tenants.ts`, with the module's existing `route` options (`requirePlatformAdmin`) and slug resolution. Suspended tenants are allowed, because suspension already blocks their sessions and revoking is still useful before a resume. A deleted tenant has no sessions left (delete removes them), so it is refused with `409 invalid-transition`, the same refusal suspend and resume give for a state that doesn't allow them. Recording a `revoked: 0` entry against a tombstone would only add noise to its history.

The revocation and its `tenant_history` entry are written in one transaction. The history `action` CHECK constraint gains `user-sessions-revoke`, and `tenantHistoryActions` in the schema gains it too. The entry leaves `before` and `after` null and puts `{ selector, value, revoked }` in `detail`. Its actor is `tenant-admin-key:<keyId>` or the existing `platform-admin:<id>:<address>`.
- *Alternative:* select the user through a path parameter (`/users/:externalUserId/sessions`). Rejected: `externalUserId` is free-form tenant text (G32), so it would need URL-encoding, and revoking by wallet is the more useful action after a stolen device, because it covers every owner credential of the wallet.
- *Alternative:* record revocations only in logs. Rejected: R3 is a security action, and the tenant history is the audit trail operators already read.

### D5. CORS drops credentials and nothing else
`app.ts` drops `credentials: true`. `@fastify/cors` keeps reflecting the requested headers, so `authorization` still passes preflight. A wallet-api test asserts that `Access-Control-Allow-Credentials` is absent on a preflight and on an actual response.

### D6. R5: the token stays a bearer token in `localStorage`
Considered: an HttpOnly, `SameSite=Strict`, `Path=/api` cookie set by wallet-api through wallet-web's same-origin `/api` proxy.
- **For the cookie:** script on the wallet origin cannot read the token, so an XSS cannot take it away to use from elsewhere.
- **Against:** an XSS on the wallet origin can still make same-origin requests that carry the cookie while the page is open, so it still gets the session's power, just not a portable copy. A cookie only works same-origin: every BYO-wallet tenant and every deployment that sets `GIANO_WALLET_API_URL` to another origin would have to add a same-origin proxy. The injection contract (`sessionToken`, `onSessionChanged`, `getSessionToken`) is public in `@appliedblockchain/giano-wallet-core`, and the paymaster client and viem transport would have to stop sending headers. It would also bring CSRF back as a concern, and `credentials: true` with it.
- **Decision:** keep the bearer token in `localStorage`. What makes theft costly is the lifecycle in this change: idle expiry, the cap and revocation, together with the passkey on every fund movement. The mitigation for XSS is the wallet origin's CSP (report item X3), which is tracked separately. The decision and this trade-off go into `specs/ARCHITECTURE.md` under the session model.

### D7. The client ends the session at one point
The injection gains an internal `endSession(reason)`. It sets the token to null and calls `onSessionChanged(null)`. Then:
- `api()` checks `response.status === 401 && init.auth`, calls `endSession`, and throws a `SessionEndedError`. That error is exported from wallet-core, with `code: 4100` so the EIP-1193 provider surfaces it as "Unauthorized", which a dApp can tell apart from 4001 "User rejected".
- The injection exposes `onUnauthorized(token?)` for the other clients. Given the token the refused request carried, it calls `endSession` only if that token is still current, so a late 401 for a token a new sign-in replaced ends nothing. `api()` applies the same check. `management/api.ts` and `erc7677-client.ts` already receive the injection's token getter, and they receive `onUnauthorized` next to it.
- Only wallet-api gets the token, and only wallet-api's 401 ends the session. A bundler or sponsorship service configured on another origin could otherwise read the session and sign the user out with a 401 of its own (a missing API key, say). The injection exposes `isWalletApiUrl(url)` (same origin as `apiUrl`, under its path) and `sessionFetch`, a fetch that attaches the token to wallet-api URLs only and calls `onUnauthorized` on their 401. wallet-kit's `sessionHttp` passes `sessionFetch` to viem's `http` as `fetchFn`. The paymaster client takes `sessionEndpoint`, which wallet-kit sets from `isWalletApiUrl(paymasterServiceUrl)`: without it, the client sends no token and reads a 401 as a refusal, as before this change. The host maps an HTTP 401 to 4100 only when viem reports a wallet-api URL with it.
- `logoutAll()` calls `POST /v1/sessions/logout-all`. Whatever the result, it then calls `endSession("logout-all")`, and it returns whether the server call succeeded, so the UI can say that other devices may still be signed in.

wallet-kit's management controller already has `resetToSignedOut()`. It subscribes to the session change, so any ended session (not only an explicit logout) resets the controller, with a `sessionEnded` flag that wallet-web turns into a message.
- *Alternative:* retry with a silent re-authentication. Rejected: there is none. Signing in needs a passkey, so the user has to act.

## Risks / Trade-offs

- [Users leaving a tab open longer than an hour get an extra passkey prompt] → The prompt is one tap. The default is configurable per deployment, and a per-tenant override is ready to add (D2).
- [The migration ages existing sessions: they idle out an hour after issue] → Intended. Users sign in again at most once. Called out in the release notes.
- [The `FOR UPDATE` on `users` serialises a user's concurrent sign-ins] → Sign-ins are human-paced and the lock lasts one short transaction.
- [Clients built before this change keep a dead token after a 401 and show a generic error] → Unchanged from today's behavior after expiry. The fix ships in the wallet-core and wallet-kit release, and the BYO-wallet docs say to treat a 401 as the end of the session.
- [Expired and revoked rows still accumulate] → Retention is G34. The partial indexes leave out revoked rows; expired and idle rows stay in them until G34, filtered by the query.
- [Migration number clash with the A1 stack's `0010_usage_indexes`] → This change uses `0011` and keeps it, whichever merges first. The runner applies every unapplied file in filename order, so a `0010` that arrives later is still applied, and the two are independent (an index on another table). The migration test checks the list.

## Migration Plan

1. Deploy wallet-api: the migration runs at start (adds the column, backfills it from `created_at`, adds the index, extends the CHECK constraint). It is additive, and old code ignores the column.
2. New wallet-api answers no CORS credentials header. No Giano client uses credentials, and BYO wallets are told in the release notes.
3. Publish wallet-core and wallet-kit with the changeset, then deploy wallet-web.
4. Rollback: redeploying the previous wallet-api is safe. The extra column and index are ignored, and history entries with the new action stay readable as text. The CHECK constraint keeps accepting the new action until a later migration removes it.

