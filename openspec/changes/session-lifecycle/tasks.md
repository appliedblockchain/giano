## 1. wallet-api: session core (PR 1)

- [x] 1.1 Migration `0011_session_lifecycle.sql`: add `sessions.last_used_at timestamptz NOT NULL DEFAULT now()`, backfill it from `created_at`, add the partial indexes `sessions_user_live_idx ON sessions (user_id, last_used_at) WHERE revoked_at IS NULL` and `sessions_wallet_live_idx ON sessions (lower(wallet_address)) WHERE revoked_at IS NULL`, and extend the `tenant_history.action` CHECK with `user-sessions-revoke`. Mirror all of it in `db/schema.ts` (column, index, `tenantHistoryActions`) and update `test/migrations.test.ts`. If the A1 stack (#210, `0010_usage_indexes`) has not merged, note the dependency in the PR.
- [x] 1.2 `config.ts`: add `SESSION_IDLE_TIMEOUT_SECONDS` (default 3600, ≥ 300, ≤ `SESSION_TTL_SECONDS`) and `SESSION_MAX_PER_USER` (default 10, ≥ 1), with doc comments, and make `loadConfig` refuse values out of bounds and name the variable. Add both to the wallet-api README env reference, `specs/DEVELOPER-GUIDE.md` and `deploy/docker-compose.reference.yml`, next to `SESSION_TTL_SECONDS`.
- [x] 1.3 `services/sessions.ts`: pass the idle timeout and the cap to `createSessionService`. Add the idle predicate to `resolve()`, and the guarded 60-second `touch()` that `requireSession` calls once the request has passed its tenant checks (design D1). Turn `create()` into the lock-insert-trim transaction (D3).
- [x] 1.4 `services/sessions.ts`: add `revokeLive({ tenantId, selector })` for `userId`, `externalUserId` and `walletAddress` (lowercase compare), returning the count, live sessions only and scoped to the tenant (D4). Rebuild `revokeAllForUser` on it and keep `revokeAllForCredential`'s behavior.
- [x] 1.5 `routes/credentials.ts`: add `POST /v1/sessions/logout-all` behind the session check, answering `{ ok: true, revoked }`. Leave `logout` as it is.
- [x] 1.6 `app.ts`: drop `credentials: true` from the CORS registration (D5).
- [x] 1.7 Tests (in a session-lifecycle test file, with the existing Postgres harness) for every scenario in `specs/wallet-sessions/spec.md` from the first four requirements and the CORS one: token not stored, removed credential, idle accept and refuse (backdate `last_used_at`), absolute expiry not extended, touch written at most once a minute, invalid configuration, the cap including concurrent sign-ins and dead sessions not counting, logout-all, other users unaffected, the identical 401 bodies, and a preflight and response without `Access-Control-Allow-Credentials`.
- [x] 1.8 Regenerate `openapi/openapi.json`. Run `pnpm -F @appliedblockchain/giano-wallet-api test`, its typecheck and `pnpm lint`.

## 2. wallet-api: admin revocation and history (PR 2)

- [x] 2.1 `services/tenants.ts` `getByAdminKeyHash` also returns the key id. `plugins/auth.ts` decorates `request.adminKeyId` and `requireAdmin` sets it.
- [x] 2.2 A shared helper that runs `revokeLive` and appends the `user-sessions-revoke` history entry in one transaction: actor, null before and after, detail `{ selector, value, revoked }`, and the platform admin session when there is one.
- [x] 2.3 `routes/admin.ts`: `POST /v1/admin/sessions/revoke` behind `requireAdmin`. The body takes exactly one of `externalUserId` or `walletAddress` (a 20-byte hex address), else 400. It answers `{ revoked }`.
- [x] 2.4 `routes/platform-tenants.ts`: `POST /v1/platform/tenants/:slug/sessions/revoke` with the module's platform route options and slug resolution. It works for suspended tenants, answers 404 like the other routes for an unknown slug, and refuses a deleted tenant with 409 `invalid-transition`.
- [x] 2.5 Tests for every scenario of the two revocation requirements in `specs/wallet-sessions/spec.md` and the new scenarios in `specs/tenant-administration/spec.md`: stolen phone, by wallet in mixed case, another tenant's user (`revoked: 0` and their sessions still work), repeated, both or neither selector, a suspended tenant, a tenant key on the platform route, `Origin` refused, and the history entry's shape for both actors.
- [x] 2.6 Regenerate OpenAPI. Run the wallet-api suite, its typecheck and lint.

## 3. Client: wallet-core and wallet-kit (PR 3)

- [x] 3.1 wallet-core: add `SessionEndedError` (a `GianoError` with code 4100) and export it. In `create-wallet-api-injection.ts`, add `endSession()`, end the session on a 401 to an authenticated `api()` call, and expose `onUnauthorized()` and `logoutAll()` (D7). The interface and any test doubles of the injection gain both.
- [x] 3.2 wallet-core: `management/api.ts` and `paymaster/erc7677-client.ts` take an optional `onUnauthorized`, call it on a 401 to a request that carried the token, and throw `SessionEndedError`. A 401 without a token, and other statuses, keep today's behavior.
- [x] 3.3 wallet-kit: `sessionHttp` calls `onUnauthorized` on a 401 when it attached a token. Wire `onUnauthorized` into the management API and paymaster client. The management controller resets to signed-out on any session change to none, with a `sessionEnded` flag, and gains `logoutAll()`, which reports whether the server call succeeded.
- [x] 3.4 Unit tests for every scenario in `specs/wallet-session-client/spec.md` that the libraries cover: a 401 on each of the four clients ends the session and clears storage; 429 and 503 keep it; a 401 without a token does not end it; `logoutAll` clears the session locally when the call fails; the provider surfaces 4100 to a dApp.
- [x] 3.6 wallet-kit: a pending request gains `sessionEnded()`, which answers the dApp 4100 instead of 4001, for a review screen whose pre-flight reports the session ended. Test it in the request store. (Found while building 4.2: approve and reject alone could only answer 4001.)
- [x] 3.5 Add a changeset for `@appliedblockchain/giano-wallet-core` and `@appliedblockchain/giano-wallet-kit` (minor: new API; note the new 401 behavior). Run their tests, typecheck and lint.

## 4. wallet-web (PR 3)

- [x] 4.1 `views/Manage.tsx`: add "Sign out everywhere" next to the existing sign-out, with a line explaining that it signs out every device. If the server call failed, say that other devices may still be signed in.
- [x] 4.2 When the controller reports `sessionEnded`, show the sign-in state with a "Your session ended. Sign in again." message instead of an error, in Manage and in the review views.
- [x] 4.3 Typecheck, lint and build wallet-web.

## 5. e2e

- [x] 5.1 Sign out everywhere: sign in on two browser contexts as the same user, pick "Sign out everywhere" in one, and check that the other's next management action shows the session-ended state.
- [x] 5.2 Admin revocation: with the e2e tenant admin key, revoke the signed-in user by `externalUserId` through `/v1/admin/sessions/revoke`, and check that the wallet returns to sign-in on its next action. Check the history entry through the platform route.
- [x] 5.3 Re-run `wallet-flow`, `wallet-management`, `byo-wallet` and `tenant-isolation`, then the full suite.

## 6. Docs and wrap-up

- [x] 6.1 `specs/ARCHITECTURE.md`: describe the session model (absolute and idle expiry, cap, sign-out everywhere, admin revocation) and record the R5 decision and its XSS trade-off from design D6.
- [x] 6.2 BYO-wallet guidance (`specs/INTEGRATION.md` or `specs/DEVELOPER-GUIDE.md`, wherever the injection contract is documented): treat a 401 as the end of the session, and know that CORS carries no credentials.
- [ ] 6.3 Run `openspec validate session-lifecycle --strict`. Open the PRs as a `gh stack` (PR 1 → PR 2 → PR 3) with titles ending `(G5)`, and update the G5 Notion ticket with the PR links.
