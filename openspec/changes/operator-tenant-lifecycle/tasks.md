## 1. Migration and data model (D2)

- [x] 1.1 Write `services/wallet-api/migrations/0007_tenant_lifecycle.sql` per spec §5.2, with header comments in the style of `0006_tx_mappings.sql`. It adds:
  - to `tenants`: `status`, `managed_by`, `version` and `status_changed_at`, with their CHECKs and `tenants_status_idx`;
  - to `tenant_admin_keys`: `created_by`;
  - the tables `operator_challenges` (including `message`), `operator_sessions` and `tenant_history`, with their indexes.
- [x] 1.2 Mirror the migration in `src/db/schema.ts` (new columns, three tables, `Tenant` type) and confirm the migration runner applies it on a fresh and on a populated database.
- [x] 1.3 Add the challenge housekeeping interval to `src/index.ts`, next to the prober and unref'd. It calls `challenges.prune()` and deletes `operator_challenges` that expired more than a day ago; clear it in `shutdown` (design D12).

## 2. Single validator and origin claims (D3)

- [x] 2.1 Split `tenantSeedSchema` in `src/services/tenants.ts` into `tenantFieldsSchema` (`.strict()`), `checkTenantInvariants(fields, { adminKeyCount })`, `tenantSeedSchema`, `tenantCreateSchema` and `tenantPatchSchema` (design D3). Keep the seed transform (`rpId` default, `walletOrigin` in `expectedOrigins`) and apply the same normalisation on create.
- [x] 2.2 Implement `checkOriginClaims(tx, { selfId, claims })`. It takes `pg_advisory_xact_lock(hashtext('giano:tenant-origin-claims'))` and returns the clashing origin and slug, across every status (design D4).
- [x] 2.3 Map unique violations on `slug`, `wallet_origin`, `rp_id` and `tenants_pkey` to a typed conflict error naming the field (spec §6.3).
- [x] 2.4 Rework `seedTenants` (design D8). For each entry:
  - read the existing row `FOR UPDATE`;
  - refuse a deleted slug;
  - call `checkOriginClaims`, with a boot error naming the origin, the other slug, its `managed_by` and its `status`;
  - take over operator-managed rows;
  - increment `version` and append `create`, `seed-apply` or `seed-takeover` history only when something changed;
  - never touch `status`.
- [x] 2.5 Add the cross-entry `expectedOrigins` and `walletOrigin` overlap check to `tenantsSeedSchema`, so that two overlapping seed entries fail in `loadConfig` and name both tenants.
- [x] 2.6 Update the header comment of `tenants.ts`: every write, seed or operator, passes through `checkTenantInvariants` and `checkOriginClaims`.
- [x] 2.7 Tests in `test/tenants.test.ts`:
  - each invariant (rpId mismatch, expected origin outside the RP ID, closed tenant without keys, unknown field);
  - seed overlap refusing boot;
  - the deleted origin still claimed;
  - concurrent claims, giving exactly one winner;
  - every row of the spec §9 table;
  - no history row on an idle restart;
  - two concurrent `seedTenants` runs writing one `seed-apply`.

## 3. Lifecycle-aware resolution

- [x] 3.1 Add `status = 'active'` to `getByOrigin`, `getByHost`, `getByAdminKeyHash` and `isCorsOrigin`. Replace `getById` with `getActiveById` and `getByIdAnyStatus` and update every call site (design D5).
- [x] 3.2 Change `requireSession` in `src/plugins/auth.ts` to use `getActiveById` and return the generic `401` when it is null.
- [x] 3.3 Tests for a suspended tenant (spec `tenant-lifecycle`, "Only active tenants resolve"):
  - an Origin ceremony returns 403;
  - the well-known document by Host returns 404;
  - its admin key returns 401;
  - an existing session returns 401, with and without an Origin;
  - its CORS origin gets no grant;
  - after resume, the same session works again;
  - the watcher still settles for it.

## 4. Operator sign-in, sessions and guard (D1)

- [x] 4.1 Add to `src/config.ts`: `OPERATOR_ADDRESSES` (JSON, ids and addresses unique, lowercase addresses), `OPERATOR_SIWE_DOMAIN` (required when the list is non-empty), `OPERATOR_SIWE_URI`, `OPERATOR_CHALLENGE_TTL_SECONDS`, `OPERATOR_SESSION_TTL_SECONDS`, `OPERATOR_RATE_LIMIT_PER_MINUTE` and `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS`. The last must be greater than `PAYMASTER_WATCHER_CONFIRMATIONS`.
- [x] 4.2 Write `src/services/operator-sessions.ts`:
  - `issueChallenge`: builds the message with `viem/siwe`, and stores the nonce, address, message and expiry for a listed address only;
  - `verify`: parse, ECDSA recovery, list check, then atomic consume matching the stored text (design D2);
  - `createSession`: `gos_` token, sha256 stored;
  - `resolve` and `revoke`.
- [x] 4.3 Add `requireOperator` to `src/plugins/auth.ts`, in this order: Origin refused with `403 operator-origin-refused`; bearer token hash looked up as unrevoked and unexpired; address still configured; then `request.operator = { id, address, sessionId }` and a child logger with `operator: id`. Add the generic 401 body and the `giano_operator_auth_failures_total{reason}` counter in `plugins/metrics.ts`.
- [x] 4.4 Write `src/routes/operator-auth.ts` with `challenge`, `verify` (Origin check only) and `logout` (full guard). Rate limits follow design D10.
- [x] 4.5 Register the operator plugin and routes in `src/app.ts` only when `OPERATOR_ADDRESSES` is non-empty, and add the `operatorSession` security scheme. Update the `adminKey` scheme description so it no longer says the key comes only from `TENANTS_SEED`.
- [x] 4.6 Write `scripts/operator-login.ts` and the `operator:login` script in `package.json`. It takes `--api <url>` and `OPERATOR_PRIVATE_KEY`, runs challenge and verify, and prints the token.
- [x] 4.7 Tests in `test/operator-auth.test.ts`, one per scenario in spec `operator-authentication`:
  - a valid sign-in;
  - each altered field, re-signed, returning 401;
  - replay, an expired challenge, a wrong signer and an unlisted address, all with identical 401 bodies;
  - the unlisted challenge storing nothing;
  - concurrent verify;
  - an Origin refused on every route;
  - a tenant key on operator routes and an operator token on admin routes;
  - expired, revoked and de-listed sessions;
  - an empty list giving 404;
  - duplicate config refusing boot;
  - logout;
  - per-session rate limit.

## 5. Operator tenant routes (D4)

- [x] 5.1 Write `src/routes/operator-tenants.ts` with `requireOperator` and the read routes: `GET /v1/operator/tenants?status=` (newest first, deleted excluded by default) and `GET /v1/operator/tenants/:slug` (fields, `managedBy`, `status`, `version`, keys without material, user and credential counts, last userop time, per-chain ledger position).
- [x] 5.2 Create: `POST /v1/operator/tenants`. In one transaction: validate, claim origins, insert as active and operator-managed, generate `gak_` keys, and append `create` history. Return 201 with the plaintext keys once.
- [x] 5.3 Update: `PATCH /v1/operator/tenants/:slug`. Handle `If-Match` with 428 and 412, return 422 for immutable fields and 409 `seed-managed`, then merge, validate, claim origins, increment `version`, and append `update` history.
- [x] 5.4 Lifecycle: `POST …/suspend` (reason required), `POST …/resume` and `DELETE …`. Each takes a row lock and checks the source state, returning 409 `invalid-transition`. Delete applies the preconditions in design D7: heads read before the transaction, then not-suspended, seed-managed, has-funds with figures, has-reservations (unexpired only) and ledger-stale. The tombstone removes sessions through `users`, plus challenges, `pending_additions` and admin keys.
- [x] 5.5 Admin keys: `POST …/admin-keys` (active and operator-managed only) and `DELETE …/admin-keys/:keyId` (409 `last-admin-key` when `openRegistration` is false), each with history detail (key id, label, hash prefix).
- [x] 5.6 `POST …/adopt` (409 `still-seeded` while the slug is in the running `TENANTS_SEED`) and `GET …/history?before=` (newest first, 50 per page, `next` cursor).
- [x] 5.7 Tests in `test/operator-tenants.test.ts`, one per scenario in specs `tenant-administration` and `tenant-lifecycle`. They include:
  - concurrent creates and concurrent suspends;
  - every delete precondition, including an expired-but-unswept reservation;
  - delete with no ledger rows;
  - the after-delete state;
  - writes to seed-managed tenants returning 409, and suspend and resume returning 200;
  - attribution on every write;
  - create-then-resolve in the same process.
- [x] 5.8 Run `pnpm -F @appliedblockchain/giano-wallet-api openapi` and commit `openapi/openapi.json`; confirm `openapi:check` passes.

## 6. E2E

- [x] 6.1 In `deploy/docker-compose.e2e.yml`, give `wallet-api` an anvil account in `OPERATOR_ADDRESSES`, `OPERATOR_SIWE_DOMAIN=paymaster.localhost` and `OPERATOR_SIWE_URI=http://paymaster.localhost`.
- [x] 6.2 Write `e2e/tests/operator.spec.ts`. It signs in in-process with viem and the anvil key, then covers spec §14.2 steps 1 and 2:
  - suspend `byo`, so connecting from `app-byo.localhost` fails; resume it, so connecting succeeds, with `stock` unaffected throughout;
  - create `runtime`, and check that `/.well-known/webauthn` with `Host: wallet-runtime.localhost` returns its document with no restart.

## 7. Docs and wrap-up

- [x] 7.1 Update the docs:
  - `specs/ARCHITECTURE.md`: an operator row in the *decided from* table;
  - `specs/DEVELOPER-GUIDE.md` §1: tenants come from the seed or from operators;
  - `services/wallet-api/README.md`: the new environment variables and `operator:login`;
  - `specs/OPERATOR-ADMIN-SPECS.md` §13: tick D1–D4.
- [x] 7.2 Run `pnpm -F @appliedblockchain/giano-wallet-api typecheck`, `test` and `openapi:check`, and the E2E suite, and record the results in the PR.
- [x] 7.3 Update the PR #125 description checklist, and list the pre-deploy items for devops: O-8 (seed secret check) and O-3 (environment and `/v1/operator/*` restriction).
