## Context

The full technical spec is `specs/PLATFORM-ADMIN-SPECS.md`, revised 2026-10-21 against `main` at `5f0ce0e`. This document records the decisions that shape the code and points to that spec for detail. The motivation is in proposal.md, and the behaviour is in this change's `specs/`.

These facts about today's code shape the approach (spec §3):

- **Per-request resolution.** Tenants are resolved per request from Postgres, and `buildApp` never reads `tenants`. That is why a runtime write takes effect at once, with no restart. This change must not add a tenant cache.
- **Five resolvers decide tenant identity.** They are `getByOrigin`, `getByHost`, `getByAdminKeyHash`, `getById` and `isCorsOrigin`, all in `createTenantService`. The watcher's slug cache reads the table directly and is unaffected.
- **The seed schema is not built to be shared.** `tenantSeedSchema` is a `z.object(...).superRefine(...).transform(...)`, so it cannot be extended, and it silently drops unknown keys. Its cross-tenant checks cover `slug`, `id`, `walletOrigin`, `rpId` and admin keys, but not `expectedOrigins`.
- **`requireSession` can let a request through with no tenant.** With no Origin, it sets `request.tenant = getById(session.tenantId)` and proceeds even when that returns null.
- **No sessions column for tenants.** `sessions` has no `tenant_id`; a session's tenant is its user's.
- **Nothing sweeps challenges.** `challenges.prune()` is never called.
- **Only the watcher expires reservations.** `ledger.expireStale()` runs only inside the watcher.
- **No `trustProxy`.** `request.ip` is the proxy's address.
- **Mostly no cascades to `tenants`.** `users`, `credentials`, `challenges`, `pending_additions`, `wallet_management_log`, `userop_log` and `ror_origins` reference `tenants` without cascade, so a hard delete would fail or destroy records.
- **Several replicas run `wallet-api`.** They seed concurrently at boot.

## Goals / Non-Goals

**Goals:**
- R1 through the API, with the invariant enforced on every write path, seed included.
- One place where tenant rules live, and one place where tenant resolution lives.
- A failed precondition is a `4xx` with a reason a platform admin can act on, never a `500`.

**Non-Goals:**
- The console (PR 2), `/v1/platform/chains` (its own card), and `infra/iac/` changes.
- A tenant cache, or any change to how non-platform routes are shaped.
- Making a runtime tenant's wallet origin reachable (spec §1.3, O-5).

## Decisions

**D1 — The platform tier is new routes on `wallet-api`** (spec H-a). `wallet-api` already owns the table, the validation, the ledger and the chain registry. A separate service would need its own copy of the invariant.
*Rejected:* a standalone admin service writing the same table.

**D2 — Platform admins sign in with a wallet (EIP-4361), and verify matches the stored message text** (spec H-b, H-l, §4).
- The challenge row stores the exact text the server issued.
- Verify parses the message, recovers the signer by ECDSA, checks the platform admin list, and then consumes the challenge with a single `UPDATE … WHERE nonce AND address AND message AND used_at IS NULL AND expires_at > now() RETURNING`.
- The text match checks every field and the time window at once, against values only the server chose.

*Rejected:*
- `validateSiweMessage` as the check. In viem 2.31.6 it skips `issuedAt`, `uri`, `version` and `chainId`.
- A shared platform API key. It is a secret to copy and leak, and gives no second factor.
- ERC-1271 contract signers. They need RPC, and sign-in must work when every chain is down.

**D3 — The tenant schema splits into fields and invariants** (spec §6.1). The new pieces:
- `tenantFieldsSchema`: field shapes, `.strict()`;
- `checkTenantInvariants(fields, { adminKeyCount })`: returns issues with paths;
- `tenantSeedSchema`: fields plus plaintext `adminKeys`;
- `tenantCreateSchema`: fields plus `adminKeys: { label }[]`;
- `tenantPatchSchema`: the mutable subset.

The seed keeps its existing transform, which defaults `rpId` and puts `walletOrigin` into `expectedOrigins`, and create applies the same normalisation. Update merges onto the stored row and re-runs fields and invariants.
*Rejected:* a second schema for runtime writes. Two copies of the invariant drift.

**D4 — Origin claims are checked under an advisory lock in the writing transaction** (spec §6.2).
- Every writer of `wallet_origin` or `expected_origins` (seed, create, update) first takes `pg_advisory_xact_lock(hashtext('giano:tenant-origin-claims'))`.
- It then queries for any other row with `wallet_origin = ANY($claims) OR expected_origins && $claims`.

*Rejected:* a side table with one row per claimed origin and a unique index. It is stronger, but adds a table to keep in sync with two array columns, and at this write rate a deployment-wide lock costs nothing.

**D5 — Resolvers filter on `status = 'active'` inside `createTenantService`** (spec §8).
- `getById` becomes `getActiveById`, used by `requireSession`, and `getByIdAnyStatus`, used by the watcher and the platform routes. The split makes the choice visible at each call site.
- `requireSession` returns the generic `401` when the active tenant is missing.
- Platform admin routes use their own lookups by slug over any status, and never use the resolvers.

*Rejected:* filtering in each route. There are too many call sites, and one missed check would bring a suspended tenant back.

**D6 — Lifecycle columns go on `tenants`, and history goes in an append-only table** (spec §5.2).
- `status`, `managed_by`, `version` and `status_changed_at` are added to `tenants`, with defaults that backfill existing rows as `active` and `seed`.
- `tenant_history` has no cascade, and holds jsonb before and after snapshots with key material redacted.
- `version` is incremented by every writer, seed included.

*Rejected:* a separate `tenant_status` table. It would add a join to every resolver on the hot path.

**D7 — Delete is a tombstone, behind locked preconditions** (spec §5.3).
- The chain heads are read *before* the transaction opens.
- Inside the transaction:
  1. `SELECT … FOR UPDATE` on the tenant;
  2. check the state and owner;
  3. check `paymaster_tenants` balance and deficit;
  4. check for reservations with `state='reserved' AND expires_at > now()`;
  5. compare `paymaster_state.last_synced_block` against the heads.
- Then set `status='deleted'` and delete the tenant's sessions (through `users`), challenges, `pending_additions` and admin keys.
- If the delete races the watcher, the lock on the tenant row plus the balance re-read inside the transaction bounds the window to a settlement mined in between. The lag threshold covers that.

*Rejected:* a hard delete. The foreign keys forbid it, the paymaster keys balances on the id, and a reused RP ID would inherit live passkeys.

**D8 — The seed and platform admins own tenants exclusively, and the seed wins at boot** (spec H-h, §9). `seedTenants` reads the existing row `FOR UPDATE`, so concurrent replicas serialise. It compares the stored values before writing, so an unchanged boot writes nothing. It never touches `status`.
*Rejected:* letting both edit seeded tenants. The next boot would silently revert platform admin edits.

**D9 — Admin keys are generated by the server** (spec H-i). A key is 32 random bytes, base64url, prefixed `gak_`, with only its sha256 stored. The existing `resolveAdminTenant` hashes whatever it is given, so seeded keys without the prefix keep working.

**D10 — Rate limits are keyed by platform admin, not IP.** Authenticated routes use `@fastify/rate-limit` with a key generator over the session id. Challenge keys on the requested address, verify on the parsed message address, and a global ceiling applies to both. `trustProxy` stays unset, because changing it affects every existing per-IP limit and is out of scope.

**D11 — The Origin refusal runs first in `requirePlatformAdmin`, and as its own hook on challenge and verify.** It is a cheap extra layer, not the access control (spec §4.5). It costs one header check.

**D12 — Challenge housekeeping is an unref'd interval in `src/index.ts`, next to the chain prober.** It calls `challenges.prune()` and deletes `platform_admin_challenges` that expired more than a day ago. It runs on every replica, because the deletes are idempotent. *Rejected:* pruning on issue, which puts a delete on the hot path.

## Risks / Trade-offs

- **[Runtime state can stop a deploy from booting]** A seed entry clashing with a platform admin tenant's origin, or naming a deleted slug, refuses boot. → This is accepted: two tenants answering one origin is worse. During a rolling deploy the old tasks keep serving. The boot error names the origin, the other slug, its owner and its state, and the fix is in the spec §6.2 runbook paragraph.
- **[Stricter seed parsing]** `.strict()` refuses seeds that today pass with unknown keys dropped. → Every `deploy/` seed is clean. The AWS dev secret is checked before deploy (O-8), and the error names the key.
- **[A suspended tenant's users see a generic failure]** They get the existing unknown-tenant responses, with no explanation. → This is intended, so the API does not reveal which slugs exist. The suspending platform admin tells the tenant.
- **[A paymaster authorisation outlives the suspension]** One signed before the suspension stays valid on-chain for up to `SPONSORSHIP_VALIDITY_SECONDS`. → The console offers the on-chain disable in PR 2. The API cannot do it.
- **[Phishing for a platform admin signature]** → The signed `domain` binds the signature to the console host. The platform admin rule (O-9) is to use a wallet that warns on a domain mismatch, on a hardware device.
- **[The deployment-wide advisory lock serialises all tenant writes]** → Tenant writes are rare, and the lock is held only for the length of the write transaction.
- **[The ledger can be stale at delete time]** → The lag check plus the row lock. A deployment with no watcher can never delete a sponsoring tenant, which is correct.

## Migration Plan

1. **Migration `0007_tenant_lifecycle.sql`.** It is additive: new columns with defaults and three new tables. Existing rows become `active` and `seed`. It is applied by the existing runner at boot (`RUN_MIGRATIONS`).
2. **Ship with `OPERATOR_ADDRESSES` unset.** The behaviour change for existing deployments is then limited to:
   - lifecycle-aware resolution, a no-op while every tenant is active;
   - the stricter seed: unknown keys and origin overlaps;
   - the challenge sweep.
3. **Before deploy to AWS dev:** check the `tenants-seed` secret (O-8).
4. **Enable on a deployment:** devops sets `OPERATOR_ADDRESSES` and `OPERATOR_SIWE_DOMAIN`, and adds the `/v1/platform/*` restriction at `api.*` (O-3). Acceptance follows spec §14.3, using `platform:login` with a throwaway EOA.
5. **Rollback:** unset `OPERATOR_ADDRESSES` to remove the routes. Code rollback is safe, because the previous image ignores the new columns and tables.
   - A tenant left suspended or deleted would become live again under the old image, because it does not read `status`. Before rolling back code, resume or note such tenants.
   - The migration is not reversed.

## Open Questions

- The exact boot-error and `409` message wording. Settled in review, with no effect on behaviour.
- Whether `GET /v1/platform/tenants/:slug` also returns the tenant's `ror_origins`. They are tenant-admin-owned and harmless to show; decide during D4 by what the console in PR 2 needs.
