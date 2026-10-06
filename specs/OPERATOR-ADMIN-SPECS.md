# Giano — operator admin: runtime tenants and blockchain status

This document is the **how** for H5 (*Admin application for tenants, blockchain status*, 3 SP),
whose **what** is the requirement reproduced in [§2](#2-the-requirements). It specifies an
operator tier in `wallet-api`, the tenant lifecycle it manages, how runtime writes keep the
invariant tenant ≡ wallet origin ≡ RP ID, how they coexist with `TENANTS_SEED`, and the console
that drives them.

Everything asserted about the current state in [§3](#3-current-state-verified) was read out of this
repository on 2026-10-06; each claim carries its evidence. [§13](#13-traceability) maps the
requirement and every deliverable to the section that specifies it.

Status: **draft for technical review.** [§12](#12-risks-and-open-items) lists what still needs a
call. O-1 (the blockchain-status requirements) is the only one that changes scope.

---

## Contents

1. [Scope and decisions](#1-scope-and-decisions)
2. [The requirements](#2-the-requirements)
3. [Current state, verified](#3-current-state-verified)
4. [Operator authority](#4-operator-authority)
5. [Tenant lifecycle and data model](#5-tenant-lifecycle-and-data-model)
6. [Keeping the invariant under runtime writes](#6-keeping-the-invariant-under-runtime-writes)
7. [Operator API](#7-operator-api)
8. [Resolution under the lifecycle](#8-resolution-under-the-lifecycle)
9. [Coexistence with `TENANTS_SEED`](#9-coexistence-with-tenants_seed)
10. [Blockchain status](#10-blockchain-status)
11. [The console](#11-the-console)
12. [Risks and open items](#12-risks-and-open-items)
13. [Traceability](#13-traceability)
14. [Testing and acceptance](#14-testing-and-acceptance)

---

## 1. Scope and decisions

### 1.1 What H5 delivers

An operator — Giano's own staff, never a tenant — can create, read, update, suspend and delete
tenants against a running deployment, and the change takes effect on the next request. Nothing is
redeployed and no process restarts.

Concretely, six deliverables:

| # | Deliverable | Where |
| --- | --- | --- |
| **D1** | Operator authentication: a deployment-configured set of operator keys, a `requireOperator` guard, and routes that refuse browser cross-origin calls outright | `wallet-api` — [§4](#4-operator-authority) |
| **D2** | Tenant lifecycle columns, an append-only `tenant_history`, migration `0007_tenant_lifecycle.sql` | `wallet-api` — [§5](#5-tenant-lifecycle-and-data-model) |
| **D3** | One validation path for seed and runtime writes, with the cross-tenant origin check the seed does not do today | `services/tenants.ts` — [§6](#6-keeping-the-invariant-under-runtime-writes) |
| **D4** | `/v1/operator/tenants/*` routes, and every tenant resolver made lifecycle-aware | `wallet-api` — [§7](#7-operator-api), [§8](#8-resolution-under-the-lifecycle) |
| **D5** | `/v1/operator/chains`, a server-side status read per served chain | `wallet-api` — [§10](#10-blockchain-status) |
| **D6** | An *Operator* area in the existing console: sign-in, tenant registry, create/edit/suspend/delete, key issue/revoke, chain status | `services/paymaster-admin` — [§11](#11-the-console) |

D1–D4 and D6's tenant half satisfy R1. D5 and D6's chain half are the provisional answer to the
*blockchain status* half of the card, which has no requirements yet (O-1).

### 1.2 Decisions taken in this spec

| # | Decision | Why |
| --- | --- | --- |
| **H-a** | **The operator tier is new routes on `wallet-api`**, under `/v1/operator`, not a new service. | `wallet-api` already owns the tenants table, the validation, the ledger and the chain registry. A second service writing the same table would need its own copy of the invariant, and two copies drift. Same reasoning as PAYMASTER-SPECS S1. |
| **H-b** | **Operator keys are configuration, never rows.** `OPERATOR_KEYS` is a JSON array of `{ id, sha256 }`, read at boot. The operator routes are not registered when it is empty. | "A caller may name a tenant; only configuration admits one" ([`ARCHITECTURE.md`](./ARCHITECTURE.md)). If operator authority lived in the database, anything that could write the database could mint an operator. Hashes only, so the plaintext never sits in a task definition. Off by default, like sponsorship. [§4](#4-operator-authority). |
| **H-c** | **Operator routes refuse any request that carries an `Origin` header.** The console reaches them through its own nginx proxy, which strips it. | The CORS plugin grants ACAO to every tenant's `cors_origins` on every route. Refusing `Origin` on `/v1/operator/*` means no browser page on any origin can call these routes cross-origin, whatever CORS says, and the check is one line. [§4.3](#43-no-browser-cross-origin-path). |
| **H-d** | **Delete is a tombstone.** A deleted tenant's row stays, with `status = 'deleted'`; its slug, id, wallet origin and RP ID are never reusable. | The id keys the tenant's balance on every paymaster, which nothing off-chain can delete. `userop_log`, `wallet_management_log`, `users` and `credentials` reference `tenants` without cascade, and they are records we keep. And an RP ID handed to a new tenant would inherit every passkey users still hold for the old one. [§5.3](#53-delete). |
| **H-e** | **Suspend before delete, and delete refuses while money is attached.** | Suspend is immediate and reversible, so it is the incident tool. Delete is irreversible, so it requires the reversible step first and a zero balance and no open reservations on every chain. [§5](#5-tenant-lifecycle-and-data-model). |
| **H-f** | **`slug`, `id`, `walletOrigin` and `rpId` are immutable through the API.** | `rpId` is immutable today (passkeys bind to it); `walletOrigin` must keep its host equal to `rpId` (D1 in `tenants.ts`), so it is immutable with it. `id` is the paymaster key. `slug` is the seed's upsert key. A tenant that needs a new origin is a new tenant. |
| **H-g** | **Runtime and seed writes go through one validator**, and that validator gains a cross-tenant check: no origin may be claimed by two tenants. | `getByOrigin` resolves `wallet_origin OR origin = ANY(expected_origins)` with `findFirst`. Two tenants claiming the same origin resolve to whichever row Postgres returns first. The seed schema checks duplicate `walletOrigin` and `rpId` but not `expectedOrigins`, so this is a latent gap today that runtime writes would make reachable. [§6.2](#62-origin-claims-are-disjoint). |
| **H-h** | **A tenant is managed by the seed or by operators, never both.** Seed-managed tenants are read-only through the API. A seed entry whose slug matches an operator-managed tenant takes it over at boot and records that in the history. | Without ownership, the next boot silently overwrites operator edits to any seeded tenant. Config wins over runtime state because config is what was reviewed and deployed. [§9](#9-coexistence-with-tenants_seed). |
| **H-i** | **Admin keys are generated by the server** and returned once. The API never accepts a caller-chosen admin key. | A generated key has full entropy and cannot collide with an operator key or another tenant's key. The seed keeps accepting plaintext keys, as it does today. |
| **H-j** | **The console is the existing `paymaster-admin`**, gaining an Operator area. The image and package keep their names. | It is already the operator console, already deployed at `paymaster.*`, and already holds the on-chain roster. Joining the registry to that roster on tenant id is what lets an operator see a tenant that exists in one place and not the other. Renaming the image touches ECR and Terraform, which is devops territory (O-4). |

### 1.3 Out of scope

- **Making a new tenant's wallet origin reachable.** A runtime-created tenant exists in
  `wallet-api` immediately. Its `walletOrigin` still needs DNS, a certificate and a route to a
  wallet UI. The stock `wallet-web` takes its dApp allowlist and brand from a per-container
  `config.json` and safely serves one tenant ([`ARCHITECTURE.md`](./ARCHITECTURE.md), *Host-resolved
  tenant config*). Until that lands, a tenant created at runtime brings its own UI (BYO) or gets
  its own `wallet-web` task, which is an infra change. H5 removes the redeploy of `wallet-api`; it
  does not remove the infra work of serving a new hostname. Stated plainly in the console's create
  dialog.
- **Tenant self-service** (BR-35's tenant-facing half). Tenants keep their admin key and the
  existing `/v1/admin/*` routes.
- **On-chain administration from the API.** Registering, enabling and disabling a tenant on the
  paymaster stays a wallet-signed transaction from the console, exactly as `TenantsPanel` does it
  today. The API holds no key that can do it (ARCHITECTURE property 2).
- **Fees, treasury, roles.** Unchanged; already in the console.
- **`infra/iac/`.** The new `OPERATOR_KEYS` secret and any network restriction on `paymaster.*` are
  raised as O-3 for devops.

---

## 2. The requirements

Reproduced from the H5 page so this document stands alone.

**R1 — Tenants can be created, read, updated and deleted at runtime, without a redeploy.**

This is Giano's own admin application, for us: an operator surface, not a tenant-facing one.

**Blockchain status** is named in the card's title with no requirement attached. [§10](#10-blockchain-status)
specifies a provisional read-only status view so the console has somewhere to put it; O-1 asks for
the real requirement.

---

## 3. Current state, verified

| Claim | Verdict | Evidence |
| --- | --- | --- |
| Tenants are provisioned only by `TENANTS_SEED`, upserted by slug after migrations and before `listen` | ✅ | `src/index.ts:24-29`, `seedTenants` in `src/services/tenants.ts` |
| Every seed write passes through `validateTenantSeed` / `tenantSeedSchema` | ✅ | `src/services/tenants.ts`, `src/config.ts:85-97` |
| `rpId` must equal the `walletOrigin` host; every `expectedOrigins` host must equal `rpId` or be a subdomain | ✅ | `tenantSeedSchema.superRefine` |
| `rpId` and `id` are immutable on re-seed, except the `.invalid` sentinel | ✅ | `seedTenants` |
| The seed rejects duplicate slug, id, walletOrigin, rpId and admin key across tenants | ✅ | `tenantsSeedSchema` |
| The seed does **not** reject an origin listed in two tenants' `expectedOrigins`, or in one's `expectedOrigins` and another's `walletOrigin` | ❌ gap | `tenantsSeedSchema` checks only the five fields above; `getByOrigin` uses `findFirst` over `wallet_origin OR = ANY(expected_origins)` |
| Admin routes are scoped to the tenant whose key authorised them; no cross-tenant tier exists | ✅ | `requireAdmin` in `src/plugins/auth.ts`; `src/routes/admin.ts`, `admin-sponsorship.ts` |
| Tenant resolution is per request, from the database; `buildApp` never reads `tenants` | ✅ | `src/plugins/tenant.ts`; comment in `src/app.ts`. This is what makes R1 achievable without restarts. |
| Five resolvers decide tenant identity: `getByOrigin`, `getByHost`, `getByAdminKeyHash`, `getById` (session path), `isCorsOrigin` | ✅ | call sites: `plugins/tenant.ts:35,52`, `plugins/auth.ts:41,73`, `routes/tx-mappings.ts:24`, `app.ts:85` |
| `tenants` has no status column; every row is live | ✅ | `src/db/schema.ts:8-24` |
| `users`, `credentials`, `challenges`, `pending_additions`, `wallet_management_log`, `userop_log`, `ror_origins` reference `tenants` without `ON DELETE CASCADE` | ✅ | `src/db/schema.ts` |
| `paymaster_tenants`, `sponsorship_reservations`, `tenant_sponsorship*`, `tenant_tx_mappings*` cascade | ✅ | `src/db/schema.ts` |
| The paymaster exposes `registerTenant`, `setTenantEnabled`, `setTenantWithdrawAddress` under `TENANT_ADMIN_ROLE`; nothing deregisters | ✅ | `packages/contracts/src/paymaster/GianoPaymaster.sol:394-419` |
| `paymaster-admin` reads the chain only; it has no route to `wallet-api` | ✅ | `services/paymaster-admin/docker/nginx.conf.template` has `/rpc/<chainId>` locations and no `/api`. [`INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) R31 says the console proxies `/api`; the template disagrees. |
| Per-chain status is already tracked: boot verification, a background prober, `/v1/version` exposing `ready`/`unavailable` | ✅ | `src/services/chain-verify.ts`, `src/index.ts:88-110`, `src/routes/health.ts` |
| Paymaster position per chain is already persisted by the watcher | ✅ | `paymaster_state` (deposit, treasury, stake, invariant slack, last synced block) and `paymaster_tenants` |

---

## 4. Operator authority

### 4.1 Configuration

```jsonc
// OPERATOR_KEYS — JSON array, parsed and validated in src/config.ts
[
  { "id": "ops-gabriel", "sha256": "9f2c…" },  // 64 lowercase hex chars
  { "id": "ops-oncall",  "sha256": "41aa…" }
]
```

- `id` is a label recorded on every write (`actor = "operator:<id>"`), `^[a-z0-9-]{1,64}$`, unique.
- An empty or absent value means the operator routes are not registered at all, and the console's
  Operator area reports *operator API disabled on this deployment*.
- Boot refuses if any operator hash equals a row in `tenant_admin_keys`. A seeded tenant key and an
  operator key that hash the same would make one secret both.
- A helper prints a fresh key and its hash: `pnpm -F @appliedblockchain/giano-wallet-api operator-key`.
  The plaintext goes to the operator; the hash goes into the secret.

Rotation is a config change and a rolling restart. That is a redeploy, which is acceptable for
operator credentials: R1 is about tenants.

### 4.2 The guard

`plugins/auth.ts` gains `requireOperator`, alongside `requireAdmin`:

1. Reject with `403 operator-origin-refused` if the request carries an `Origin` header (§4.3).
2. Take the bearer token, `sha256` it, look the digest up in an in-memory `Map<hash, id>` built at
   boot, and confirm with `timingSafeEqual`, the same shape as `resolveAdminTenant`.
3. On failure, `401 unauthorized` with the same body whether the key is unknown, malformed or a
   tenant admin key. Count it in `giano_operator_auth_failures_total`.
4. On success, set `request.operator = { id }` and log with `operator: id`.

A tenant admin key presented on `/v1/operator/*` fails at step 2 because it is not in the operator
map. An operator key presented on `/v1/admin/*` fails `requireAdmin` because it is not in
`tenant_admin_keys`. The two tiers never share a lookup.

Rate limit: `OPERATOR_RATE_LIMIT_PER_MINUTE` (default 60) per key id, plus per IP on failures.

### 4.3 No browser cross-origin path

Browsers attach `Origin` to every cross-origin request and to every non-GET same-origin request.
Refusing `Origin` on operator routes therefore closes the cross-origin path regardless of what the
CORS plugin answers on preflight. The console calls the API through a same-origin `/api/` location
in its own nginx, which does `proxy_set_header Origin "";`, so its requests arrive without one.
`curl` and scripts never send it.

### 4.4 Where the key lives in the browser

In React state only. Not `localStorage`, not `sessionStorage`. A reload asks for it again. This is
an internal tool used by a handful of people, and a key that survives the tab is a key that
survives on a shared machine.

---

## 5. Tenant lifecycle and data model

### 5.1 States

```
            create (operator)            suspend
   ──────────────────────────► active ◄──────────► suspended ──── delete ───► deleted
   seed upsert (boot) ───────►         resume                      (terminal)
```

| State | Resolves on ceremony / Host / admin key / session / CORS | Watcher and ledger | Writable by operator |
| --- | --- | --- | --- |
| `active` | yes | yes | if operator-managed |
| `suspended` | **no** — as if unknown | yes: settlements and reconciliation keep running, because on-chain events for this tenant still happen | lifecycle actions only (resume, delete, revoke key) |
| `deleted` | no | yes, for the same reason | nothing |

Suspension does not delete sessions. Resolution refuses them while suspended, and resume restores
whatever has not expired. Delete removes the tenant's sessions, open challenges, pending additions
and admin keys in the same transaction.

The paymaster has its own flag (`setTenantEnabled`). Suspending in the database stops new
sponsorship decisions at once. A paymaster authorisation signed before the suspension remains valid
on-chain for up to `SPONSORSHIP_VALIDITY_SECONDS`. To close that window, the console offers the
on-chain disable as the next step of the suspend flow (§11.3). The API does not and cannot do it
(§1.3).

### 5.2 Migration `0007_tenant_lifecycle.sql`

```sql
ALTER TABLE tenants
  ADD COLUMN status      text        NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'suspended', 'deleted')),
  ADD COLUMN managed_by  text        NOT NULL DEFAULT 'seed'
    CHECK (managed_by IN ('seed', 'operator')),
  ADD COLUMN version     integer     NOT NULL DEFAULT 1,
  ADD COLUMN status_changed_at timestamptz;

-- every existing row came from TENANTS_SEED, so the 'seed' default is the correct backfill

CREATE INDEX tenants_status_idx ON tenants (status);

ALTER TABLE tenant_admin_keys
  ADD COLUMN created_by text NOT NULL DEFAULT 'seed';   -- 'seed' | 'operator:<id>'

CREATE TABLE tenant_history (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id),     -- no cascade: tenants are never hard-deleted
  action      text NOT NULL,   -- create | update | suspend | resume | delete
                               -- | admin-key-issue | admin-key-revoke | seed-apply | seed-takeover | adopt
  actor       text NOT NULL,   -- 'seed' | 'operator:<id>'
  before      jsonb,           -- the tenant row before; null on create
  after       jsonb,           -- the tenant row after
  detail      jsonb,           -- e.g. { keyId, label, hashPrefix } for key actions
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenant_history_tenant_idx ON tenant_history (tenant_id, created_at);
```

`version` increments on every write and is the ETag for `PATCH` (§7.2). `before` and `after` never
contain key material: admin keys are recorded in `detail` as id, label and the first 8 hex chars of
the hash.

`seedTenants` writes a `seed-apply` history row only when the upsert changed something, so a
restart does not append a row per tenant.

### 5.3 Delete

`DELETE /v1/operator/tenants/:slug` succeeds only when, in one transaction holding a row lock on the
tenant:

1. `status = 'suspended'` — otherwise `409 tenant-not-suspended`;
2. `managed_by = 'operator'` — otherwise `409 seed-managed`;
3. on every chain, `paymaster_tenants.balance_wei = 0` and `deficit_wei = 0` — otherwise
   `409 tenant-has-funds`, with per-chain figures and the `last_synced_block` they were read at;
4. no `sponsorship_reservations` in state `reserved` — otherwise `409 tenant-has-reservations`.

Then: `status = 'deleted'`; delete `sessions`, `challenges`, `pending_additions` and
`tenant_admin_keys` for the tenant; append `tenant_history`. Everything else stays.

The ledger in check 3 is a cache rebuilt from events. If its `last_synced_block` is more than
`TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS` (new, default 50) behind the chain head, delete refuses with
`409 ledger-stale` rather than trusting an old zero.

An on-chain balance cannot be moved by Giano: only the tenant's registered withdraw address can call
`withdrawTenant`. So a tenant with funds is deleted by asking the tenant to withdraw, which is the
correct order of events anyway.

---

## 6. Keeping the invariant under runtime writes

### 6.1 One validator

`tenantSeedSchema` today mixes three things: field shapes, the single-tenant invariant (rpId ≡
walletOrigin host, expectedOrigins under rpId, admin keys required when registration is closed),
and seed-only input (plaintext `adminKeys`). It splits into:

| Piece | Used by |
| --- | --- |
| `tenantFieldsSchema` — field shapes only, `.strict()` | seed, create, update |
| `checkTenantInvariants(fields, { adminKeyCount })` — the single-tenant rules, returning issues with paths | seed, create, update |
| `tenantSeedSchema` — `tenantFieldsSchema` + `adminKeys: string[]`, calling `checkTenantInvariants` with `adminKeys.length` | seed |
| `tenantCreateSchema` — `tenantFieldsSchema` + `adminKeys: { label }[]`, same call | create |
| `tenantPatchSchema` — the mutable subset, all optional | update |

Update merges the patch onto the stored row and re-runs `tenantFieldsSchema` and
`checkTenantInvariants` on the result, with `adminKeyCount` taken from the database. So
`openRegistration: false` on a tenant with no admin keys is refused the same way the seed refuses it.

The comment at the top of `tenants.ts` changes to say that **every** write, seed or operator, passes
through `checkTenantInvariants` and `checkOriginClaims`.

### 6.2 Origin claims are disjoint

A tenant's *origin claims* are `{walletOrigin} ∪ expectedOrigins`. No origin may be claimed by two
tenants, including deleted ones (their origins stay reserved, H-d).

Postgres cannot put a unique constraint across array elements, so the check runs in the writing
transaction under a transaction-scoped advisory lock:

```ts
await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('giano:tenant-origin-claims'))`);
const clash = await tx.execute(sql`
  SELECT slug FROM tenants
  WHERE id <> ${selfId}
    AND (wallet_origin = ANY(${claims}) OR expected_origins && ${claims})`);
```

Every writer of `wallet_origin` or `expected_origins` (seed, create, update) takes the same lock, so
two concurrent creates claiming the same origin serialise and the second gets
`409 origin-claimed` naming the origin and the other tenant's slug. The lock is per deployment, not
per tenant, which is fine at this write rate.

The seed gains the same check. The seeds in `deploy/docker-compose.{e2e,dev,sepolia}.yml` claim
disjoint origins and boot unchanged. The AWS dev seed is the ASM secret `tenants-seed`
(`infra/iac/ecs_services.tf:52`), whose contents are not in the repository; it has to be checked before this ships
(O-8). A seed that overlaps refuses to boot, which is what every other seed violation already does.

`corsOrigins` and `allowedDappOrigins` are not claims: two tenants may list the same dApp, and
`isCorsOrigin` only answers yes or no.

### 6.3 Database errors as API errors

Unique violations on `slug`, `wallet_origin`, `rp_id` and `tenants_pkey` map to `409 conflict` with
the field name. Nothing reaches the client as a 500 because of a duplicate.

---

## 7. Operator API

All routes: `requireOperator`, tag `operator`, `security: [{ operatorKey: [] }]` in the OpenAPI
document (regenerated; `openapi/generate.ts --check` keeps CI honest). Tenants are addressed by
slug because that is what operators type; responses always include the id.

### 7.1 Routes

| Method & path | Does | Notable responses |
| --- | --- | --- |
| `GET /v1/operator/tenants?status=` | List, newest first; default excludes `deleted` | `200 { tenants: TenantSummary[] }` |
| `GET /v1/operator/tenants/:slug` | One tenant: all fields, `managedBy`, `status`, `version`, admin keys (id, label, hash prefix, createdBy, createdAt), user and credential counts, last userop time, per-chain ledger position from `paymaster_tenants` | `404` |
| `POST /v1/operator/tenants` | Create. Body `tenantCreateSchema`. `id` optional, for a tenant already registered on-chain under a fixed id | `201 { tenant, adminKeys: [{ id, label, key }] }` — plaintext once. `400` with per-path issues, `409 origin-claimed` / `conflict` |
| `PATCH /v1/operator/tenants/:slug` | Update mutable fields: `rpName`, `expectedOrigins`, `allowedDappOrigins`, `corsOrigins`, `openRegistration`, `policy`, `branding`. Requires `If-Match: "<version>"` | `200`, `400`, `409 seed-managed`, `409 origin-claimed`, `412 version-mismatch`, `422 immutable-field` if the body names `slug`, `id`, `walletOrigin` or `rpId` |
| `POST /v1/operator/tenants/:slug/suspend` | `active → suspended`. Body `{ reason }`, recorded | `409 invalid-transition` |
| `POST /v1/operator/tenants/:slug/resume` | `suspended → active` | `409 invalid-transition` |
| `DELETE /v1/operator/tenants/:slug` | `suspended → deleted`, under §5.3 | `204`, the four `409`s in §5.3 |
| `POST /v1/operator/tenants/:slug/admin-keys` | Issue a key. Body `{ label }` | `201 { id, label, key }` — plaintext once |
| `DELETE /v1/operator/tenants/:slug/admin-keys/:keyId` | Revoke. Refused if it is the last key and `openRegistration` is false | `204`, `409 last-admin-key` |
| `POST /v1/operator/tenants/:slug/adopt` | `managed_by: seed → operator`. Refused while the slug is still in the running process's `TENANTS_SEED` | `409 still-seeded` |
| `GET /v1/operator/tenants/:slug/history` | `tenant_history`, newest first, paginated | `200` |
| `GET /v1/operator/chains` | Blockchain status (§10) | `200` |

Lifecycle actions (suspend, resume, delete, key revoke) are allowed on seed-managed tenants. They
are incident tools, and an operator should not need a redeploy to stop a compromised tenant. The
next boot does **not** reactivate a seed-managed tenant an operator suspended: `seedTenants`
updates fields and keys but never touches `status`.

Field edits on a seed-managed tenant are refused (`409 seed-managed`), because the next boot would
overwrite them.

### 7.2 Concurrency

`PATCH` without `If-Match` is `428 precondition-required`. With a stale version it is
`412 version-mismatch` and the current version in the body. Lifecycle transitions take a row lock
and check the source state, so two operators suspending at once get one `200` and one `409`.

### 7.3 Generated admin keys

32 random bytes, base64url, prefixed `gak_` so a leaked key is recognisable in a secret scanner.
The prefix is cosmetic: `resolveAdminTenant` hashes whatever it is given, so seeded keys without
the prefix keep working.

---

## 8. Resolution under the lifecycle

Every resolver in `createTenantService` gets `AND status = 'active'`. `getById` splits, because the
watcher and settlement code legitimately read non-active tenants:

| Resolver | After H5 | Callers |
| --- | --- | --- |
| `getByOrigin` | active only | `plugins/tenant.ts` onRequest |
| `getByHost` | active only | `requireTenantByHost`, `routes/tx-mappings.ts` |
| `getByAdminKeyHash` | active only — a suspended tenant's admin key is `401` | `resolveAdminTenant` |
| `getActiveById` (new) | active only | `requireSession` |
| `getById` | any status, renamed `getByIdAnyStatus` so the choice is visible at the call site | watcher, operator routes |
| `isCorsOrigin` | active only | CORS delegate in `app.ts` |

`requireSession` needs one more change. Today, a request with no resolvable `Origin` falls through
to `request.tenant = getById(session.tenantId)` and proceeds even if that returns null. After H5 it
uses `getActiveById`, and a null result is `401` with the same body as an invalid session. Without
this, a session minted before suspension would keep working on server-to-server calls.

The slug cache in `src/index.ts` (metrics labels for the watcher) reads the table directly and is
unaffected.

Because resolution is per request from the database, every lifecycle transition and every field
edit is in force on the next request on every replica. This is the property R1 needs, and it exists
already. H5 must not introduce a tenant cache. Any future cache needs a TTL short enough that a
suspension still counts as immediate.

---

## 9. Coexistence with `TENANTS_SEED`

| Situation at boot | Behaviour |
| --- | --- |
| Seed slug not in the table | Insert, `managed_by = 'seed'`, history `create` with actor `seed` |
| Seed slug matches a seed-managed row | Today's upsert; history `seed-apply` only if something changed; `status` untouched |
| Seed slug matches an **operator-managed** row | Takeover: upsert, set `managed_by = 'seed'`, history `seed-takeover`, `WARN` log naming the slug. Immutability checks (`rpId`, `id`) still apply and still refuse boot on mismatch. |
| Seed slug matches a **deleted** row | Refuse boot: `tenant "<slug>" was deleted; a deleted tenant is never re-created` |
| Seed-managed row whose slug is no longer in the seed | Left as is. It stays seed-managed and read-only until an operator adopts it (`POST …/adopt`). |

The takeover row is the way to move a tenant from runtime management into reviewed config: copy it
into the seed, deploy, and the seed owns it from then on. Adopt goes the other way.

`TENANTS_SEED` stays the only way to provision tenants in the e2e and devnet stacks, which have to
come up deterministic with fixed ids pre-registered on the devnet paymaster.

---

## 10. Blockchain status

Provisional: the card names it and gives no requirement (O-1). Specified at the size of the data
`wallet-api` already has, so it costs little if the real requirement turns out different.

### 10.1 Why server-side

The console already reads each paymaster from the chain. It cannot see what `wallet-api` sees: the
bundler URLs are internal Cloud Map hostnames the browser cannot reach and must not learn
([`INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) §14.6), the prober's verdict lives in the API process,
and the ledger position and watcher lag are rows in its database. The question an operator is
asking is "can this deployment transact on chain X right now", and only `wallet-api` can answer it.

### 10.2 `GET /v1/operator/chains`

One entry per served chain, probed in parallel with a 3-second timeout each so one dead chain does
not stall the response:

```jsonc
{
  "chains": [{
    "chainId": 84532,
    "name": "Base Sepolia",
    "registryStatus": "ready",                 // the prober's verdict, as /v1/version reports it
    "verification": { "checkedAt": "…", "failures": [] },   // last ChainVerification
    "node":    { "reachable": true, "headBlock": "18234411", "headAgeSeconds": 2 },
    "bundler": { "reachable": true, "entryPointSupported": true },  // eth_supportedEntryPoints
    "paymaster": {                             // null when this chain does not sponsor
      "address": "0x…",
      "depositWei": "…", "treasuryWei": "…", "stakeWei": "…",
      "invariantSlackWei": "…",                // from paymaster_state
      "lastSyncedBlock": "18234400",
      "watcherLagBlocks": 11,                  // headBlock − lastSyncedBlock
      "checkedAt": "…"
    },
    "signer": "ok"                             // sponsorship signer health, or "disabled"
  }]
}
```

No new background job, table or metric. The prober must keep its last `ChainVerification` per
chain in the registry entry so the route can return it. That is deployment configuration state
the registry already holds, not tenant state.

The thresholds that turn these figures into a verdict (head age, watcher lag) stay in the console,
next to the `giano-doctor` thresholds it already applies, until O-1 says who consumes the status
and whether it should also alert.

---

## 11. The console

### 11.1 Wiring

- nginx template: the same regex `/api/` location `wallet-web` uses (deferred DNS resolution via a
  variable `proxy_pass`, prefix re-appended), plus `proxy_set_header Origin "";`. `connect-src 'self'` already
  covers it.
- `config.json` gains `operatorApi: boolean`, rendered `true` when `GIANO_WALLET_API_URL` is set.
  When false, the Operator area is hidden.
- `services/paymaster-admin/src/lib/operator-api.ts`: a typed client over the routes in §7, generated
  types from `services/wallet-api/openapi` so the console breaks at build time when the API changes.

### 11.2 Layout

A top-level switch between the existing **Paymaster** tabs (Overview, Tenants, Roles, Settings,
History, Health — unchanged) and a new **Operator** area with three tabs:

| Tab | Contents |
| --- | --- |
| **Tenants** | Registry table: slug, id, status, managed-by, wallet origin, users, and per selected chain an *on-chain* column joined from the paymaster roster by id: `registered · enabled`, `registered · disabled`, or `not registered`. A fourth group lists tenants on the roster with **no** registry row, which today nobody can see. Row → detail drawer with fields, keys, ledger position and history. |
| **Chains** | One card per served chain from `/v1/operator/chains`, with the thresholds applied and the same ok/check/failing badges as `HealthPanel`. |
| **Sign-in** | Shown in place of the other two until an operator key is entered (§4.4). |

### 11.3 Flows

**Create.** Form validated client-side with the same zod schema (imported from a shared module, not
re-typed). On `201`, a modal shows the generated admin keys with copy buttons and the text *these
are shown once*. Then an optional second step: *Register on <chain>*, which calls the existing
`registerTenant(id, withdrawAddress, slug)` through the connected wallet and needs
`TENANT_ADMIN_ROLE`, as `TenantsPanel` does today. The dialog states the §1.3 limitation about
serving the wallet origin.

**Edit.** Fields pre-filled; the request carries `If-Match`. On `412`, the drawer reloads and shows
what changed.

**Suspend.** Reason required. After `200`, the console offers `setTenantEnabled(id, false)` on each
chain where the tenant is registered and enabled, and says why (§5.1, the authorisation window).
**Resume** offers the reverse.

**Delete.** Only on a suspended tenant. Type-the-slug confirmation. A `409` shows the per-chain
balance or open reservations from the response.

---

## 12. Risks and open items

| # | Item |
| --- | --- |
| **O-1** | **Blockchain status has no requirement.** §10 is a guess at the smallest useful thing. Needed: who looks at it (operators in the console, or an alerting path too), and whether "status" includes anything beyond node, bundler, paymaster and watcher, e.g. gas price, EntryPoint deposit trend, or per-tenant balance warnings. D5 can be dropped without touching D1–D4. |
| **O-2** | **Estimate.** The card says 3 SP and its estimation field says 2.5. D1–D4 plus D6's tenant half fit something near that. D5 and the Chains tab do not, and are the first thing to cut or split into a follow-up card. |
| **O-3** | **Devops (`infra/iac/`).** Three asks, none of them H5 deliverables: an ASM secret `giano-<env>-operator-keys` mapped to `OPERATOR_KEYS` on `wallet-api`; `GIANO_WALLET_API_URL` on the `paymaster-admin` task; and a decision on restricting `paymaster.*` at the ALB (VPN CIDR or ALB OIDC). The operator key is the control; a network restriction is defence in depth for a host that now fronts write routes. |
| **O-4** | **Naming.** `paymaster-admin` now administers more than the paymaster. Renaming the package, image and ECR repository is a separate, mechanical change with an infra component. Not proposed here. |
| **O-5** | **Serving a runtime tenant's wallet origin** still needs infra (§1.3). The real fix is the Host-resolved `wallet-web` config already listed as unbuilt in [`ARCHITECTURE.md`](./ARCHITECTURE.md). Worth a card of its own, because until it lands "create a tenant at runtime" means "create the backend half at runtime". |
| **O-6** | **`INFRASTRUCTURE.md` R31** says `paymaster-admin` proxies `/api` to `wallet-api`. The nginx template does not. After D6 it will, and R31 becomes true; the doc should be checked against the template either way. |
| **O-7** | **Branding** is stored and editable through this API, and still read by nothing. Editing it in the console changes no UI. The console labels the field accordingly. |
| **O-8** | **The AWS dev `tenants-seed` secret** must be checked for overlapping origin claims (§6.2) before D3 deploys, or `wallet-api` will refuse to boot on dev. |

Risk worth naming: **a suspended tenant's dApp users see failures, not an explanation.** Ceremonies
return `403 unknown-tenant` and the popup shows its generic error. A distinct
`403 tenant-suspended` would tell an attacker which slugs exist, so the generic response is the
intended behaviour. The operator who suspends is expected to tell the tenant.

---

## 13. Traceability

| Requirement / item | Satisfied by |
| --- | --- |
| R1 — create | §7.1 `POST`, §6 validation, §11.3 Create |
| R1 — read | §7.1 `GET` list / detail / history, §11.2 Tenants tab |
| R1 — update | §7.1 `PATCH`, §6.1 merge-then-validate, §7.2 concurrency |
| R1 — delete | §5.3 tombstone delete, §5.1 suspend, §7.1 lifecycle routes |
| R1 — without a redeploy | §8: per-request resolution, no tenant cache; §9: seed no longer the only writer |
| R1 — the tenant ≡ wallet origin ≡ RP ID invariant holds | §6.1 single validator, §6.2 disjoint origin claims, H-f immutable fields |
| R1 — operator surface, not tenant-facing | §4: separate key set, separate guard, no cross-origin path |
| Blockchain status (provisional) | §10, §11.2 Chains tab — pending O-1 |

### Deliverables

| # | Files |
| --- | --- |
| D1 | `src/config.ts` (`OPERATOR_KEYS`, `OPERATOR_RATE_LIMIT_PER_MINUTE`, `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS`), `src/plugins/auth.ts` (`requireOperator`), `src/index.ts` (operator/tenant hash collision check), `scripts/operator-key.ts` |
| D2 | `migrations/0007_tenant_lifecycle.sql`, `src/db/schema.ts` |
| D3 | `src/services/tenants.ts` (schema split, `checkTenantInvariants`, `checkOriginClaims`, seed ownership rules) |
| D4 | `src/routes/operator-tenants.ts`, `src/services/tenants.ts` (lifecycle-aware resolvers), `src/plugins/auth.ts` (`requireSession` change), `src/app.ts` (registration when `OPERATOR_KEYS` is non-empty), `openapi/` |
| D5 | `src/routes/operator-chains.ts`, `src/services/chains.ts` (keep last verification), `src/index.ts` (prober stores it) |
| D6 | `services/paymaster-admin/docker/{nginx.conf.template,entrypoint.sh,config.json}`, `src/config.ts`, `src/lib/operator-api.ts`, `src/operator/{SignIn,TenantsTab,TenantDrawer,ChainsTab}.tsx`, `src/App.tsx` |

---

## 14. Testing and acceptance

### 14.1 `wallet-api` (vitest + testcontainers)

- **Invariant.** Create with `rpId` ≠ wallet host → `400`; an `expectedOrigins` entry outside
  `rpId` → `400`; `openRegistration: false` with no keys → `400`; `PATCH` that would leave a closed
  tenant keyless → `400`.
- **Origin claims.** Two concurrent creates claiming the same origin → exactly one `201`, one
  `409 origin-claimed`. A seed whose `expectedOrigins` overlaps another seed's `walletOrigin`
  refuses to boot. A deleted tenant's origin stays claimed.
- **Immutability.** `PATCH` naming `walletOrigin`, `rpId`, `id` or `slug` → `422`.
- **Lifecycle resolution.** For a suspended tenant: `Origin` ceremony → `403`; `/.well-known/webauthn`
  by Host → `404`; its admin key → `401`; an existing session, with and without `Origin` → `401`;
  its CORS origin gets no ACAO. Resume → the same session works again.
- **Delete.** Active → `409`; seed-managed → `409`; non-zero ledger balance → `409` with figures;
  open reservation → `409`; stale ledger → `409`; success → sessions and keys gone, `userop_log`
  rows intact, slug unusable by a later create.
- **Seed coexistence.** Each row of the §9 table, including that a restart does not reactivate a
  suspended seed-managed tenant and does not write a history row when nothing changed.
- **Operator auth.** No key / wrong key / tenant admin key → `401` with identical bodies; any
  `Origin` header → `403`; operator key on `/v1/admin/*` → `401`; `OPERATOR_KEYS` empty → operator
  routes `404`; operator hash equal to a seeded admin-key hash → boot refuses.
- **No restart.** Create a tenant through the API, then in the same process: `GET
  /.well-known/webauthn` with its Host resolves, and `POST /v1/webauthn/options` with its Origin
  resolves.

### 14.2 E2E (`e2e/tests/operator.spec.ts`)

Against the two-tenant compose stack, with an operator key added to `deploy/docker-compose.e2e.yml`:

1. Suspend `byo` through the API; connecting from `app-byo.localhost` fails. Resume; it succeeds.
   Tenant `stock` is unaffected throughout.
2. Create tenant `runtime` with walletOrigin `http://wallet-runtime.localhost`; `GET
   http://api.localhost/.well-known/webauthn` with `Host: wallet-runtime.localhost` returns its
   document with no container restarted.
3. Console smoke: sign in with the operator key, the registry shows `stock`, `byo` and `runtime`,
   `stock` and `byo` show *registered · enabled* against the devnet paymaster, `runtime` shows
   *not registered*.

### 14.3 Acceptance on dev

```fish
# operator routes exist and refuse anonymous callers
curl -s -o /dev/null -w '%{http_code}\n' https://api.dev.giano.appliedblockchain.dev/v1/operator/tenants
# → 401

# and refuse anything a browser could send cross-origin
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $GIANO_OPERATOR_KEY" \
  -H 'Origin: https://evil.example' https://api.dev.giano.appliedblockchain.dev/v1/operator/tenants
# → 403

# create, read, suspend, resume, delete a throwaway tenant without a deploy
set -l api https://api.dev.giano.appliedblockchain.dev/v1/operator/tenants
set -l auth "Authorization: Bearer $GIANO_OPERATOR_KEY"
curl -s -H $auth -H 'Content-Type: application/json' -X POST $api -d '{
  "slug": "h5-acceptance", "walletOrigin": "https://h5-acceptance.invalid.example",
  "rpName": "H5 acceptance", "adminKeys": [{ "label": "acceptance" }] }' | jq '.tenant.id'
curl -s -H $auth $api/h5-acceptance | jq '{status, managedBy, version}'
curl -s -H $auth -X POST $api/h5-acceptance/suspend -d '{"reason":"acceptance"}' -H 'Content-Type: application/json'
curl -s -H $auth -X DELETE -o /dev/null -w '%{http_code}\n' $api/h5-acceptance   # → 204
curl -s -H $auth "$api?status=deleted" | jq '.tenants[].slug'                     # → "h5-acceptance"
```

---

## Related documents

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the trust model and the *decided from* table this spec
  extends with an operator row
- [`DEVELOPER-GUIDE.md`](./DEVELOPER-GUIDE.md) §1 — the tenancy model
- [`MULTICHAIN_SPECS.md`](./MULTICHAIN_SPECS.md) §3.5, §9.5 — chain verification and per-tenant policy
- [`PAYMASTER-SPECS.md`](./PAYMASTER-SPECS.md) — the ledger, the watcher, on-chain tenant registration, O1
- [`INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) §14.6 — how `paymaster-admin` is deployed
- [`BUSINESS-REQUIREMENTS.md`](./BUSINESS-REQUIREMENTS.md) BR-35 — the tenant-facing administration this does not build
