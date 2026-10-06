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
| **D1** | Operator sign-in with a wallet (EIP-4361) against a deployment-configured list of operator addresses, short-lived operator sessions, a `requireOperator` guard, and routes that refuse browser cross-origin calls outright | `wallet-api` — [§4](#4-operator-authority) |
| **D2** | Tenant lifecycle columns, an append-only `tenant_history`, operator challenge and session tables, migration `0007_tenant_lifecycle.sql` | `wallet-api` — [§5](#5-tenant-lifecycle-and-data-model) |
| **D3** | One validation path for seed and runtime writes, with the cross-tenant origin check the seed does not do today | `services/tenants.ts` — [§6](#6-keeping-the-invariant-under-runtime-writes) |
| **D4** | `/v1/operator/tenants/*` routes, and every tenant resolver made lifecycle-aware | `wallet-api` — [§7](#7-operator-api), [§8](#8-resolution-under-the-lifecycle) |
| **D5** | `/v1/operator/chains`, a server-side status read per served chain | `wallet-api` — [§10](#10-blockchain-status) |
| **D6** | An *Operator* area in the existing console: wallet sign-in, tenant registry, create/edit/suspend/delete, key issue/revoke, chain status | `services/paymaster-admin` — [§11](#11-the-console) |

D1–D4 and D6's tenant half satisfy R1. D5 and D6's chain half are the provisional answer to the
*blockchain status* half of the card, which has no requirements yet (O-1).

### 1.2 Decisions taken in this spec

| # | Decision | Why |
| --- | --- | --- |
| **H-a** | **The operator tier is new routes on `wallet-api`**, under `/v1/operator`, not a new service. | `wallet-api` already owns the tenants table, the validation, the ledger and the chain registry. A second service writing the same table would need its own copy of the invariant, and two copies drift. Same reasoning as PAYMASTER-SPECS S1. |
| **H-b** | **Operators sign in with a wallet.** `OPERATOR_ADDRESSES` lists `{ id, address }`; an operator signs an EIP-4361 message and gets a 30-minute session. The operator routes are not registered when the list is empty. | No shared secret exists to copy or leak, a hardware wallet is the second factor, and the API identity is the same address that signs the on-chain tenant actions. The list is configuration, never rows: "a caller may name a tenant; only configuration admits one" ([`ARCHITECTURE.md`](./ARCHITECTURE.md)), and a database write must not be able to mint an operator. Off by default, like sponsorship. [§4](#4-operator-authority). |
| **H-c** | **Operator routes refuse any request that carries an `Origin` header.** The console reaches them through its own nginx proxy, which strips it. | The CORS plugin grants ACAO to every tenant's `cors_origins` on every route. Refusing `Origin` on `/v1/operator/*` means no browser page on any origin can call these routes cross-origin, whatever CORS says, and the check is one line. [§4.5](#45-no-browser-cross-origin-path). |
| **H-d** | **Delete is a tombstone.** A deleted tenant's row stays, with `status = 'deleted'`; its slug, id, wallet origin and RP ID are never reusable. | The id keys the tenant's balance on every paymaster, which nothing off-chain can delete. `userop_log`, `wallet_management_log`, `users` and `credentials` reference `tenants` without cascade, and they are records we keep. And an RP ID handed to a new tenant would inherit every passkey users still hold for the old one. [§5.3](#53-delete). |
| **H-e** | **Suspend before delete, and delete refuses while money is attached.** | Suspend is immediate and reversible, so it is the incident tool. Delete is irreversible, so it requires the reversible step first and a zero balance and no open reservations on every chain. [§5](#5-tenant-lifecycle-and-data-model). |
| **H-f** | **`slug`, `id`, `walletOrigin` and `rpId` are immutable through the API.** | `rpId` is immutable today (passkeys bind to it); `walletOrigin` must keep its host equal to `rpId` (D1 in `tenants.ts`), so it is immutable with it. `id` is the paymaster key. `slug` is the seed's upsert key. A tenant that needs a new origin is a new tenant. |
| **H-g** | **Runtime and seed writes go through one validator**, and that validator gains a cross-tenant check: no origin may be claimed by two tenants. | `getByOrigin` resolves `wallet_origin OR origin = ANY(expected_origins)` with `findFirst`. Two tenants claiming the same origin resolve to whichever row Postgres returns first. The seed schema checks duplicate `walletOrigin` and `rpId` but not `expectedOrigins`, so this is a latent gap today that runtime writes would make reachable. [§6.2](#62-origin-claims-are-disjoint). |
| **H-h** | **A tenant is managed by the seed or by operators, never both.** Through the API, a seed-managed tenant can only be suspended and resumed. A seed entry whose slug matches an operator-managed tenant takes it over at boot and records that in the history. | Without ownership, the next boot silently overwrites operator edits to any seeded tenant. Config wins over runtime state because config is what was reviewed and deployed. [§9](#9-coexistence-with-tenants_seed). |
| **H-i** | **Admin keys are generated by the server** and returned once. The API never accepts a caller-chosen admin key. | A generated key has full entropy and cannot collide with another tenant's key. The seed keeps accepting plaintext keys, as it does today. |
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
- **`infra/iac/`.** The new `wallet-api` and `paymaster-admin` environment variables and any network
  restriction on `paymaster.*` are raised as O-3 for devops.

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

An operator signs in with an Ethereum wallet, using Sign-In with Ethereum
([EIP-4361](https://eips.ethereum.org/EIPS/eip-4361)). The deployment configures which addresses
are operators. A verified signature buys a short-lived operator session, and that session is what
the operator routes accept.

The console already connects a wallet for every on-chain action, so the person who signs in to the
API and the person who signs `registerTenant` or `setTenantEnabled` are the same identity, and the
history records the address. There is no shared secret to copy, rotate or leak, and an operator
who uses a hardware wallet gets a second factor without the API implementing one.

### 4.1 Configuration

```jsonc
// OPERATOR_ADDRESSES — JSON array, parsed and validated in src/config.ts
[
  { "id": "ops-gabriel", "address": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" },
  { "id": "ops-oncall",  "address": "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2" }
]
```

- `id` is a label, `^[a-z0-9-]{1,64}$`. Both `id` and `address` are unique across entries; boot
  refuses a duplicate.
- Addresses are normalised to lowercase on parse. They are EOAs: the signature is checked by ECDSA
  recovery, so a Safe or other contract account cannot be an operator (§4.3).
- An empty or absent value means no operator route is registered, and the console's Operator area
  reports *operator API disabled on this deployment*.
- Addresses are public, so this is a plain environment variable, not a secret.

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPERATOR_ADDRESSES` | `[]` | as above |
| `OPERATOR_SIWE_DOMAIN` | required when `OPERATOR_ADDRESSES` is non-empty | the console's host, e.g. `paymaster.dev.giano.appliedblockchain.dev`; the `domain` every sign-in message must carry |
| `OPERATOR_SIWE_URI` | `https://${OPERATOR_SIWE_DOMAIN}` | the `uri` every sign-in message must carry |
| `OPERATOR_CHALLENGE_TTL_SECONDS` | `300` | how long a nonce stays usable |
| `OPERATOR_SESSION_TTL_SECONDS` | `1800` | absolute session lifetime; no sliding renewal |
| `OPERATOR_RATE_LIMIT_PER_MINUTE` | `60` | per operator session; challenge and verify are limited per IP |

Adding or removing an operator is a config change and a rolling restart. Removal takes effect on the
next request of any open session after the restart, because the guard re-checks the address against
the current list (§4.4).

### 4.2 Sign-in

```
console                               wallet-api                         wallet
   │ POST /v1/operator/auth/challenge     │                                   │
   │   { address, chainId }  ───────────► │ address ∈ OPERATOR_ADDRESSES?     │
   │                                      │ insert operator_challenges row    │
   │ ◄─── { message }  (EIP-4361 text)    │                                   │
   │ personal_sign(message) ──────────────┼─────────────────────────────────► │
   │ ◄────────────────────────────────────┼──────────────────── signature ─── │
   │ POST /v1/operator/auth/verify        │                                   │
   │   { message, signature } ──────────► │ checks in §4.3, consume nonce     │
   │                                      │ insert operator_sessions row      │
   │ ◄─── { token, expiresAt, operator }  │                                   │
```

**Challenge.** `POST /v1/operator/auth/challenge` with `{ address, chainId }`. An address not in the
list gets the same `200` shape as one that is, with a message whose nonce is never stored, so the
endpoint does not reveal who the operators are. For a listed address the API generates a nonce with
`generateSiweNonce` from `viem/siwe` (viem 2.31.6, already a dependency), stores it, and returns the
message built by `createSiweMessage`:

| Field | Value |
| --- | --- |
| `domain` | `OPERATOR_SIWE_DOMAIN` |
| `uri` | `OPERATOR_SIWE_URI` |
| `address` | the requested address, checksummed |
| `statement` | `Sign in to the Giano operator console. This grants access to tenant administration for <N> minutes.` |
| `version` | `1` |
| `chainId` | the console's selected chain; recorded, not checked against anything |
| `nonce` | the stored nonce |
| `issuedAt` / `expirationTime` | now / now + `OPERATOR_CHALLENGE_TTL_SECONDS` |

The API builds the message and the console only relays it. The server then only ever verifies text
it wrote, and the console has no say over which domain the operator is asked to sign for.

**Verify.** `POST /v1/operator/auth/verify` with `{ message, signature }`. On success:
`{ token, expiresAt, operator: { id, address } }`. The token is 32 random bytes, base64url, prefixed
`gos_`, and stored as a sha256 hash.

**Logout.** `POST /v1/operator/auth/logout` sets `revoked_at` on the presented session.

### 4.3 What verify checks

In order. Step 4 is the only write, and the session row is inserted only after it succeeds:

1. `parseSiweMessage(message)` succeeds; `validateSiweMessage` passes with `domain =
   OPERATOR_SIWE_DOMAIN` and the current time inside `issuedAt`…`expirationTime`; and the parsed
   `uri` and `version` equal `OPERATOR_SIWE_URI` and `1`, checked separately because
   `validateSiweMessage` does not cover them.
2. `recoverMessageAddress({ message, signature })` equals the message's `address`. ECDSA only, with
   no ERC-1271 call, so verify needs no RPC and works when every chain is down, which is when an
   operator most needs to sign in.
3. The address is in `OPERATOR_ADDRESSES`.
4. The nonce is consumed atomically:
   `UPDATE operator_challenges SET used_at = now() WHERE nonce = $1 AND address = $2 AND used_at IS NULL AND expires_at > now() RETURNING nonce`.
   No row means replayed, expired or never issued.

Any failure is `401 unauthorized` with one body, whatever the cause, and increments
`giano_operator_auth_failures_total{reason}` with the specific reason for us to see.

**Why the domain matters.** The API never sees the browser's `Origin` (§4.5), so the binding between
a signature and the console is the message's `domain`. Wallets that implement EIP-4361 (MetaMask,
Rabby, Ledger Live) warn when a page asks for a signature on a message whose `domain` is not the
page's own. A phishing page that obtains a challenge for our domain and asks an operator to sign it
triggers that warning. A wallet that does not implement the check would not warn (O-9).

### 4.4 The guard

`plugins/auth.ts` gains `requireOperator`, alongside `requireAdmin`:

1. Refuse with `403 operator-origin-refused` if the request carries an `Origin` header (§4.5).
2. Take the bearer token, sha256 it, and load the `operator_sessions` row by hash where
   `revoked_at IS NULL AND expires_at > now()`.
3. Confirm the row's address is still in the current `OPERATOR_ADDRESSES`. Removing an operator
   from config ends their sessions at the next restart without touching the table.
4. On any failure, `401 unauthorized`, with the same body as an invalid token anywhere else.
5. On success, set `request.operator = { id, address, sessionId }`, with `id` taken from the
   current `OPERATOR_ADDRESSES` entry for that address, and log with `operator: id`.

A tenant admin key on `/v1/operator/*` fails at step 2 because it is not a session hash. An operator
session token on `/v1/admin/*` fails `requireAdmin` because it is not in `tenant_admin_keys`. The two
tiers never share a lookup.

The challenge and verify routes run step 1 only. Logout runs the whole guard.

### 4.5 No browser cross-origin path

Browsers attach `Origin` to every cross-origin request and to every non-GET same-origin request.
Refusing `Origin` on every `/v1/operator/*` route closes the cross-origin path regardless of what
the CORS plugin answers on preflight. The console calls the API through a same-origin `/api/`
location in its own nginx, which does `proxy_set_header Origin "";`, so its requests arrive without
one. Scripts never send it.

### 4.6 State and storage

Challenges and sessions are rows (§5.2), because `wallet-api` runs more than one replica and a nonce
issued by one must be consumable by another. Who is an operator stays configuration: a database
write can create a session row, but the guard ignores any session whose address is not in the
configured list.

The console keeps the session token in React state only, never in `localStorage` or
`sessionStorage`. A reload signs in again, which costs one wallet prompt. The console already
reloads on `accountsChanged`, so switching the wallet's account also drops the operator session,
and the API identity cannot drift away from the connected wallet.

### 4.7 Scripts and tests

`scripts/operator-login.ts` (`pnpm -F @appliedblockchain/giano-wallet-api operator-login`) runs the
same challenge and verify against a given API URL, with a private key from `OPERATOR_PRIVATE_KEY`,
and prints a session token. It exists for the e2e suite (an anvil account) and for acceptance on dev
(a throwaway EOA listed only on dev). A real operator uses the console and their own wallet.

---

## 5. Tenant lifecycle and data model

### 5.1 States

```
            create (operator)            suspend
   ──────────────────────────► active ◄──────────► suspended ──── delete ───► deleted
   seed upsert (boot) ───────►         resume                      (terminal)
```

| State | Resolves on ceremony / Host / admin key / session / CORS | Watcher and ledger | Operator actions, operator-managed | Operator actions, seed-managed |
| --- | --- | --- | --- | --- |
| `active` | yes | yes | edit fields, issue and revoke keys, suspend | suspend |
| `suspended` | **no**, as if unknown | yes: settlements and reconciliation keep running, because on-chain events for this tenant still happen | resume, revoke keys, delete | resume |
| `deleted` | no | yes, for the same reason | none | none (a seed-managed tenant is never deleted) |

Seed-managed tenants get suspend and resume because those are incident tools that must not wait for
a redeploy, and `seedTenants` never touches `status`. Every other write on a seed-managed tenant is
refused with `409 seed-managed`, because the next boot would undo it: the seed rewrites fields and
replaces the admin-key set wholesale. A leaked key on a seeded tenant is handled by suspending the
tenant, removing the key from the seed and redeploying.

Suspension does not delete the tenant's user sessions. Resolution refuses them while suspended, and resume restores
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
  ADD COLUMN created_by text NOT NULL DEFAULT 'seed';   -- 'seed' | 'operator:<id>:<address>'

CREATE TABLE operator_challenges (
  nonce       text PRIMARY KEY,
  address     text NOT NULL,                 -- lowercase
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX operator_challenges_expires_idx ON operator_challenges (expires_at);

CREATE TABLE operator_sessions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash  text NOT NULL UNIQUE,          -- sha256 hex of the gos_ token
  operator_id text NOT NULL,                 -- the OPERATOR_ADDRESSES id at sign-in
  address     text NOT NULL,                 -- lowercase
  chain_id    bigint NOT NULL,               -- from the signed message, for the record
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  ip          text,
  user_agent  text
);
CREATE INDEX operator_sessions_expires_idx ON operator_sessions (expires_at);

CREATE TABLE tenant_history (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id),     -- no cascade: tenants are never hard-deleted
  action      text NOT NULL,   -- create | update | suspend | resume | delete
                               -- | admin-key-issue | admin-key-revoke | seed-apply | seed-takeover | adopt
  actor       text NOT NULL,   -- 'seed' | 'operator:<id>:<address>'
  operator_session_id uuid REFERENCES operator_sessions(id),  -- null for seed writes
  before      jsonb,           -- the tenant row before; null on create
  after       jsonb,           -- the tenant row after
  detail      jsonb,           -- e.g. { keyId, label, hashPrefix } for key actions
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenant_history_tenant_idx ON tenant_history (tenant_id, created_at);
```

Expired challenges are deleted by the periodic sweep that already expires tenant challenges.
Operator sessions are kept: they are the record of who signed in when, `tenant_history` references
them, and a handful of operators signing in a few times a day produces a negligible number of rows.

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
3. on every chain, `paymaster_tenants.balance_wei = 0` and `deficit_wei = 0`, where a chain with no
   row counts as zero — otherwise `409 tenant-has-funds`, with per-chain figures and the
   `last_synced_block` they were read at;
4. no `sponsorship_reservations` in state `reserved` — otherwise `409 tenant-has-reservations`.

Then: `status = 'deleted'`; delete `sessions`, `challenges`, `pending_additions` and
`tenant_admin_keys` for the tenant; append `tenant_history`. Everything else stays.

The ledger in check 3 is a cache rebuilt from events. If, on any sponsoring chain,
`paymaster_state.last_synced_block` is more than `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS` (new,
default 50) behind the chain head, delete refuses with `409 ledger-stale` rather than trusting an
old zero. A chain that cannot be reached for its head counts as stale.

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
(`infra/iac/ecs_services.tf:52`), whose contents are not in the repository; it has to be checked
before this ships (O-8). A seed that overlaps refuses to boot, which is what every other seed violation already does.

`corsOrigins` and `allowedDappOrigins` are not claims: two tenants may list the same dApp, and
`isCorsOrigin` only answers yes or no.

### 6.3 Database errors as API errors

Unique violations on `slug`, `wallet_origin`, `rp_id` and `tenants_pkey` map to `409 conflict` with
the field name. Nothing reaches the client as a 500 because of a duplicate.

---

## 7. Operator API

Every route except challenge and verify (§4.2) runs `requireOperator`. All carry tag `operator`,
and the guarded ones declare `security: [{ operatorSession: [] }]` in the OpenAPI document, which is
regenerated and kept honest by `openapi/generate.ts --check` in CI. Tenants are addressed by slug
because that is what operators type; responses always include the id.

### 7.1 Routes

| Method & path | Does | Notable responses |
| --- | --- | --- |
| `POST /v1/operator/auth/challenge` | Sign-in message (§4.2) | `200 { message }` |
| `POST /v1/operator/auth/verify` | Session from a signed message (§4.3) | `200 { token, expiresAt, operator }`, `401` |
| `POST /v1/operator/auth/logout` | Revoke the presented session | `204`, `401` |
| `GET /v1/operator/tenants?status=` | List, newest first; default excludes `deleted` | `200 { tenants: TenantSummary[] }` |
| `GET /v1/operator/tenants/:slug` | One tenant: all fields, `managedBy`, `status`, `version`, admin keys (id, label, hash prefix, createdBy, createdAt), user and credential counts, last userop time, per-chain ledger position from `paymaster_tenants` | `404` |
| `POST /v1/operator/tenants` | Create. Body `tenantCreateSchema`. `id` optional, for a tenant already registered on-chain under a fixed id | `201 { tenant, adminKeys: [{ id, label, key }] }` — plaintext once. `400` with per-path issues, `409 origin-claimed` / `conflict` |
| `PATCH /v1/operator/tenants/:slug` | Update mutable fields: `rpName`, `expectedOrigins`, `allowedDappOrigins`, `corsOrigins`, `openRegistration`, `policy`, `branding`. Requires `If-Match: "<version>"` | `200`, `400`, `409 seed-managed`, `409 origin-claimed`, `412 version-mismatch`, `422 immutable-field` if the body names `slug`, `id`, `walletOrigin` or `rpId` |
| `POST /v1/operator/tenants/:slug/suspend` | `active → suspended`. Body `{ reason }`, recorded | `409 invalid-transition` |
| `POST /v1/operator/tenants/:slug/resume` | `suspended → active` | `409 invalid-transition` |
| `DELETE /v1/operator/tenants/:slug` | `suspended → deleted`, under §5.3 | `204`, the `409`s in §5.3 |
| `POST /v1/operator/tenants/:slug/admin-keys` | Issue a key. Body `{ label }`. Active tenants only | `201 { id, label, key }` — plaintext once. `409 seed-managed`, `409 invalid-transition` |
| `DELETE /v1/operator/tenants/:slug/admin-keys/:keyId` | Revoke. Refused if it is the last key and `openRegistration` is false | `204`, `409 seed-managed`, `409 last-admin-key` |
| `POST /v1/operator/tenants/:slug/adopt` | `managed_by: seed → operator`. Refused while the slug is still in the running process's `TENANTS_SEED` | `409 still-seeded` |
| `GET /v1/operator/tenants/:slug/history?before=` | `tenant_history`, newest first, 50 per page | `200 { entries, next }` |
| `GET /v1/operator/chains` | Blockchain status (§10) | `200` |

On a seed-managed tenant only suspend and resume are allowed (§5.1). The next boot does not
reactivate a seed-managed tenant an operator suspended, because `seedTenants` never touches
`status`.

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
| Seed slug matches an **operator-managed** row | Takeover: upsert, set `managed_by = 'seed'`, history `seed-takeover`, `WARN` log naming the slug. The admin-key set becomes the seed's, so operator-issued keys are removed. `status` is untouched. Immutability checks (`rpId`, `id`) still apply and still refuse boot on mismatch. |
| Seed slug matches a **deleted** row | Refuse boot: `tenant "<slug>" was deleted; a deleted tenant is never re-created` |
| Seed-managed row whose slug is no longer in the seed | Left as is. It stays seed-managed, limited to suspend and resume, until an operator adopts it (`POST …/adopt`). |

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
  variable `proxy_pass`, prefix re-appended), plus `proxy_set_header Origin "";`. The existing
  `connect-src 'self'` already covers it.
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
| **Sign-in** | Shown in place of the other two until the operator has a session. One button, *Sign in with wallet*: connects the wallet if needed, then runs §4.2 with the connected address and the selected chain. Shows which operator id and address are signed in and when the session expires. Any `401` returns here. |

### 11.3 Flows

**Sign in.** The wallet the console already connects for on-chain actions signs the challenge with
`personal_sign`. If the connected address is not an operator, sign-in fails with the generic `401`
and the console says the connected address is not on this deployment's operator list. The Tenants
tab shows whether the signed-in address also holds `TENANT_ADMIN_ROLE` on the selected chain, from
the roles the console already reads, and disables the on-chain steps below when it does not.

**Create.** The console does not duplicate the validator: a `400` comes back with per-path issues
(§7.1), and the form shows each against its field. On `201`, a modal shows the generated admin keys with copy buttons and the text *these
are shown once*. Then an optional second step: *Register on <chain>*, which calls the existing
`registerTenant(id, withdrawAddress, slug)` through the connected wallet and needs
`TENANT_ADMIN_ROLE`, as `TenantsPanel` does today. The dialog states the §1.3 limitation about
serving the wallet origin.

**Edit.** Fields pre-filled; the request carries `If-Match`. On `412`, the drawer reloads and shows
what changed.

**Suspend.** Reason required. After `200`, the console offers `setTenantEnabled(id, false)` on each
chain where the tenant is registered and enabled, and says why (§5.1, the authorisation window).
**Resume** offers the reverse.

**Delete.** Only on a suspended, operator-managed tenant. Type-the-slug confirmation, which also
says the slug, wallet origin and RP ID can never be used again (H-d). A `409` shows the per-chain
balance or open reservations from the response.

---

## 12. Risks and open items

| # | Item |
| --- | --- |
| **O-1** | **Blockchain status has no requirement.** §10 is a guess at the smallest useful thing. Needed: who looks at it (operators in the console, or an alerting path too), and whether "status" includes anything beyond node, bundler, paymaster and watcher, e.g. gas price, EntryPoint deposit trend, or per-tenant balance warnings. D5 can be dropped without touching D1–D4. |
| **O-2** | **Estimate.** The card says 3 SP and its estimation field says 2.5. D1–D4 plus D6's tenant half fit something near that. D5 and the Chains tab do not, and are the first thing to cut or split into a follow-up card. |
| **O-3** | **Devops (`infra/iac/`).** Three asks, none of them H5 deliverables: `OPERATOR_ADDRESSES` and `OPERATOR_SIWE_DOMAIN` as plain environment variables on `wallet-api` (addresses are public, so no ASM secret); `GIANO_WALLET_API_URL` on the `paymaster-admin` task; and a decision on restricting `paymaster.*` at the ALB (VPN CIDR or ALB OIDC). Wallet sign-in is the control; a network restriction is defence in depth for a host that now fronts write routes. |
| **O-4** | **Naming.** `paymaster-admin` now administers more than the paymaster. Renaming the package, image and ECR repository is a separate, mechanical change with an infra component. Not proposed here. |
| **O-5** | **Serving a runtime tenant's wallet origin** still needs infra (§1.3). The real fix is the Host-resolved `wallet-web` config already listed as unbuilt in [`ARCHITECTURE.md`](./ARCHITECTURE.md). Worth a card of its own, because until it lands "create a tenant at runtime" means "create the backend half at runtime". |
| **O-6** | **`INFRASTRUCTURE.md` R31** says `paymaster-admin` proxies `/api` to `wallet-api`. The nginx template does not. After D6 it will, and R31 becomes true; the doc should be checked against the template either way. |
| **O-7** | **Branding** is stored and editable through this API, and still read by nothing. Editing it in the console changes no UI. The console labels the field accordingly. |
| **O-8** | **The AWS dev `tenants-seed` secret** must be checked for overlapping origin claims (§6.2) before D3 deploys, or `wallet-api` will refuse to boot on dev. |
| **O-9** | **Wallets that skip the EIP-4361 domain check.** The phishing protection in §4.3 relies on the operator's wallet warning about a `domain` mismatch. MetaMask, Rabby and Ledger Live do; an arbitrary wallet may not. The operator list is small, so the mitigation is a written rule: operators sign in with one of those wallets, on a hardware device. |

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
| R1 — operator surface, not tenant-facing | §4: configured operator addresses, wallet sign-in, a separate guard, no cross-origin path |
| Blockchain status (provisional) | §10, §11.2 Chains tab — pending O-1 |

### Deliverables

| # | Files |
| --- | --- |
| D1 | `src/config.ts` (the `OPERATOR_*` variables in §4.1, `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS`), `src/routes/operator-auth.ts` (challenge, verify, logout), `src/services/operator-sessions.ts`, `src/plugins/auth.ts` (`requireOperator`), `scripts/operator-login.ts` |
| D2 | `migrations/0007_tenant_lifecycle.sql`, `src/db/schema.ts`, the challenge expiry sweep |
| D3 | `src/services/tenants.ts` (schema split, `checkTenantInvariants`, `checkOriginClaims`, seed ownership rules) |
| D4 | `src/routes/operator-tenants.ts`, `src/services/tenants.ts` (lifecycle-aware resolvers), `src/plugins/auth.ts` (`requireSession` change), `src/app.ts` (registration when `OPERATOR_ADDRESSES` is non-empty), `openapi/` |
| D5 | `src/routes/operator-chains.ts`, `src/services/chains.ts` (keep last verification), `src/index.ts` (prober stores it) |
| D6 | `services/paymaster-admin/docker/{nginx.conf.template,entrypoint.sh,config.json}`, `src/config.ts`, `src/lib/operator-api.ts`, `src/lib/operator-session.ts`, `src/operator/{SignIn,TenantsTab,TenantDrawer,ChainsTab}.tsx`, `src/App.tsx` |

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
  open reservation → `409`; stale ledger → `409`; no ledger rows at all → allowed; success → user
  sessions and keys gone, `userop_log` rows intact, slug unusable by a later create.
- **Seed-managed writes.** `PATCH`, key issue, key revoke and delete → `409 seed-managed`; suspend
  and resume → `200`.
- **Seed coexistence.** Each row of the §9 table, including that a restart does not reactivate a
  suspended seed-managed tenant and does not write a history row when nothing changed.
- **Operator sign-in.** A valid challenge signed by a listed EOA → session. Each of these → `401`
  with identical bodies: a signature by a different key; an address not in the list; a reused nonce;
  an expired challenge; a message with another `domain`, `uri` or `version`; a message the API did
  not issue. Two concurrent verifies of one nonce → exactly one session. A challenge for an unlisted
  address returns the same shape as for a listed one and stores nothing.
- **Operator guard.** No token / wrong token / expired / revoked / tenant admin key → `401` with
  identical bodies; any `Origin` header → `403`, including on challenge and verify; a session token
  on `/v1/admin/*` → `401`; a session whose address was removed from `OPERATOR_ADDRESSES` → `401`
  after restart; `OPERATOR_ADDRESSES` empty → every operator route `404`; a duplicate id or address
  in the list → boot refuses.
- **Attribution.** Every operator write's `tenant_history` row carries `operator:<id>:<address>`
  and the session id.
- **No restart.** Create a tenant through the API, then in the same process: `GET
  /.well-known/webauthn` with its Host resolves, and `POST /v1/webauthn/options` with its Origin
  resolves.

### 14.2 E2E (`e2e/tests/operator.spec.ts`)

Against the two-tenant compose stack, with an anvil account listed in `OPERATOR_ADDRESSES` in
`deploy/docker-compose.e2e.yml`, `OPERATOR_SIWE_DOMAIN=paymaster.localhost` and
`OPERATOR_SIWE_URI=http://paymaster.localhost`. API steps take their
token from `operator-login` with that account's key:

1. Suspend `byo` through the API; connecting from `app-byo.localhost` fails. Resume; it succeeds.
   Tenant `stock` is unaffected throughout.
2. Create tenant `runtime` with walletOrigin `http://wallet-runtime.localhost`; `GET
   http://api.localhost/.well-known/webauthn` with `Host: wallet-runtime.localhost` returns its
   document with no container restarted.
3. Console smoke: connect the anvil account through the injected test provider and *Sign in with
   wallet*. The registry shows `stock`, `byo` and `runtime`; `stock` and `byo` show
   *registered · enabled* against the devnet paymaster, and `runtime` shows *not registered*.

### 14.3 Acceptance on dev

Run with a throwaway EOA that is listed in dev's `OPERATOR_ADDRESSES` and nowhere else.

```fish
set -l base https://api.dev.giano.appliedblockchain.dev/v1/operator

# operator routes exist and refuse anonymous callers
curl -s -o /dev/null -w '%{http_code}\n' $base/tenants
# → 401

# sign in the way the console does, from a script
set -l token (OPERATOR_PRIVATE_KEY=$H5_ACCEPTANCE_KEY \
  pnpm -s -F @appliedblockchain/giano-wallet-api operator-login --api https://api.dev.giano.appliedblockchain.dev)
set -l auth "Authorization: Bearer $token"

# a valid session is still refused when a browser could have sent the request
curl -s -o /dev/null -w '%{http_code}\n' -H $auth -H 'Origin: https://evil.example' $base/tenants
# → 403

# create, read, suspend and delete a throwaway tenant without a deploy.
# A deleted slug can never be reused (H-d), so every run takes a fresh one.
set -l slug h5-acceptance-(date +%s)
curl -s -H $auth -H 'Content-Type: application/json' -X POST $base/tenants -d "{
  \"slug\": \"$slug\", \"walletOrigin\": \"https://$slug.invalid.example\",
  \"rpName\": \"H5 acceptance\", \"adminKeys\": [{ \"label\": \"acceptance\" }] }" | jq '.tenant.id'
curl -s -H $auth $base/tenants/$slug | jq '{status, managedBy, version}'
curl -s -H $auth -H 'Content-Type: application/json' -X POST $base/tenants/$slug/suspend -d '{"reason":"acceptance"}'
curl -s -H $auth -X DELETE -o /dev/null -w '%{http_code}\n' $base/tenants/$slug   # → 204
curl -s -H $auth "$base/tenants?status=deleted" | jq '.tenants[].slug'            # includes $slug
curl -s -H $auth $base/tenants/$slug/history | jq '.entries[].actor' | sort -u     # → "operator:<id>:<address>"

# logout ends the session
curl -s -H $auth -X POST -o /dev/null $base/auth/logout
curl -s -o /dev/null -w '%{http_code}\n' -H $auth $base/tenants
# → 401
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
