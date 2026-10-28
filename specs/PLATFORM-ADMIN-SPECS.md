# Giano — platform admin: runtime tenants and blockchain status

This document is the **how** for H5 (*Admin application for tenants, blockchain status*, 3 SP),
whose **what** is the requirement reproduced in [§2](#2-the-requirements). It specifies a
platform tier in `wallet-api`, the tenant lifecycle it manages, how runtime writes keep the
invariant tenant ≡ wallet origin ≡ RP ID, how they replaced `TENANTS_SEED`, and the console
that drives them.

A **platform admin** is one of Giano's own staff who manages tenants and the other platform
admins. The role was called *operator* until it was renamed; migration `0007_tenant_lifecycle.sql`
and the stored value `managed_by = 'operator'` still carry the old name (§5.2). It is distinct from
a tenant's admin keys and `/v1/admin/*` routes, which are scoped to one tenant.

Everything asserted about the current state in [§3](#3-current-state-verified) was read out of this
repository on 2026-10-06 and re-verified against `main` at `5f0ce0e` on 2026-10-21; each claim
carries its evidence. [§13](#13-traceability) maps the requirement and every deliverable to the
section that specifies it.

Status: **revised after verification, 2026-10-21.** The review corrected the challenge sweep
(§5.2), the reservation check (§5.3), the sign-in checks (§4.3), the console proxy (§11.1) and
the scope of the blockchain-status half (H-k). [§12](#12-risks-and-open-items) lists what still
needs a call. O-1 (the blockchain-status requirements) is the only one that changes scope, and it
no longer blocks R1.

---

## Contents

1. [Scope and decisions](#1-scope-and-decisions)
2. [The requirements](#2-the-requirements)
3. [Current state, verified](#3-current-state-verified)
4. [Platform admin authority](#4-platform-admin-authority)
5. [Tenant lifecycle and data model](#5-tenant-lifecycle-and-data-model)
6. [Keeping the invariant under runtime writes](#6-keeping-the-invariant-under-runtime-writes)
7. [Platform API](#7-platform-api)
8. [Resolution under the lifecycle](#8-resolution-under-the-lifecycle)
9. [Retiring `TENANTS_SEED`](#9-retiring-tenants_seed)
10. [Blockchain status](#10-blockchain-status)
11. [The console](#11-the-console)
12. [Risks and open items](#12-risks-and-open-items)
13. [Traceability](#13-traceability)
14. [Testing and acceptance](#14-testing-and-acceptance)

---

## 1. Scope and decisions

### 1.1 What H5 delivers

A platform admin — Giano's own staff, never a tenant — can create, read, update, suspend and delete
tenants against a running deployment, and the change takes effect on the next request. Nothing is
redeployed and no process restarts.

Concretely, six deliverables:

| # | Deliverable | Where |
| --- | --- | --- |
| **D1** | Platform admin sign-in with a wallet (EIP-4361) against a `platform_admins` table the platform admins manage themselves, short-lived platform admin sessions, a `requirePlatformAdmin` guard, and routes that refuse browser cross-origin calls outright | `wallet-api` — [§4](#4-platform-admin-authority) |
| **D2** | Tenant lifecycle columns, an append-only `tenant_history`, platform admin challenge and session tables, migration `0007_tenant_lifecycle.sql` | `wallet-api` — [§5](#5-tenant-lifecycle-and-data-model) |
| **D3** | One validation path for every tenant write, with the cross-tenant origin check the retired seed never did | `services/tenants.ts` — [§6](#6-keeping-the-invariant-under-runtime-writes) |
| **D4** | `/v1/platform/tenants/*` routes, and every tenant resolver made lifecycle-aware | `wallet-api` — [§7](#7-platform-api), [§8](#8-resolution-under-the-lifecycle) |
| **D5** | `/v1/platform/chains`, a server-side status read per served chain. *Follow-up card (H-k).* | `wallet-api` — [§10](#10-blockchain-status) |
| **D6** | A *Platform* area in the existing console: wallet sign-in, tenant registry, create/edit/suspend/delete, key issue/revoke, chain status | `services/paymaster-admin` — [§11](#11-the-console) |

D1–D4 and D6's tenant half satisfy R1. D5 and D6's chain half are the provisional answer to the
*blockchain status* half of the card, which has no requirements yet (O-1). They move to a card of
their own (H-k) and are specified here only so that card starts from something.

Delivery, in order:

| PR | Contents | Satisfies |
| --- | --- | --- |
| **1** | D2 → D3 → D1 → D4: migration, single validator, platform admin sign-in, platform routes and lifecycle-aware resolution, with the `wallet-api` tests in §14.1 and E2E steps 1–2 in §14.2 | R1 through the API |
| **2** | D6's tenant half: console proxy, sign-in, Tenants tab, E2E step 3 | R1 in the console |
| follow-up card | D5 and the Chains tab, once O-1 has an answer | blockchain status |

### 1.2 Decisions taken in this spec

| # | Decision | Why |
| --- | --- | --- |
| **H-a** | **The platform tier is new routes on `wallet-api`**, under `/v1/platform`, not a new service. | `wallet-api` already owns the tenants table, the validation, the ledger and the chain registry. A second service writing the same table would need its own copy of the invariant, and two copies drift. Same reasoning as PAYMASTER-SPECS S1. |
| **H-b** | **Platform admins sign in with a wallet.** The `platform_admins` table lists `{ id, address }`; a platform admin signs an EIP-4361 message and gets a 30-minute session. Platform admins add and remove platform admins in the console. The init step writes an environment's bootstrap platform admins (`src/environments.ts`) into an empty table only. The platform routes are not registered in an environment with no sign-in domain. | No shared secret exists to copy or leak, a hardware wallet is the second factor, and the API identity is the same address that signs the on-chain tenant actions. **This reverses the original decision** that the list is "configuration, never rows" so that a database write could not mint a platform admin. A config-only list meant a redeploy for every change. That risk is now accepted, and mitigated: only a signed-in platform admin reaches the management routes, every change is recorded in `platform_admin_history`, and nobody can remove themselves or the last platform admin. The sign-in domain is still code, never a row (§4.1). [§4](#4-platform-admin-authority). |
| **H-c** | **Platform admin routes refuse any request that carries an `Origin` header.** The console reaches them through its own nginx proxy, which strips it. | The CORS plugin grants ACAO to every tenant's `cors_origins` on every route. Refusing `Origin` on `/v1/platform/*` means no browser page on any origin can call these routes cross-origin, whatever CORS says, and the check is one line. [§4.5](#45-no-browser-cross-origin-path). |
| **H-d** | **Delete is a tombstone.** A deleted tenant's row stays, with `status = 'deleted'`; its slug, id, wallet origin and RP ID are never reusable. | The id keys the tenant's balance on every paymaster, which nothing off-chain can delete. `userop_log`, `wallet_management_log`, `users` and `credentials` reference `tenants` without cascade, and they are records we keep. And an RP ID handed to a new tenant would inherit every passkey users still hold for the old one. [§5.3](#53-delete). |
| **H-e** | **Suspend before delete, and delete refuses while money is attached.** | Suspend is immediate and reversible, so it is the incident tool. Delete is irreversible, so it requires the reversible step first and a zero balance and no open reservations on every chain. [§5](#5-tenant-lifecycle-and-data-model). |
| **H-f** | **`slug`, `id`, `walletOrigin` and `rpId` are immutable through the API.** | `rpId` is immutable today (passkeys bind to it); `walletOrigin` must keep its host equal to `rpId` (D1 in `tenants.ts`), so it is immutable with it. `id` is the paymaster key. `slug` is what platform admins address a tenant by. A tenant that needs a new origin is a new tenant. |
| **H-g** | **Every tenant write goes through one validator**, and that validator gains a cross-tenant check: no origin may be claimed by two tenants. | `getByOrigin` resolves `wallet_origin OR origin = ANY(expected_origins)` with `findFirst`. Two tenants claiming the same origin resolve to whichever row Postgres returns first. The seed schema checked duplicate `walletOrigin` and `rpId` but not `expectedOrigins`, a latent gap that runtime writes would have made reachable. [§6.2](#62-origin-claims-are-disjoint). |
| **H-h** | **Platform admins are the only writers of a live deployment's tenants; `TENANTS_SEED` is retired.** `wallet-api` no longer reads it and boots with zero tenants. Tenants an earlier version seeded are handed to the platform admins once, at boot. Local stacks get their test tenants from the insert-only init step (`dist/init.js`), which refuses `TENANT_FIXTURES` on any environment that is not a local stack. | Two writers of one row needed an ownership rule: a seed-managed tenant could not be edited without a redeploy, and a seed entry silently took over a platform-admin-managed tenant at the next boot. One writer needs no rule. [§9](#9-retiring-tenants_seed). |
| **H-i** | **Admin keys are generated by the server** and returned once. The API never accepts a caller-chosen admin key. | A generated key has full entropy and cannot collide with another tenant's key. Only the local-stack fixtures take plaintext keys (§9). |
| **H-j** | **The console is the existing `paymaster-admin`**, gaining a Platform area. The image and package keep their names. | It is already the console Giano's staff use, already deployed at `paymaster.*`, and already holds the on-chain roster. Joining the registry to that roster on tenant id is what lets a platform admin see a tenant that exists in one place and not the other. Renaming the image touches ECR and Terraform, which is devops territory (O-4). |
| **H-k** | **H5 delivers R1 only. Blockchain status (D5 and the Chains tab) is a separate card.** | The card is estimated at 3 SP and D1–D4 with D6's tenant half already fill it. Blockchain status has no requirement (O-1), and §10 needs new code the original draft did not count: a bundler method, a prober that records its results, a resolver in the console image. Splitting lets R1 ship without waiting on O-1. |
| **H-l** | **Verify accepts only the exact text the server issued.** The challenge row stores the message, and verify requires the signed text to match it byte for byte. | `validateSiweMessage` in viem 2.31.6 does not check `issuedAt`, `uri`, `version` or `chainId`, and checks no time window at all when `expirationTime` is absent. Matching the stored text checks every field at once, against values only the server chose. [§4.3](#43-what-verify-checks). |

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
- **Sponsorship configuration for a runtime tenant.** Sponsorship rules are per tenant and per
  chain, and are written with the tenant's own admin key through `PUT /v1/admin/sponsorship`.
  That is how `src/provision-sponsorship.ts` installs them on a deployment today. A tenant created
  here gets admin keys and no rules, so it is not sponsored until someone uses one of those keys to
  `PUT` its rules. The console's create dialog says so. A platform route for sponsorship rules
  would be a second writer of rules the tenant owns, and is not proposed.
- **Fees, treasury, roles.** Unchanged; already in the console.
- **`infra/iac/`.** The network restriction on `/v1/platform/*` is raised as O-3 for devops. The
  `wallet-api` and `paymaster-admin` environment variables and the init container have since landed
  in Terraform.
- **Blockchain status.** D5 and the Chains tab, per H-k.

---

## 2. The requirements

Reproduced from the H5 page so this document stands alone.

**R1 — Tenants can be created, read, updated and deleted at runtime, without a redeploy.**

This is Giano's own admin application, for us: a platform admin surface, not a tenant-facing one.

**Blockchain status** is named in the card's title with no requirement attached. [§10](#10-blockchain-status)
specifies a provisional read-only status view so the console has somewhere to put it; O-1 asks for
the real requirement.

---

## 3. Current state, verified

This is the repository H5 started from. The seed rows below describe `TENANTS_SEED`, which has
since been retired (§9).

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
| The paymaster exposes `registerTenant`, `setTenantEnabled` under `TENANT_ADMIN_ROLE` and `setTenantWithdrawAddress` under `WITHDRAW_ADDRESS_ADMIN_ROLE` (timelocked since G9); nothing deregisters | ✅ | `packages/contracts/src/paymaster/GianoPaymaster.sol:394-419` |
| `paymaster-admin` reads the chain only; it has no route to `wallet-api` | ✅ | `services/paymaster-admin/docker/nginx.conf.template` has `/rpc/<chainId>` locations and no `/api`, and its comment says a variable `proxy_pass` "would need a resolver this image cannot assume". `wallet-web` already solves that by taking the resolver from `/etc/resolv.conf` (`services/wallet-web/docker/entrypoint.sh`). [`INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) R31 says the console proxies `/api`; the template disagrees. |
| The console reloads when the wallet changes | ✅ | `services/paymaster-admin/src/App.tsx` reloads on `accountsChanged` **and** `chainChanged`; switching deployment drops the wallet connection |
| Per-chain status is already tracked: boot verification, a background prober, `/v1/version` exposing `ready`/`unavailable` | ⚠️ partly | `src/services/chain-verify.ts`, `src/index.ts:87-130`, `src/routes/health.ts`. For a `ready` chain the prober only calls `getChainId()` and keeps no result; a full `ChainVerification` exists only from boot and from recovery attempts. |
| The bundler client can report the EntryPoints it supports | ❌ | `src/services/bundler.ts` exposes send, estimate, receipt and by-hash only; `routes/bundler-relay.ts` answers `eth_supportedEntryPoints` from configuration, not from the bundler |
| Paymaster position per chain is already persisted by the watcher | ✅ | `paymaster_state` (deposit, treasury, stake, invariant slack, last synced block) and `paymaster_tenants`. The watcher runs only where `PAYMASTER_WATCHER_ENABLED` is set, and its cursor trails the head by `PAYMASTER_WATCHER_CONFIRMATIONS`. |
| Expired sponsorship reservations are marked `expired` | ⚠️ only by the watcher | `ledger.expireStale()` is called from the watcher's poll only (`src/services/paymaster-watcher.ts`); with no watcher, an expired reservation stays `reserved` |
| Expired tenant challenges are swept | ❌ | `challenges.prune()` exists (`src/services/challenges.ts:48`) and nothing calls it |
| Sessions carry a tenant | ❌ | `sessions` has no `tenant_id`; a session's tenant is its user's (`src/db/schema.ts`, `sessions`) |
| Fastify sees the client's IP | ❌ | `trustProxy` is not set, so behind the ALB or the console's nginx `request.ip` is the proxy's address |

---

## 4. Platform admin authority

A platform admin signs in with an Ethereum wallet, using Sign-In with Ethereum
([EIP-4361](https://eips.ethereum.org/EIPS/eip-4361)). The `platform_admins` table says which addresses
are platform admins, and the platform admins manage it. A verified signature buys a short-lived
platform admin session, and that session is what the platform routes accept.

The console already connects a wallet for every on-chain action, so the person who signs in to the
API and the person who signs `registerTenant` or `setTenantEnabled` are the same identity, and the
history records the address. There is no shared secret to copy, rotate or leak, and a platform admin
who uses a hardware wallet gets a second factor without the API implementing one.

### 4.1 Configuration

What an environment *is* lives in code, in `src/environments.ts`, keyed by the required variable
`GIANO_ENVIRONMENT` (`dev`, `stg`, `prd`, `reference`, `e2e`, `local-infra`, `local-dev`,
`local-sepolia`, `test`; Terraform sets it to `terraform.workspace`):

```ts
// src/environments.ts (abridged)
dev:   { siweDomain: 'paymaster.dev.giano.appliedblockchain.dev', bootstrapAdmins: [GIOVANNI], localStack: false },
e2e:   { siweDomain: 'paymaster.localhost', siweUri: 'http://paymaster.localhost',
         bootstrapAdmins: [ANVIL_3, ANVIL_0, GIOVANNI], localStack: true },
reference: { siweDomain: null, bootstrapAdmins: [], localStack: false },
```

- `siweDomain` / `siweUri` are the console's host and URI, the `domain` and `uri` every sign-in
  message must carry. `siweUri` defaults to `https://<siweDomain>`. They are never stored in the
  database, because a wrong value would sign every platform admin out, including whoever set it. They
  change only with a release. `null` means the environment runs no console (`reference`,
  `local-dev`, `local-sepolia`): no platform route is registered, and a console pointed at it
  reports *platform API disabled on this deployment*.
- `bootstrapAdmins` are written by the init step (§9) **only into an empty `platform_admins` table**,
  recorded in `platform_admin_history` as `bootstrap` by `bootstrap:<environment>`. Once a database has a
  platform admin, the table is the platform admins' to manage, and a later release that changes this list
  changes nothing there. Addresses are public, so committing them is safe.
- `localStack` marks a compose stack on a developer machine or in CI. Only these may load
  `TENANT_FIXTURES` (§9).

The `platform_admins` table (migration `0008_platform_admins.sql`):

- `id` is a label, `^[a-z0-9-]{1,64}$`. Both `id` and `address` are unique; adding a duplicate is
  `409 conflict`.
- Addresses are stored lowercase. They are EOAs: the signature is checked by ECDSA recovery, so a
  Safe or other contract account cannot be a platform admin (§4.3).
- `added_by` is `bootstrap:<environment>` or `platform-admin:<id>:<address>`.

Platform admins manage platform admins through four routes, behind the same guard and rate limit as the tenant
routes (`src/routes/platform-admins.ts`, `src/services/platform-admins.ts`):

| Route | Does |
| --- | --- |
| `GET /v1/platform/admins` | the platform admins, oldest first |
| `POST /v1/platform/admins` | `{ id, address }`; the new platform admin can sign in at once. `201` |
| `DELETE /v1/platform/admins/:id` | removes the platform admin and revokes their open sessions. `409 self-removal` for your own row, `409 last-admin` for the only one. `204` |
| `GET /v1/platform/admins/history` | the latest 100 entries of `platform_admin_history` (`bootstrap`, `add`, `remove`), newest first |

Writes to the table are serialised by a Postgres advisory lock, so the last-admin check cannot
race.

| Variable | Default | Meaning |
| --- | --- | --- |
| `GIANO_ENVIRONMENT` | required | which entry of `src/environments.ts` this is |
| `PLATFORM_CHALLENGE_TTL_SECONDS` | `300` | how long a nonce stays usable |
| `PLATFORM_SESSION_TTL_SECONDS` | `1800` | absolute session lifetime; no sliding renewal |
| `PLATFORM_RATE_LIMIT_PER_MINUTE` | `60` | per platform admin session. Challenge is limited to the same rate per requested address and verify per address parsed from the message, under a deployment-wide sign-in ceiling of ten times the rate. Not per IP: without `trustProxy` every request arrives from the proxy's address (§3). |

Adding or removing a platform admin needs no restart. Removal takes effect on the next request of any
open session, because removal revokes the platform admin's sessions and the guard re-checks the address
against the table on every request (§4.4).

### 4.2 Sign-in

```
console                               wallet-api                         wallet
   │ POST /v1/platform/auth/challenge     │                                   │
   │   { address, chainId }  ───────────► │ address ∈ platform_admins?        │
   │                                      │ insert platform_admin_challenges  │
   │ ◄─── { message }  (EIP-4361 text)    │                                   │
   │ personal_sign(message) ──────────────┼─────────────────────────────────► │
   │ ◄────────────────────────────────────┼──────────────────── signature ─── │
   │ POST /v1/platform/auth/verify        │                                   │
   │   { message, signature } ──────────► │ checks in §4.3, consume nonce     │
   │                                      │ insert platform_admin_sessions    │
   │ ◄─── { token, expiresAt, admin }     │                                   │
```

**Challenge.** `POST /v1/platform/auth/challenge` with `{ address, chainId }`. An address not in the
list gets the same `200` shape as one that is, with a message whose nonce is never stored, so the
endpoint does not reveal who the platform admins are. For a listed address the API generates a nonce with
`generateSiweNonce` from `viem/siwe` (viem 2.31.6, already a dependency), builds the message with
`createSiweMessage`, stores the nonce **and the exact message text** (H-l), and returns the message:

| Field | Value |
| --- | --- |
| `domain` | the environment's `siweDomain` (§4.1) |
| `uri` | the environment's `siweUri` |
| `address` | the requested address, checksummed |
| `statement` | `Sign in to the Giano platform console. This grants access to tenant administration for <N> minutes.` |
| `version` | `1` |
| `chainId` | the console's selected chain; recorded, not checked against anything |
| `nonce` | the stored nonce |
| `issuedAt` / `expirationTime` | now / now + `PLATFORM_CHALLENGE_TTL_SECONDS` |

The API builds the message and the console only relays it. Because the challenge row keeps the
text, the server only ever accepts text it wrote, and the console has no say over which domain the
platform admin is asked to sign for.

**Verify.** `POST /v1/platform/auth/verify` with `{ message, signature }`. On success:
`{ token, expiresAt, admin: { id, address } }`. The token is 32 random bytes, base64url, prefixed
`gps_`, and stored as a sha256 hash.

**Logout.** `POST /v1/platform/auth/logout` sets `revoked_at` on the presented session.

### 4.3 What verify checks

In order. Step 4 is the only write, and the session row is inserted only after it succeeds:

1. `parseSiweMessage(message)` succeeds and yields a `nonce` and an `address`.
2. `recoverMessageAddress({ message, signature })` equals that `address`. ECDSA only, with
   no ERC-1271 call, so verify needs no RPC and works when every chain is down, which is when a
   platform admin most needs to sign in.
3. The address is in the `platform_admins` table.
4. The challenge is consumed atomically, and only if the signed text is the text issued for it:
   `UPDATE platform_admin_challenges SET used_at = now() WHERE nonce = $1 AND address = $2 AND message = $3 AND used_at IS NULL AND expires_at > now() RETURNING nonce`.
   No row means replayed, expired, altered or never issued.

Step 4 is what checks `domain`, `uri`, `version`, `chainId`, `statement` and the time window. The
stored text carries the values the server chose, and `expires_at` is the server's own clock.
`validateSiweMessage` is not used: in viem 2.31.6 it checks `domain`, `nonce`, `scheme`,
`expirationTime`, `notBefore` and `address`, and not `issuedAt`, `uri`, `version` or `chainId`
(H-l).

Any failure is `401 unauthorized` with one body, whatever the cause, and increments
`giano_platform_auth_failures_total{reason}` with the specific reason for us to see.

**Why the domain matters.** The API never sees the browser's `Origin` (§4.5), so the binding between
a signature and the console is the message's `domain`. Wallets that implement EIP-4361 (MetaMask,
Rabby, Ledger Live) warn when a page asks for a signature on a message whose `domain` is not the
page's own. A phishing page that obtains a challenge for our domain and asks a platform admin to sign it
triggers that warning. A wallet that does not implement the check would not warn (O-9).

### 4.4 The guard

`plugins/auth.ts` gains `requirePlatformAdmin`, alongside `requireAdmin`:

1. Refuse with `403 platform-origin-refused` if the request carries an `Origin` header (§4.5).
2. Take the bearer token, sha256 it, and load the `platform_admin_sessions` row by hash where
   `revoked_at IS NULL AND expires_at > now()`.
3. Confirm the row's address is still in the `platform_admins` table. Removing a platform admin also revokes
   their sessions, and this check ends any that remain at their next request.
4. On any failure, `401 unauthorized`, with the same body as an invalid token anywhere else.
5. On success, set `request.platformAdmin = { id, address, sessionId }`, with `id` taken from the
   current `platform_admins` row for that address, and log with `admin: id`.

A tenant admin key on `/v1/platform/*` fails at step 2 because it is not a session hash. A platform admin
session token on `/v1/admin/*` fails `requireAdmin` because it is not in `tenant_admin_keys`. The two
tiers never share a lookup.

The challenge and verify routes run step 1 only. Logout runs the whole guard.

### 4.5 No browser cross-origin path

Browsers attach `Origin` to every cross-origin request and to every non-GET same-origin request.
Refusing `Origin` on every `/v1/platform/*` route closes the cross-origin path regardless of what
the CORS plugin answers on preflight. The console calls the API through a same-origin `/api/`
location in its own nginx, which does `proxy_set_header Origin "";`, so its requests arrive without
one. Scripts never send it.

This is a cheap extra layer, not the access control. Platform admin sessions are bearer tokens held in
page state, and the browser never attaches them by itself, so cross-site request forgery is not
the threat it guards against. What controls access is the signature (§4.3) and the session (§4.4).

### 4.6 State and storage

Challenges and sessions are rows (§5.2), because `wallet-api` runs more than one replica and a nonce
issued by one must be consumable by another. Who is a platform admin is a row too, in `platform_admins`
(§4.1): the guard ignores any session whose address is not in that table, so removing a platform admin
ends their sessions at once.

The console keeps the session token in React state only, never in `localStorage` or
`sessionStorage`. A reload signs in again, which costs one wallet prompt. The console already
reloads on `accountsChanged` and `chainChanged`, so switching the wallet's account or chain also
drops the platform admin session, and the API identity cannot drift away from the connected wallet.
Switching deployment in the console drops the wallet connection without a reload, so
`selectDeployment` must clear the platform admin token as well. Signing in again after a chain switch is
the accepted cost.

### 4.7 Scripts and tests

`scripts/platform-login.ts` (`pnpm -F @appliedblockchain/giano-wallet-api platform:login`, named
like the existing `verify:authorisation`) runs the same challenge and verify against a given API
URL, with a private key from `PLATFORM_ADMIN_PRIVATE_KEY`, and prints a session token. It exists for
acceptance on dev (a throwaway EOA listed only on dev). The e2e suite already depends on viem
2.31.6 and signs in-process with an anvil account instead of shelling out. A real platform admin uses
the console and their own wallet.

---

## 5. Tenant lifecycle and data model

### 5.1 States

```
         create (platform admin)         suspend
   ──────────────────────────► active ◄──────────► suspended ──── delete ───► deleted
   fixture (local stacks) ───►         resume                      (terminal)
```

| State | Resolves on ceremony / Host / admin key / session / CORS | Watcher and ledger | Platform admin actions |
| --- | --- | --- | --- |
| `active` | yes | yes | edit fields, issue and revoke keys, suspend |
| `suspended` | **no**, as if unknown | yes: settlements and reconciliation keep running, because on-chain events for this tenant still happen | resume, revoke keys, delete |
| `deleted` | no | yes, for the same reason | none |

Suspension does not delete the tenant's user sessions. Resolution refuses them while suspended, and resume restores
whatever has not expired. Delete removes the tenant's sessions (found through `users`, since
`sessions` has no tenant column), open challenges, pending additions and admin keys in the same
transaction.

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

-- every existing row came from TENANTS_SEED, or is the 0002 'default' backfill (rp_id
-- 'migrated.invalid') that only a seed entry can claim, so 'seed' is the correct backfill for both

CREATE INDEX tenants_status_idx ON tenants (status);

ALTER TABLE tenant_admin_keys
  ADD COLUMN created_by text NOT NULL DEFAULT 'seed';   -- 'operator:<id>:<address>' | 'fixture' | 'seed' (retired)

CREATE TABLE operator_challenges (
  nonce       text PRIMARY KEY,
  address     text NOT NULL,                 -- lowercase
  message     text NOT NULL,                 -- the exact EIP-4361 text issued (H-l)
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX operator_challenges_expires_idx ON operator_challenges (expires_at);

CREATE TABLE operator_sessions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash  text NOT NULL UNIQUE,          -- sha256 hex of the gos_ token
  operator_id text NOT NULL,                 -- the operators.id at sign-in
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
  actor       text NOT NULL,   -- 'operator:<id>:<address>' | 'fixture' | 'system:tenants-seed-retirement'
                               -- | 'seed' (retired)
  operator_session_id uuid REFERENCES operator_sessions(id),  -- null unless an operator wrote it
  before      jsonb,           -- the tenant row before; null on create
  after       jsonb,           -- the tenant row after
  detail      jsonb,           -- e.g. { keyId, label, hashPrefix } for key actions
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenant_history_tenant_idx ON tenant_history (tenant_id, created_at);
```

The role was called *operator* when 0007 was written, so its tables carry that name. Migration
`0008_platform_admins.sql` renames them: `operator_challenges` → `platform_admin_challenges`,
`operator_sessions` → `platform_admin_sessions` (column `operator_id` → `admin_id`), and
`tenant_history.operator_session_id` → `platform_admin_session_id`. It rewrites the actors already
recorded as `operator:<id>:<address>` to `platform-admin:<id>:<address>`, and the session token
prefix is now `gps_`.

0008 also adds the platform admins themselves (§4.1): `platform_admins (id, address,
added_by, created_at)`, and an append-only `platform_admin_history (admin_id, address, action, actor,
platform_admin_session_id, created_at)` with `action` one of `bootstrap | add | remove`. History rows
outlive the platform admin they describe, so they have no foreign key to `platform_admins`.

No sweep exists today: `challenges.prune()` is defined and never called (§3). D2 adds one, an
unref'd interval in `src/index.ts` next to the chain prober. It calls `challenges.prune()` and
deletes `platform_admin_challenges` rows that expired more than a day ago. Every replica may run it,
because the deletes are idempotent. Platform admin sessions are kept: they are the record of who signed
in when, `tenant_history` references them, and a handful of platform admins signing in a few times a day
produces a negligible number of rows.

`version` increments on every write and is the ETag for `PATCH` (§7.2). `before` and `after` never
contain key material: admin keys are recorded in `detail` as id, label and the first 8 hex chars of
the hash.

`managed_by` and the `seed-apply` and `seed-takeover` actions belong to the retired `TENANTS_SEED`.
`managed_by` is dropped by `0009_drop_tenant_managed_by.sql`, after the release whose boot step
handed every seed-managed tenant to the platform admins (§9). Nothing writes the two actions any
more; they stay for the history the seed left.

### 5.3 Delete

`DELETE /v1/platform/tenants/:slug` succeeds only when, in one transaction holding a row lock on the
tenant:

1. `status = 'suspended'` — otherwise `409 tenant-not-suspended`;
2. on every chain, `paymaster_tenants.balance_wei = 0` and `deficit_wei = 0`, where a chain with no
   row counts as zero — otherwise `409 tenant-has-funds`, with per-chain figures and the
   `last_synced_block` they were read at;
3. no `sponsorship_reservations` with `state = 'reserved' AND expires_at > now()` — otherwise
   `409 tenant-has-reservations`. The `expires_at` condition is needed because only the watcher marks
   reservations `expired` (§3). Without it, a reservation that expired while no watcher ran would
   block the delete forever. The ledger already treats an expired reservation as not counting.

Then: `status = 'deleted'`; delete `sessions`, `challenges`, `pending_additions` and
`tenant_admin_keys` for the tenant; append `tenant_history`. Everything else stays.

The ledger in check 2 is a cache rebuilt from events. If, on any sponsoring chain,
`paymaster_state.last_synced_block` is more than `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS` (new,
default 50) behind the chain head, delete refuses with `409 ledger-stale` rather than trusting an
old zero. A chain that cannot be reached for its head counts as stale. The heads are read before
the transaction opens, so no RPC call runs while the row lock is held.

- The watcher's cursor trails the head by `PAYMASTER_WATCHER_CONFIRMATIONS` by design, so boot
  refuses a `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS` that is not greater than it.
- A deployment that sponsors but runs no watcher has a null `last_synced_block`. There, delete
  always refuses with `ledger-stale`, which is intended: nothing is checking the ledger.

The API cannot move an on-chain balance, and the normal path is the tenant's: only the registered
withdraw address can call `withdrawTenant`. So a tenant with funds is deleted by asking the tenant
to withdraw, which is the correct order of events anyway.

There is an on-chain exception. A holder of `WITHDRAW_ADDRESS_ADMIN_ROLE` can call
`setTenantWithdrawAddress`, so the role can redirect a tenant's withdrawal and then withdraw. That
is the recovery path for a balance its tenant has abandoned. Since G9 the role is held by the
paymaster's timelock in production, so a redirect is a public, queued proposal that waits its
published delay; the console builds the proposal rather than sending it. It is never an API
action.

---

## 6. Keeping the invariant under runtime writes

### 6.1 One validator

The seed's `tenantSeedSchema` mixed three things: field shapes, the single-tenant invariant (rpId ≡
walletOrigin host, expectedOrigins under rpId, admin keys required when registration is closed),
and seed-only input (plaintext `adminKeys`). It is split into:

| Piece | Used by |
| --- | --- |
| `tenantFieldsSchema` — field shapes only, `.strict()` | fixtures, create, update |
| `checkTenantInvariants(fields, { adminKeyCount })` — the single-tenant rules, returning issues with paths | fixtures, create, update |
| `tenantFixtureSchema` (`services/tenant-fixtures.ts`) — `tenantFieldsSchema` + `adminKeys: string[]`, calling `checkTenantInvariants` with `adminKeys.length` | local-stack fixtures (§9) |
| `tenantCreateSchema` — `tenantFieldsSchema` + `adminKeys: { label }[]`, same call | create |
| `tenantPatchSchema` — the mutable subset, all optional | update |

`.strict()` means an unknown key in a fixture or a request is refused rather than silently dropped,
so a typo never reads as "applied".

Update merges the patch onto the stored row and re-runs `tenantFieldsSchema` and
`checkTenantInvariants` on the result, with `adminKeyCount` taken from the database. So
`openRegistration: false` on a tenant with no admin keys is refused the same way a create refuses it.

The comment at the top of `tenants.ts` says that **every** write, platform admin or fixture, passes
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

Every writer of `wallet_origin` or `expected_origins` (fixtures, create, update) takes the same lock, so
two concurrent creates claiming the same origin serialise and the second gets
`409 origin-claimed` naming the origin and the other tenant's slug. The lock is per deployment, not
per tenant, which is fine at this write rate.

The local-stack fixtures (§9) get the same check against the database, and are checked against each
other before any is written. A fixture whose origin another tenant already claims fails the
one-shot, and with it the stack's bring-up, naming the origin and the other tenant's slug and
`status`.

`corsOrigins` and `allowedDappOrigins` are not claims: two tenants may list the same dApp, and
`isCorsOrigin` only answers yes or no.

### 6.3 Database errors as API errors

Unique violations on `slug`, `wallet_origin`, `rp_id` and `tenants_pkey` map to `409 conflict` with
the field name. Nothing reaches the client as a 500 because of a duplicate.

---

## 7. Platform API

Every route except challenge and verify (§4.2) runs `requirePlatformAdmin`. All carry tag `platform`,
and the guarded ones declare `security: [{ platformSession: [] }]` in the OpenAPI document, which is
regenerated and kept honest by `openapi/generate.ts --check` in CI. Tenants are addressed by slug
because that is what platform admins type; responses always include the id.

### 7.1 Routes

| Method & path | Does | Notable responses |
| --- | --- | --- |
| `POST /v1/platform/auth/challenge` | Sign-in message (§4.2) | `200 { message }` |
| `POST /v1/platform/auth/verify` | Session from a signed message (§4.3) | `200 { token, expiresAt, admin }`, `401` |
| `POST /v1/platform/auth/logout` | Revoke the presented session | `204`, `401` |
| `GET /v1/platform/tenants?status=` | List, newest first; default excludes `deleted` | `200 { tenants: TenantSummary[] }` |
| `GET /v1/platform/tenants/:slug` | One tenant: all fields, `status`, `version`, admin keys (id, label, hash prefix, createdBy, createdAt), user and credential counts, last userop time, per-chain ledger position from `paymaster_tenants` | `404` |
| `POST /v1/platform/tenants` | Create. Body `tenantCreateSchema`. `id` optional, for a tenant already registered on-chain under a fixed id | `201 { tenant, adminKeys: [{ id, label, key }] }` — plaintext once. `400` with per-path issues, `409 origin-claimed` / `conflict` |
| `PATCH /v1/platform/tenants/:slug` | Update mutable fields: `rpName`, `expectedOrigins`, `allowedDappOrigins`, `corsOrigins`, `openRegistration`, `policy`, `branding`. Requires `If-Match: "<version>"` | `200`, `400`, `409 origin-claimed`, `412 version-mismatch`, `422 immutable-field` if the body names `slug`, `id`, `walletOrigin` or `rpId` |
| `POST /v1/platform/tenants/:slug/suspend` | `active → suspended`. Body `{ reason }`, recorded | `409 invalid-transition` |
| `POST /v1/platform/tenants/:slug/resume` | `suspended → active` | `409 invalid-transition` |
| `DELETE /v1/platform/tenants/:slug` | `suspended → deleted`, under §5.3 | `204`, the `409`s in §5.3 |
| `POST /v1/platform/tenants/:slug/admin-keys` | Issue a key. Body `{ label }`. Active tenants only | `201 { id, label, key }` — plaintext once. `409 invalid-transition` |
| `DELETE /v1/platform/tenants/:slug/admin-keys/:keyId` | Revoke. Refused if it is the last key and `openRegistration` is false | `204`, `409 last-admin-key` |
| `GET /v1/platform/tenants/:slug/history?before=` | `tenant_history`, newest first, 50 per page | `200 { entries, next }` |
| `GET /v1/platform/chains` | Blockchain status (§10). *Follow-up card (H-k); not registered by H5.* | `200` |
| `POST /v1/platform/rpc/:chainId` | Chain read relay for the console (G10, openspec `platform-chain-reads`): the `/v1/rpc` read allowlist behind a platform admin session, bodies ≤ 16 KiB, `eth_getLogs` bounded to `PLATFORM_RPC_MAX_LOG_BLOCKS`, `PLATFORM_RPC_RATE_LIMIT_PER_MINUTE` per session (separate from the routes above) | `200` JSON-RPC (`-32601`, `-32602`, `-32021`, `-32023` as errors), `400`, `401`, `403`, `413` |

### 7.2 Concurrency

`PATCH` without `If-Match` is `428 precondition-required`. With a stale version it is
`412 version-mismatch` and the current version in the body. Lifecycle transitions take a row lock
and check the source state, so two platform admins suspending at once get one `200` and one `409`.

### 7.3 Generated admin keys

32 random bytes, base64url, prefixed `gak_` so a leaked key is recognisable in a secret scanner.
The prefix is cosmetic: `resolveAdminTenant` hashes whatever it is given, so keys without the
prefix (fixture keys, and keys the retired seed wrote) keep working.

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
| `getById` | any status, renamed `getByIdAnyStatus` so the choice is visible at the call site | watcher, platform routes |
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

## 9. Retiring `TENANTS_SEED`

`TENANTS_SEED` used to upsert tenants by slug at every boot, which made it a second writer next to
the platform admins and needed ownership rules between the two (H-h). It is retired. `wallet-api` no
longer reads it, and boots with zero tenants, logging a warning until a platform admin creates one. On
every live deployment (dev, staging, prod) tenants are created, edited, suspended and deleted only
by Giano's platform admins, in the console's Platform area (§7, §11). The seed-only rules went with it:
seed takeover at boot, the suspend-and-resume-only limit on seed-managed tenants, the
`POST …/adopt` route, the `409 seed-managed` and `409 still-seeded` errors, and `managedBy` in
platform admin responses.

**The handover (done).** For one release, a boot step handed every tenant an earlier version had
seeded to the platform admins, writing a history entry `adopt` with actor
`system:tenants-seed-retirement` for each. That boot step and the `managed_by` column are gone
(`0009_drop_tenant_managed_by.sql`); those history entries remain. A deployment upgrading straight
past that release loses only those entries.

**Local stacks.** The e2e, dev, loopback and Sepolia compose stacks still have to come up
deterministic, with fixed tenant ids pre-registered on the devnet paymaster and fixed admin keys the
provisioners and the e2e suite use. They get them from the init step, `node dist/init.js`
(source `src/init.ts` and `src/services/tenant-fixtures.ts`), which every deployment runs before
`wallet-api`: the `init` service in each compose file, and an init container in the AWS task. It
runs migrations, then writes the environment's bootstrap platform admins into an empty `platform_admins` table
(§4.1), then, on a `localStack` environment only, reads `TENANT_FIXTURES`, a JSON array with the
old seed entry's fields, including a pinned `id` and plaintext `adminKeys`. It creates each missing
tenant through the same invariant and origin-claim checks as every other write (§6), with actor
`fixture`. `wallet-api` starts only after it completes, and runs with `RUN_MIGRATIONS=false`. It is
insert-only: an existing slug is left untouched, so console edits survive a restart and `down -v`
resets the fixtures. On any environment that is not a local stack, init refuses to start when
`TENANT_FIXTURES` is set, so no live configuration can create a tenant.

---

## 10. Blockchain status

**Not delivered by H5** (H-k). The card names it and gives no requirement (O-1). This section is
kept as the starting point for the follow-up card. It is specified at the size of the data
`wallet-api` already has, so it costs little if the real requirement turns out different.

### 10.1 Why server-side

The console already reads each paymaster from the chain. It cannot see what `wallet-api` sees: the
bundler URLs are internal Cloud Map hostnames the browser cannot reach and must not learn
([`INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) §14.6), the prober's verdict lives in the API process,
and the ledger position and watcher lag are rows in its database. The question a platform admin is
asking is "can this deployment transact on chain X right now", and only `wallet-api` can answer it.

### 10.2 `GET /v1/platform/chains`

One entry per served chain, probed in parallel with a 3-second timeout each so one dead chain does
not stall the response:

```jsonc
{
  "signer": "ok",                              // sponsorship signer health, "unavailable" or "disabled";
                                               // one signer serves every chain, so it is not per chain
  "chains": [{
    "chainId": 84532,
    "name": "Base Sepolia",
    "registryStatus": "ready",                 // the prober's verdict, as /v1/version reports it
    "verification": { "checkedAt": "…", "failures": [] },   // last full ChainVerification (boot or recovery)
    "lastProbe": { "at": "…", "ok": true },    // the prober's last reachability probe
    "node":    { "reachable": true, "headBlock": "18234411", "headAgeSeconds": 2 },
    "bundler": { "reachable": true, "entryPointSupported": true },  // new BundlerClient.supportedEntryPoints()
    "paymaster": {                             // null when this chain does not sponsor
      "address": "0x…",
      "depositWei": "…", "treasuryWei": "…", "stakeWei": "…",
      "invariantSlackWei": "…",                // from paymaster_state
      "lastSyncedBlock": "18234400",
      "watcherLagBlocks": 11,                  // headBlock − lastSyncedBlock
      "checkedAt": "…"
    }
  }]
}
```

No new background job, table or metric, but some new code:

- **The prober records what it finds.** For a `ready` chain it only calls `getChainId()` and keeps
  nothing (§3), so it must store its last full `ChainVerification` *and* the time and outcome of
  each reachability probe in the registry entry. Without that, `checkedAt` for a healthy chain
  would be the boot time. This is deployment state the registry already holds, not tenant state.
- **The bundler client gains `supportedEntryPoints()`.** `eth_supportedEntryPoints` is answered
  from configuration today and never asked of the bundler (§3).
- **The signer stays deployment-wide.** `SponsorshipSigner.health()` already answers for every chain
  (`app.ts`, MC-72), so `signer` sits at the top of the response.

The thresholds that turn these figures into a verdict (head age, watcher lag) stay in the console,
next to the `giano-doctor` thresholds it already applies, until O-1 says who consumes the status
and whether it should also alert.

---

## 11. The console

### 11.1 Wiring

- nginx template: the same regex `/api/` location `wallet-web` uses, plus
  `proxy_set_header Origin "";`. That means deferred DNS resolution through
  `set $giano_wallet_api ${GIANO_WALLET_API_UPSTREAM}` and a variable `proxy_pass`, with the prefix
  re-appended. The template's comment says this "would need a resolver this image cannot assume".
  `wallet-web` gets one by reading the nameserver from `/etc/resolv.conf` in its entrypoint, and
  that code ports to this one.
  - The entrypoint runs on the DHI nginx runtime, so it uses `sh`, `envsubst` and `jq` only.
  - It renders the `resolver` line and the `/api/` block only when `GIANO_WALLET_API_UPSTREAM` is
    set, the same way it renders `GIANO_RPC_LOCATIONS` today.
  - The existing `connect-src 'self'` already covers the new location.
- The variable is `GIANO_WALLET_API_UPSTREAM`, the name `wallet-web` uses for the same thing.
  `config.json` gains `platformApi: boolean`, rendered `true` when it is set. When false, the
  Platform area is hidden.
- `deploy/docker-compose.e2e.yml`: the `paymaster-admin` service gains `GIANO_WALLET_API_UPSTREAM` and
  `depends_on: wallet-api`. Its comment says it "needs neither wallet-api nor a database", and that
  comment changes too.
- **Reads (G10).** With `GIANO_WALLET_API_UPSTREAM` set, the console also reads the chain through
  `/api/v1/platform/rpc/<chainId>` with the session token, and renders no `/rpc/*` proxy: the
  entrypoint rewrites each `rpcUrl` to that path. One session, held by a provider around both areas,
  serves the Paymaster and the Platform area, and nothing is read before sign-in. A standalone
  console (no upstream) keeps its rate- and size-limited `/rpc/<chainId>` proxy and must sit behind
  the operator's own access control.
- `services/paymaster-admin/src/lib/platform-api.ts`: a typed client over the routes in §7, with
  hand-written request and response types. Nothing in the repository generates types from OpenAPI
  today, and adding a generator is new tooling for one small client. `openapi:check` in CI keeps
  `openapi.json` honest, and the E2E suite exercises the client against the real API. A generator
  is a follow-up if the client grows.

### 11.2 Layout

A top-level switch between the existing **Paymaster** tabs (Overview, Tenants, Roles, Settings,
History, Health — unchanged) and a new **Platform** area. H5 delivers its Tenants and Sign-in
tabs, and the Admins tab followed with `platform-admins-in-database`; the Chains tab belongs to the
follow-up card (H-k).

| Tab | Contents |
| --- | --- |
| **Tenants** | Registry table: slug, id, status, wallet origin, users, and per selected chain an *on-chain* column joined from the paymaster roster by id: `registered · enabled`, `registered · disabled`, or `not registered`. A fourth group lists tenants on the roster with **no** registry row, which today nobody can see. Row → detail drawer with fields, keys, ledger position and history. |
| **Admins** | The platform admins (id, address, who added them, when), *Add admin*, and *Remove* with a confirmation, plus the change history (§4.1). No Remove button on the signed-in platform admin's own row, or when only one platform admin is left; the API refuses both anyway. |
| **Chains** *(follow-up card)* | One card per served chain from `/v1/platform/chains`, with the thresholds applied and the same ok/check/failing badges as `HealthPanel`. |
| **Sign-in** | Shown in place of the other tabs until the platform admin has a session. One button, *Sign in with wallet*: connects the wallet if needed, then runs §4.2 with the connected address and the selected chain. Shows which platform admin id and address are signed in and when the session expires. Any `401` returns here. |

### 11.3 Flows

**Sign in.** The wallet the console already connects for on-chain actions signs the challenge with
`personal_sign`. If the connected address is not a platform admin, sign-in fails with the generic `401`
and the console says the connected address is not on this deployment's platform admin list. The Tenants
tab shows whether the signed-in address also holds `TENANT_ADMIN_ROLE` on the selected chain, from
the roles the console already reads, and disables the on-chain steps below when it does not.

**Create.** The console does not duplicate the validator: a `400` comes back with per-path issues
(§7.1), and the form shows each against its field. On `201`, a modal shows the generated admin keys with copy buttons and the text *these
are shown once*. Then an optional second step: *Register on <chain>*, which calls the existing
`registerTenant(id, withdrawAddress, slug)` through the connected wallet and needs
`TENANT_ADMIN_ROLE`, as `TenantsPanel` does today. The dialog states both §1.3 limitations:
- The wallet origin still has to be served.
- The tenant has no sponsorship rules until someone `PUT`s them with one of the keys just shown.

**Edit.** Fields pre-filled; the request carries `If-Match`. On `412`, the drawer reloads and shows
what changed.

**Suspend.** Reason required. After `200`, the console offers `setTenantEnabled(id, false)` on each
chain where the tenant is registered and enabled, and says why (§5.1, the authorisation window).
**Resume** offers the reverse.

**Delete.** Only on a suspended tenant. Type-the-slug confirmation, which also
says the slug, wallet origin and RP ID can never be used again (H-d). A `409` shows the per-chain
balance or open reservations from the response.

---

## 12. Risks and open items

| # | Item |
| --- | --- |
| **O-1** | **Blockchain status has no requirement.** §10 is a guess at the smallest useful thing. Needed: who looks at it (platform admins in the console, or an alerting path too), and whether "status" includes anything beyond node, bundler, paymaster and watcher, e.g. gas price, EntryPoint deposit trend, or per-tenant balance warnings. No longer blocks H5 (H-k); it is the first question for the follow-up card. |
| **O-2** | **Estimate.** *Resolved by H-k.* The card says 3 SP and its estimation field says 2.5. D1–D4 plus D6's tenant half fill that. D5 and the Chains tab move to a follow-up card. |
| **O-3** | **Devops (`infra/iac/`).** Three asks, none of them H5 deliverables. (1) *Done, in a changed form:* `wallet-api` gets `GIANO_ENVIRONMENT = terraform.workspace`, and the platform admins and sign-in domain come from `src/environments.ts` and the `platform_admins` table (§4.1), so no `OPERATOR_*` list is set anywhere. Its task runs the init container (§9). (2) *Done:* `GIANO_WALLET_API_UPSTREAM` on the `paymaster-admin` task. (3) **Still open:** a network restriction **on `/v1/platform/*` at the `api.*` listener**, as an ALB path rule (VPN CIDR or ALB OIDC). Restricting only `paymaster.*` would not cover these routes, because they are equally reachable on `api.*`, as §14.3 itself shows. Wallet sign-in is the control; the restriction is defence in depth for write routes. Restricting `paymaster.*` as well is optional. |
| **O-4** | **Naming.** `paymaster-admin` now administers more than the paymaster. Renaming the package, image and ECR repository is a separate, mechanical change with an infra component. Not proposed here. |
| **O-5** | **Serving a runtime tenant's wallet origin** still needs infra (§1.3). The real fix is the Host-resolved `wallet-web` config already listed as unbuilt in [`ARCHITECTURE.md`](./ARCHITECTURE.md). Worth a card of its own, because until it lands "create a tenant at runtime" means "create the backend half at runtime". |
| **O-6** | *Resolved by D6.* **`INFRASTRUCTURE.md` R31** says `paymaster-admin` proxies `/api` to `wallet-api`. It now does, when `GIANO_WALLET_API_UPSTREAM` is set, and R31 says so. |
| **O-7** | **Branding** is stored and editable through this API, and still read by nothing. Editing it in the console changes no UI. The console labels the field accordingly. |
| **O-8** | *Resolved by retiring `TENANTS_SEED` (§9).* `wallet-api` no longer reads the AWS dev `tenants-seed` secret, so its contents can no longer stop a boot. Terraform no longer injects it anywhere; devops can delete it. |
| **O-9** | **Wallets that skip the EIP-4361 domain check.** The phishing protection in §4.3 relies on the platform admin's wallet warning about a `domain` mismatch. MetaMask, Rabby and Ledger Live do; an arbitrary wallet may not. The platform admin list is small, so the mitigation is a written rule: platform admins sign in with one of those wallets, on a hardware device. |

Risk worth naming: **a suspended tenant's dApp users see failures, not an explanation.** Ceremonies
return `403 unknown-tenant` and the popup shows its generic error. A distinct
`403 tenant-suspended` would tell an attacker which slugs exist, so the generic response is the
intended behaviour. The platform admin who suspends is expected to tell the tenant.

---

## 13. Traceability

| Requirement / item | Satisfied by |
| --- | --- |
| R1 — create | §7.1 `POST`, §6 validation, §11.3 Create |
| R1 — read | §7.1 `GET` list / detail / history, §11.2 Tenants tab |
| R1 — update | §7.1 `PATCH`, §6.1 merge-then-validate, §7.2 concurrency |
| R1 — delete | §5.3 tombstone delete, §5.1 suspend, §7.1 lifecycle routes |
| R1 — without a redeploy | §8: per-request resolution, no tenant cache; §9: platform admins the only writer |
| R1 — the tenant ≡ wallet origin ≡ RP ID invariant holds | §6.1 single validator, §6.2 disjoint origin claims, H-f immutable fields |
| R1 — platform admin surface, not tenant-facing | §4: a platform-admin-managed `platform_admins` table seeded per environment, wallet sign-in, a separate guard, no cross-origin path |
| Blockchain status | Follow-up card (H-k); §10 and §11.2's Chains tab are its starting point, pending O-1 |

### Deliverables

✅ = implemented: D1–D4 by the OpenSpec change `platform-tenant-lifecycle` (PR #125), D6's tenant half by `platform-console`. The OpenSpec change `platform-admins-in-database` then moved the platform admins from configuration into the database (H-b) and added the init step (§9); the rows below describe the code as it now stands.

| # | Files |
| --- | --- |
| D1 ✅ | `src/config.ts` (`GIANO_ENVIRONMENT`, the `PLATFORM_*` tuning variables in §4.1, `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS`), `src/environments.ts` (sign-in domain and bootstrap platform admins per environment), `src/routes/platform-auth.ts` (challenge, verify, logout), `src/services/platform-sessions.ts`, `src/services/platform-admins.ts` and `src/routes/platform-admins.ts` (the platform admins and their management routes), `src/plugins/auth.ts` (`requirePlatformAdmin`), `scripts/platform-login.ts` |
| D2 ✅ | `migrations/0007_tenant_lifecycle.sql`, `migrations/0008_platform_admins.sql`, `migrations/0009_drop_tenant_managed_by.sql`, `src/db/schema.ts`, the new challenge expiry sweep (`src/services/housekeeping.ts`, scheduled in `src/index.ts`) |
| D3 ✅ | `src/services/tenants.ts` (schema split, `checkTenantInvariants`, `checkOriginClaims`); `src/services/tenant-fixtures.ts` and `src/init.ts` (the init step, which loads local-stack fixtures) replace the seed (§9) |
| D4 ✅ | `src/routes/platform-tenants.ts`, `src/services/tenant-admin.ts` (the writes), `src/services/tenants.ts` (lifecycle-aware resolvers), `src/plugins/auth.ts` (`requireSession` change), `src/app.ts` (registration when the environment has a sign-in domain), `openapi/` |
| D5 *(follow-up card)* | `src/routes/platform-chains.ts`, `src/services/chains.ts` (keep last verification and probe), `src/services/bundler.ts` (`supportedEntryPoints`), `src/index.ts` (prober stores both) |
| D6 ✅ (tenant half) | `services/paymaster-admin/docker/{nginx.conf.template,entrypoint.sh,config.json}`, `src/config.ts`, `src/lib/platform-api.ts`, `src/lib/platform-session.ts`, `src/platform/{SignIn,TenantsTab,TenantDrawer,AdminsTab}.tsx`, `src/App.tsx`, `deploy/docker-compose.e2e.yml`. `ChainsTab.tsx` belongs to the follow-up card. |

---

## 14. Testing and acceptance

### 14.1 `wallet-api` (vitest + testcontainers)

- **Invariant.** Create with `rpId` ≠ wallet host → `400`; an `expectedOrigins` entry outside
  `rpId` → `400`; `openRegistration: false` with no keys → `400`; `PATCH` that would leave a closed
  tenant keyless → `400`.
- **Origin claims.** Two concurrent creates claiming the same origin → exactly one `201`, one
  `409 origin-claimed`. A fixture whose `expectedOrigins` overlaps another fixture's `walletOrigin`
  is refused before anything is written. A deleted tenant's origin stays claimed.
- **Immutability.** `PATCH` naming `walletOrigin`, `rpId`, `id` or `slug` → `422`.
- **Lifecycle resolution.** For a suspended tenant: `Origin` ceremony → `403`; `/.well-known/webauthn`
  by Host → `404`; its admin key → `401`; an existing session, with and without `Origin` → `401`;
  its CORS origin gets no ACAO. Resume → the same session works again.
- **Delete.** Active → `409`; non-zero ledger balance → `409` with figures;
  open reservation → `409`; a reservation still `reserved` but past `expires_at` → allowed; stale
  ledger → `409`; no ledger rows at all → allowed; success → user sessions and keys gone,
  `userop_log` rows intact, slug unusable by a later create.
- **Housekeeping.** The sweep deletes tenant and platform admin challenges that expired more than a day
  ago, and leaves younger ones.
- **`managed_by` dropped.** `0009` removes the column and keeps every tenant, key and history row.
- **Init.** `TENANT_FIXTURES` outside a local stack, or an unknown `GIANO_ENVIRONMENT`, is refused
  before the database is touched.
- **Fixtures.** An unknown slug is created with hashed keys and a `create` entry by `fixture`; an
  existing slug is left exactly as it is; a deleted slug is never re-created; two loaders at once
  create the tenant once.
- **Platform admin sign-in.** A valid challenge signed by a platform admin's EOA → session. Each of these → `401`
  with identical bodies: a signature by a different key; an address not in the list; a reused nonce;
  an expired challenge; the issued message with any field changed (`domain`, `uri`, `version`,
  `chainId`, `issuedAt`, `expirationTime`, `statement`) and re-signed by the same key; a message the
  API did not issue. Two concurrent verifies of one nonce → exactly one session. A challenge for an unlisted
  address returns the same shape as for a listed one and stores nothing.
- **Platform admin guard.** No token / wrong token / expired / revoked / tenant admin key → `401` with
  identical bodies; any `Origin` header → `403`, including on challenge and verify; a session token
  on `/v1/admin/*` → `401`; a session whose platform admin was removed → `401` on the very next request;
  an environment with no sign-in domain → every platform route `404`; no known `GIANO_ENVIRONMENT`
  → boot refuses; the retired `OPERATOR_*` list and domain variables are ignored.
- **Platform admins.** Bootstrap writes nothing into a table that has a platform admin, and seeds an empty one
  once even from replicas booting together, recording each as `bootstrap`. An added platform admin can
  sign in at once and records who added them; a duplicate id or address → `409`. Removing a
  platform admin ends their sessions at once; removing yourself → `409 self-removal`; removing the last
  platform admin → `409 last-admin`. No session → `401`.
- **Attribution.** Every platform admin write's `tenant_history` row carries `platform-admin:<id>:<address>`
  and the session id.
- **No restart.** Create a tenant through the API, then in the same process: `GET
  /.well-known/webauthn` with its Host resolves, and `POST /v1/webauthn/options` with its Origin
  resolves.

### 14.2 E2E (`e2e/tests/platform-admin.spec.ts`)

Against the two-tenant compose stack, whose `GIANO_ENVIRONMENT=e2e` bootstraps anvil accounts 3
(`admin-e2e`) and 0 (`admin-console`) as platform admins and signs in for `paymaster.localhost`
(`src/environments.ts`). API steps sign in in-process with viem and account 3's key:

1. Suspend `byo` through the API; connecting from `app-byo.localhost` fails. Resume; it succeeds.
   Tenant `stock` is unaffected throughout.
2. Create tenant `runtime` with walletOrigin `http://wallet-runtime.localhost`; `GET
   http://api.localhost/.well-known/webauthn` with `Host: wallet-runtime.localhost` returns its
   document with no container restarted.
3. Console smoke: connect anvil account 0 through the injected test provider and *Sign in with
   wallet*. The registry shows `stock`, `byo` and `runtime`; `stock` and `byo` show
   *registered · enabled* against the devnet paymaster, and `runtime` shows *not registered*.
4. Admins tab (`e2e/tests/platform-console.spec.ts`): the bootstrapped platform admins are listed,
   the signed-in platform admin's own row has no Remove button, and a platform admin added from the
   console can be removed again, with both changes in the history.

### 14.3 Acceptance on dev

Run with a throwaway EOA that a platform admin has added to dev's platform admins (Admins tab, or
`POST /v1/platform/admins`) and nowhere else. Remove it afterwards.

```fish
set -l base https://api.dev.giano.appliedblockchain.dev/v1/platform

# platform routes exist and refuse anonymous callers
curl -s -o /dev/null -w '%{http_code}\n' $base/tenants
# → 401

# sign in the way the console does, from a script
set -l token (PLATFORM_ADMIN_PRIVATE_KEY=$H5_ACCEPTANCE_KEY \
  pnpm -s -F @appliedblockchain/giano-wallet-api platform:login --api https://api.dev.giano.appliedblockchain.dev)
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
curl -s -H $auth $base/tenants/$slug | jq '{status, version}'
curl -s -H $auth -H 'Content-Type: application/json' -X POST $base/tenants/$slug/suspend -d '{"reason":"acceptance"}'
curl -s -H $auth -X DELETE -o /dev/null -w '%{http_code}\n' $base/tenants/$slug   # → 204
curl -s -H $auth "$base/tenants?status=deleted" | jq '.tenants[].slug'            # includes $slug
curl -s -H $auth $base/tenants/$slug/history | jq '.entries[].actor' | sort -u     # → "platform-admin:<id>:<address>"

# logout ends the session
curl -s -H $auth -X POST -o /dev/null $base/auth/logout
curl -s -o /dev/null -w '%{http_code}\n' -H $auth $base/tenants
# → 401
```

---

## Related documents

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — the trust model and the *decided from* table this spec
  extends with a platform admin row
- [`DEVELOPER-GUIDE.md`](./DEVELOPER-GUIDE.md) §1 — the tenancy model
- [`MULTICHAIN_SPECS.md`](./MULTICHAIN_SPECS.md) §3.5, §9.5 — chain verification and per-tenant policy
- [`PAYMASTER-SPECS.md`](./PAYMASTER-SPECS.md) — the ledger, the watcher, on-chain tenant registration, O1
- [`INFRASTRUCTURE.md`](./INFRASTRUCTURE.md) §14.6 — how `paymaster-admin` is deployed
- [`BUSINESS-REQUIREMENTS.md`](./BUSINESS-REQUIREMENTS.md) BR-35 — the tenant-facing administration this does not build
