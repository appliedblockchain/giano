# Multi-Tenancy Gap Analysis

**What is missing to run one standalone Giano instance for many clients — where every client owns its
own wallet origin, serving either Giano's UI or its own.**

Status: **M1–M3 implemented** (plus light M5/M6) · Last updated 2026-07-27 · Owner: Giano team

> **Implementation status (2026-07-27):** the safety floor is in. `tenants` +
> `tenant_admin_keys` tables (`migrations/0002_tenants.sql`), per-request tenant
> resolution by Origin/Host (`src/plugins/tenant.ts`), C1/C2/C3 closed with alertable
> cross-tenant rejection metrics, per-tenant RP config / admin keys / CORS /
> OPEN_REGISTRATION / policy overrides via `TENANTS_SEED`, tenant-labelled metrics,
> per-tenant rate limits, fail-closed transport allowlist (G7.6), namespaced SDK
> session cache (G9.2). Verification matrix V1–V7, V9, V11 lives in
> `services/wallet-api/test/`; V8/V12 (browser, two wallet origins — one stock UI,
> one BYO fixture at `e2e/wallet-byo/`) in `e2e/tests/tenant-isolation.spec.ts`,
> closing G11.3. Still open: M4 custom-domain ops, Helm chart, signed registration
> grants (G7.3/D3.1), shared-store quota (full M5), rpId plumbing (D3.8).
Companion documents: [`PRODUCT-STRATEGY.md`](./PRODUCT-STRATEGY.md) · [`COST-MODEL.md`](./COST-MODEL.md)

> This document **supersedes** `PRODUCT-STRATEGY.md` §5.2 (topology T2) and roadmap item P4b, which
> named this work but never specified it.

---

## Contents

- [1. Scope and target architecture](#1-scope-and-target-architecture)
- [2. Decisions taken](#2-decisions-taken)
- [3. What the origin-per-tenant rule buys](#3-what-the-origin-per-tenant-rule-buys)
- [4. What it costs: custom-domain onboarding](#4-what-it-costs-custom-domain-onboarding)
- [5. The tenancy model](#5-the-tenancy-model)
- [6. Critical defects (C1–C3)](#6-critical-defects-c1c3)
- [7. Gap inventory](#7-gap-inventory)
- [8. Decisions still required](#8-decisions-still-required)
- [9. Work breakdown](#9-work-breakdown)
- [10. Verification strategy](#10-verification-strategy)
- [Appendix A: pre-existing bugs found en route](#appendix-a-pre-existing-bugs-found-en-route)
- [Appendix B: what the shared-origin alternative would have cost](#appendix-b-what-the-shared-origin-alternative-would-have-cost)

---

## 1. Scope and target architecture

One Applied-Blockchain-operated Giano instance — **one `wallet-api` process, one Postgres database, one
bundler, one chain** — serving many client projects.

**Every tenant provides its own wallet origin.** That origin serves either Giano's stock UI or a UI the
tenant built itself. Both cases are the same architecture; only the authorship of the SPA differs.

```
  TENANT-OWNED ORIGINS (one per tenant, one RP ID each)      OURS
  ─────────────────────────────────────────────────────      ──────────────────────
   app.keo.com  ──popup──►  wallet.keo.com                │
                            └─ serves GIANO's stock UI    │
                            └─ RP ID = wallet.keo.com     │
                                                          │
   app.acme.app ──popup──►  wallet.acme.app               │
                            └─ serves ACME's OWN UI       │
                            └─ RP ID = wallet.acme.app    │
                                                          │
        passkeys bind to the TENANT's host ───────────────┤
                                                          │
                       ═══════════ trust boundary ════════╪══════
                                                          │
                    ┌─────────────────────────────────────▼──────────────┐
                    │  ONE standalone Giano instance                     │
                    │  wallet-api · ONE Postgres · Alto · contracts      │
                    └────────────────────────────────────────────────────┘
```

The key property: **tenant ≡ wallet origin ≡ RP ID, one to one.** Every tenant is a distinct WebAuthn
relying party, so the browser itself refuses to surrender one tenant's credential to another's origin.
Isolation is cryptographic at the credential layer, and application-level only below it.

### Non-goals

| Not in scope | Why |
|---|---|
| A shared Giano-hosted origin serving many tenants | Rejected — see [Appendix B](#appendix-b-what-the-shared-origin-alternative-would-have-cost) |
| Client-facing dashboard | Explicitly excluded. Setup is manual. |
| Self-serve onboarding / billing | Manual setup by an engineer is acceptable. |
| Per-tenant chain | One chain for all tenants ([§2](#2-decisions-taken)). |
| Single-tenant back-compatibility | Multi-tenant becomes the only model ([§2](#2-decisions-taken)). |
| Iframe-embedded wallet | `frame-ancestors 'none'` is deliberate. |

### Terms used precisely throughout

- **Gap** — a capability that does not exist. Costs work.
- **Defect** — a control that is *wrong today* and becomes exploitable under multi-tenancy. Costs work
  *and* carries risk until fixed.
- **Tenant** — one client project. Equivalently: one wallet origin, one RP ID.
- **Wallet origin** — the browser origin serving a wallet UI. Tenant-owned. Carries exactly one RP ID.

Paths written as `src/…`, `routes/…`, `plugins/…`, `services/…` are relative to `services/wallet-api/`
unless otherwise qualified.

Headline finding: a repo-wide grep for `tenant|multi-tenan|clientId|client_id|appId|projectId` across
`services/`, `packages/` and `deploy/` returns **zero application hits**. There is no tenancy dimension
anywhere — not in the schema, not in config, not in the SDK, not in the transport protocol.
`services/wallet-api/README.md:5-6` states the current model plainly: *"every client project deploys it
in its own stack (Giano is never centrally hosted)."*

---

## 2. Decisions taken

| Question | Decision | Consequence |
|---|---|---|
| Wallet origin | **Every tenant provides its own** (`wallet.keo.com`, `wallet.acme.app`), pointing at Giano's UI or their own | **Tenant ≡ RP ID, 1:1.** Cryptographic credential isolation. Deletes four gaps outright and downgrades five more — see [§3](#3-what-the-origin-per-tenant-rule-buys) |
| Backend and database | **Shared** — one `wallet-api`, one Postgres for all tenants | Requires multi-RP support in `wallet-api` ([G3](#g3--config-architecture)). This is the bulk of the work that remains |
| Chain scope | **One chain for all tenants** | `CHAIN_ID`, `RPC_URL`, `BUNDLER_URL`, `ENTRYPOINT_ADDRESS`, `FACTORY_ADDRESS` stay global |
| Tenant resolution | **By `Origin` / `Host` — authoritative, not a hint** | No tenant id in the SDK, no transport protocol change, no attacker-controlled tenant selector |
| Back-compatibility | **None — multi-tenant is the only model** | Every deployment gets a `tenants` table, even with one row. All four compose files, the Helm chart, the E2E suite, `test/setup.ts` and `openapi/generate.ts` need updating |

---

## 3. What the origin-per-tenant rule buys

This section exists because the decision is not a preference — it materially shrinks the work and
removes the hardest risk. Recording *why* prevents someone later "simplifying" back to a shared origin.

### 3.1 Cross-tenant credential confusion becomes structurally impossible

`POST /v1/webauthn/authentication/verify` accepts no tenant and resolves a credential globally
(`routes/webauthn.ts:255`). On a shared origin that is an account-takeover path: all tenants would
share one RP ID, so the browser credential picker offers any tenant's passkey, and whichever tenant
asked receives a session for it.

With distinct RP IDs, two independent layers refuse:

1. **The browser** will not release a `wallet.keo.com` credential to `wallet.acme.app`. WebAuthn scopes
   both discovery and assertion by RP ID; there is no picker entry to mis-click.
2. **`verifyAuthenticationResponse`** compares the assertion's `rpIdHash` against `expectedRPID`. Even
   a forged direct request fails, because `SHA256("wallet.keo.com") ≠ SHA256("wallet.acme.app")`.

Layer 2 is only sound once RP config resolves **per request** — which is why
[G3.3](#g3--config-architecture) stays **P0** and [G1.2](#g1--data-model) drops to P1 *contingent on
it*. Carry that dependency into review; it is the hinge the whole downgrade hangs on.

### 3.2 `RP_ID` = the wallet host, which is the config shape that already ships

Every shipped config already sets `RP_ID` exactly equal to the wallet host:
`deploy/docker-compose.e2e.yml:53` and `deploy/sepolia.env.example:60` (`wallet.localhost`),
`deploy/docker-compose.dev.yml:56` (`localhost`), `deploy/docker-compose.reference.yml:37`
(`e.g. wallet.clientapp.com`). Per-tenant origins preserve that invariant, so no prerequisite fix is
needed.

This matters because the alternative was a trap. **No code anywhere sets `rp.id` or `rpId`** —
registration calls `createWebAuthnCredential({ user, challenge, authenticatorSelection })` with no `rp`
(`packages/wallet-core/src/provider.ts:422`), authentication passes
`publicKey: { challenge, userVerification, allowCredentials }` with no `rpId`
(`packages/wallet-core/src/account/get-credential.ts:27-32`), and the only `rpId` references across
`wallet-core`, `connector` and `wallet-web` `src/` are the dead field at
`services/wallet-web/src/config.ts:14,42`. So the browser defaults `rp.id` to
`window.location.hostname`. Any registrable-parent RP ID — `giano.com` while serving from
`wallet.giano.com` — would **boot successfully and then fail every ceremony** with
`400 verification-failed`, because the boot validator only checks that origins are at-or-under
`RP_ID`. Failure at ceremony time, in production, per user.

Fixing the `rpId` plumbing becomes **optional** (P2) rather than a prerequisite. It stays worth doing:
it is what would let a tenant use `keo.com` as RP ID and share credentials between `app.keo.com` and
`wallet.keo.com`, and it is the same fix that activates ROR.

### 3.3 Wallet-address collision across tenants dissolves

The counterfactual address is a pure function of `(owners, nonce, factoryAddress, initCodeHash)` — no
tenant, no user id. On-chain salt, `packages/contracts/src/GianoSmartWalletFactory.sol:91-92`:

```solidity
function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32) {
    return keccak256(abi.encode(owners, nonce));
}
```

`nonce` defaults to `0n` and **no call site in the repo ever passes one** (server
`routes/webauthn.ts:194`, client `packages/wallet-core/src/account/toGianoSmartAccount.ts:72`). On a
shared origin this was **P0**: one passkey reused across tenants ⇒ one wallet address ⇒ two tenants'
sessions authoritative over the same wallet, with `userop_log.sender` interleaving both histories.

**Distinct RP IDs remove the premise.** A passkey is RP-bound: a credential created for
`wallet.keo.com` cannot be used at `wallet.acme.app`, and an authenticator generates a *fresh keypair
per RP*. So a user transacting with two tenants necessarily holds two credentials with two P-256 keys,
hence two wallet addresses. The collision cannot be constructed through the normal flow.

Residual risk, worth one line in the design: the address remains tenant-agnostic **by construction**,
so the collision returns if Giano ever supports importing an existing key, or adding an ECDSA address
owner shared across tenants. The `nonce` salt lever stays available if that day comes — it is no longer
required. This assumption is load-bearing enough to deserve a browser test — see
[V8](#10-verification-strategy).

### 3.4 Browser-level partitioning removes two frontend gaps

`localStorage` is scoped to origin. So on per-tenant origins:

- The single `giano:session-token` key (`services/wallet-web/src/wallet.ts:7`) is **naturally
  partitioned** — tenants cannot overwrite each other's session. Gap deleted.
- The browser-minted `externalUserId` (`wallet.ts:13-20`) becomes per-`(browser, tenant)` rather than
  per-browser, so the "two tenants share one `users` row through one `localStorage`" failure
  disappears. It is still forgeable and still not a real identity, so it drops to **P1** rather than
  vanishing.

### 3.5 No transport or SDK change is needed

A tenant id would have had to reach the wallet origin somehow, and the handshake cannot carry it.
`packages/wallet-transport/src/protocol.ts:27-35`:

```ts
export const handshakeMessageSchema = z.object({
  ...base,
  type: z.literal('handshake'),
  payload: z.object({
    sdkVersion: z.string(),
    capabilities: z.array(z.string()).default([]),
  }),
});
```

Three blockers, all now moot: zod `z.object` **strips unknown keys**, so a `tenantId` from a newer SDK
to an older wallet host is silently dropped with no error; `giano: z.literal(PROTOCOL_VERSION)` (`:10`)
means any version bump makes `parseTransportMessage` return `null` (`:95-98`), discarding the message
with no diagnostic and surfacing only as `HANDSHAKE_TIMEOUT` after 15s; and the origin-allowlist
decision happens at `host.ts:96` **before** the payload is read at `:100`, so a handshake-borne tenant
would arrive too late to select the allowlist anyway.

Because the tenant *is* the origin, none of this applies. **`PROTOCOL_VERSION` stays at 1**, the public
SDK surface is unchanged — `createGianoWalletProvider({ walletUrl, chain })` already carries everything
needed, since `walletUrl` identifies the tenant — and no lockstep rollout across tenants' dApps is
required.

### 3.6 The hosted → BYO-UI migration becomes non-destructive

Because the tenant owns the origin, changing what is served at `wallet.keo.com` — Giano's stock UI
today, their own SPA later — **does not change the RP ID**. Every passkey keeps working.

This dissolves the "one-way door" recorded in `PRODUCT-STRATEGY.md` §5.3. Under a Giano-owned origin,
moving to a client-built UI meant a new RP ID and full user re-registration. Now Giano's UI is an
on-ramp to BYO-UI rather than a fork.

---

## 4. What it costs: custom-domain onboarding

The one genuinely new cost. It trades a security problem for an operations problem, which is the right
direction — but it is not free, and it did not exist under the shared-origin model.

| Item | Detail |
|---|---|
| **DNS** | Tenant CNAMEs `wallet.<their-domain>` at our edge. One record, once, by them. |
| **TLS for a domain we do not own** | ACM (or equivalent) certificate per tenant domain, validated by a DNS record **the tenant must add and keep**. Renewal silently fails if they later remove it — the classic custom-domain SaaS failure mode. Alert on approaching expiry, not only on failure. |
| **Edge routing** | A listener rule / distribution alias per tenant domain. **ALB defaults to 25 certificates per HTTPS listener** (raisable on request); CloudFront supports multiple alternate domain names but requires the certificate in `us-east-1`. Know the ceiling before onboarding client 26. |
| **UI deployment per origin** | Each origin needs the SPA served with its own `/config.json`. See [D2](#d2--one-ui-deployment-per-origin-or-one-serving-many-hosts) — one static build per origin needs **zero code change**. |
| **CSP per origin** | `services/wallet-web/docker/nginx.conf.template:10` bakes `connect-src` at boot. Per-origin config is *better* than the shared-origin union — each tenant's CSP is scoped to its own RPC and bundler — but it must be rendered per origin. |
| **Runbook** | Manual setup is accepted, so it must be written down: DNS record → certificate request → validation → tenant row → admin key → `giano-doctor` acceptance run. |

Onboarding is therefore a **documented manual procedure**, not a code path. That is consistent with the
no-dashboard decision.

---

## 5. The tenancy model

### 5.1 Tenant, origin and RP collapse into one row

Because every tenant owns exactly one origin with exactly one RP ID, the three concepts are one entity.
A shared origin would have needed two tables to express N tenants per RP; this needs one:

```sql
tenants (
  id, slug,
  wallet_origin        text UNIQUE,   -- 'https://wallet.keo.com'
  rp_id                text,          -- 'wallet.keo.com'  (host of wallet_origin)
  rp_name              text,
  expected_origins     text[],        -- ceremony origins, all at-or-under rp_id
  allowed_dapp_origins text[],        -- 'https://app.keo.com'
  cors_origins         text[],
  branding             jsonb,
  policy               jsonb,         -- userop caps, target/paymaster allowlists
  open_registration    boolean,
  ...
)
```

The `RP_ID`-vs-`EXPECTED_ORIGINS` invariant currently enforced at boot moves to the **write path** of
this table — validated on insert and update, per row.

### 5.2 Resolution is authoritative, not a hint

| Call | Resolution | Authority |
|---|---|---|
| All ceremony calls (`/v1/webauthn/*`) | `Origin` header → tenant row | **Authoritative** — WebAuthn independently verifies the ceremony ran on that origin |
| `POST /v1/userops`, `/v1/me*`, logout | `tenantId` on `SessionContext` | Authoritative — bearer token |
| `GET /.well-known/webauthn` | `Host` header → tenant row | Authoritative |
| Admin routes | Per-tenant API key → tenant | Authoritative — a secret |
| Wallet UI config | The origin the UI is served from | Authoritative |

This is the decisive simplification versus a shared origin. There, `Origin` could only ever be
*identification* — an attacker-controlled header selecting which config to load, needing a separate
secret to authorize anything. Here **`Origin` is corroborated by WebAuthn itself**: a registration or
assertion whose `clientDataJSON.origin` does not match the resolved tenant's `expected_origins` fails
verification. The header and the cryptographic evidence must agree, or the request dies.

Two rules still hold:

1. **Admin operations require a per-tenant secret, never an origin.** Origin-based admin auth would let
   anyone who can set a header administer a tenant.
2. **`expected_origins` must be validated against `rp_id` on write.** A misconfigured row re-opens the
   door that RP separation just closed — which is exactly what [V11](#10-verification-strategy) tests.

---

## 6. Critical defects (C1–C3)

Defects, not missing features: controls that are wrong today and activate the moment one backend serves
two clients. Severities below reflect the origin-per-tenant decision.

### C1 — Silent cross-tenant account merge · **P0**

**Unaffected by the origin decision.** This collision is in Postgres, not WebAuthn.

`routes/webauthn.ts:196-201`:

```ts
const result = await db.transaction(async (tx) => {
  const [user] = await tx
    .insert(users)
    .values({ externalId: externalUserId })
    .onConflictDoUpdate({ target: users.externalId, set: { externalId: externalUserId } })
    .returning();
```

A deliberate get-or-create against a **globally unique** column (`src/db/schema.ts:9`:
`externalId: text('external_id').notNull().unique()`).

**Consequence:** tenant B registers `externalUserId: "user-1"`. The conflict resolves to tenant A's
existing `users` row, and B's credential is appended to A's user. Because `MultiOwnable` treats every
credential's public key as an owner of the same wallet, **B's user becomes a co-owner of A's user's
wallet.** No error, no log.

It needs no malice — `"user-1"`, `"1"`, `"admin@example.com"` are exactly what two independent clients
pick. And note the two credentials sit under *different RP IDs*, so nothing at the WebAuthn layer
notices: each assertion is individually valid. **This is why C1 is the one defect the origin decision
does not help with, and why it is the highest-severity item in the document.**

**Required:** `UNIQUE (tenant_id, external_id)`; conflict target changes accordingly.

### C2 — Credential resolution with no tenant filter · **P1** *(was P0)*

`POST /v1/webauthn/authentication/verify` accepts **no `externalUserId` and no tenant**
(`routes/webauthn.ts:228-303`); identity comes purely from the credential id:

```ts
// routes/webauthn.ts:255
const credential = await db.query.credentials.findFirst({ where: eq(credentials.credentialId, response.id) });
```

then at `:293-294`:

```ts
const user = await db.query.users.findFirst({ where: eq(users.id, credential.userId) });
const session = await sessions.create(credential.userId, credential.id);
```

**Downgraded because distinct RP IDs make the exploit unreachable** — see
[§3.1](#31-cross-tenant-credential-confusion-becomes-structurally-impossible).

**Downgraded, not closed, and the reasons matter:**

- It is safe **only while RP config resolves correctly per request**. It is a direct dependent of
  [G3.3](#g3--config-architecture); if that regresses, C2 returns to P0 with no other guard.
- A globally-scoped lookup that happens to be safe is fragile. Any future code path that resolves a
  credential without re-deriving the RP inherits the hole.
- Defence in depth is nearly free — the row already needs `tenant_id` for attribution and quota.

**Required:** store `tenant_id` and `rp_id` on `credentials`; **reject when
`credential.tenant_id ≠ resolved tenant`**; `UNIQUE (tenant_id, credential_id)`. Make that rejection
**alertable** — if it ever fires, either RP resolution is broken or someone is probing.

Related, unchanged: `POST /v1/webauthn/options` discloses another tenant's credential ids
(`routes/webauthn.ts:131-132` looks the user up by the global `external_id` and returns their
credential list). Now an information leak rather than an attack primitive — still **P1**.

### C3 — Challenge binding is discarded · **P1** *(was P0)*

`src/services/challenges.ts:29-43` atomically consumes a challenge and **returns the bound user**:

```ts
async consume(challenge: string, kind: ChallengeKind): Promise<{ userId: string | null } | null> {
  const rows = await db
    .update(challenges)
    .set({ consumedAt: sql`now()` })
    .where(
      and(
        eq(challenges.challenge, challenge),
        eq(challenges.kind, kind),
        isNull(challenges.consumedAt),
        gt(challenges.expiresAt, sql`now()`),
      ),
    )
    .returning({ userId: challenges.userId });
  return rows[0] ?? null;
}
```

Both callers **throw the binding away** and trust the request body instead
(`routes/webauthn.ts:169-173`):

```ts
const consumed = await challenges.consume(challenge, 'registration');
if (!consumed) {
  throw new ApiError(400, 'bad-challenge', 'challenge is unknown, expired or already used');
}
```

`consumed.userId` is never read; `:167` re-reads `request.body.externalUserId`. Identical pattern at
`:250-253`.

**Downgraded** because WebAuthn origin verification acts as a backstop: a challenge issued for tenant A
but redeemed in a tenant-B ceremony carries `clientDataJSON.origin = https://wallet.keo.com`, which
fails tenant B's `expectedOrigin`. Cross-tenant redemption is therefore blocked in practice.

**Still required**, for three reasons: the binding is *already returned*, so enforcing it is nearly
free; it is the only guard against a misconfigured `expected_origins` row; and within a single tenant it
remains a genuine user-mismatch bug today.

**Required:** add `tenant_id` to `challenges`; return it from `consume()`; make both verify routes use
the **consumed challenge's** tenant and user, and reject any body value that disagrees.

---

## 7. Gap inventory

Severity: **P0** unsafe to run multi-tenant without it · **P1** required for a usable product ·
**P2** operational maturity. Rows marked ~~struck~~ are **deleted by the origin-per-tenant decision**,
retained so the reasoning is not lost.

### G1 — Data model

`src/db/schema.ts` — six tables, no tenant column anywhere.

| ID | Gap / defect | Evidence | Sev | Required change |
|---|---|---|---|---|
| G1.1 | `users.external_id` globally unique | `schema.ts:9` | **P0** | `UNIQUE (tenant_id, external_id)` — defect [C1](#c1--silent-cross-tenant-account-merge--p0) |
| G1.2 | `credentials.credential_id` globally unique; no `rp_id` column | `schema.ts:20` | **P1** | `UNIQUE (tenant_id, credential_id)` + store `rp_id`. **Depends on G3.3 for safety** — [C2](#c2--credential-resolution-with-no-tenant-filter--p1-was-p0) |
| G1.3 | `challenges` has no tenant column; `consume()`'s binding unused | `schema.ts:32-44`, `src/services/challenges.ts:29-43` | **P1** | Add `tenant_id`; return and enforce it — [C3](#c3--challenge-binding-is-discarded--p1-was-p0) |
| G1.4 | `SessionContext` carries no tenant | `src/services/sessions.ts:8-14` | **P0** | Add `tenantId` — **highest-leverage single change**; every route's authorization derives from this type |
| G1.5 | `ror_origins.origin` globally unique | `schema.ts:83` | P1 | `UNIQUE (tenant_id, origin)` — today two tenants cannot register the same origin |
| G1.6 | `userop_log` has no tenant column; no dApp origin recorded | `schema.ts:64-79` | P1 | Add `tenant_id` (consider `dapp_origin`) for attribution and billing |
| G1.7 | No `tenants` table | — | **P0** | Create per [§5.1](#51-tenant-origin-and-rp-collapse-into-one-row) |
| G1.8 | Every index is non-tenant-leading | `schema.ts:29,43,61,78` | P2 | Recompose as `(tenant_id, …)` |

> **Two global uniques must STAY global.** A reader working down an "add `tenant_id` everywhere"
> checklist will break both:
>
> - **`sessions.token_hash`** (`schema.ts:56`) — sha256 of 32 random bytes. Global uniqueness *is* the
>   anti-collision property you want for a bearer credential.
> - **`userop_log.userop_hash`** (`schema.ts:68`) — a chain-level fact computed over chainId +
>   EntryPoint (`routes/userops.ts:98-103`), and the unique constraint **backs idempotency** via
>   `onConflictDoNothing` (`:131`). Scoping it per tenant would break replay protection.

### G2 — Tenant resolution and authorization

Unaffected by the origin decision: nothing about distinct RP IDs helps with admin or session scoping.

| ID | Gap / defect | Evidence | Sev | Required change |
|---|---|---|---|---|
| G2.1 | `isAdminRequest` returns a **boolean, not an identity** — no route can know which tenant a key belongs to | `plugins/auth.ts:39-42` | **P0** | Resolve key → tenant; return the tenant |
| G2.2 | Every admin route is deployment-wide: any tenant's key can mutate any tenant's data | `routes/admin.ts:19,43-44,61` | **P0** | Scope all admin routes by resolved tenant (defect) |
| G2.3 | `requireSession` sets `request.session` with **no tenant assertion** — a valid token is accepted on any tenant's endpoint | `plugins/auth.ts:50-60` | **P0** | Assert session tenant matches the resolved request tenant |
| G2.4 | `ADMIN_API_KEYS` is a flat in-memory list with no tenant mapping | `config.ts:62`, `app.ts:74` | **P0** | Hashed per-tenant keys in a table |
| G2.5 | `timingSafeIncludes` leaks key length, is not `crypto.timingSafeEqual`, and is an O(keys × len) scan that degrades as tenant keys accumulate | `plugins/auth.ts:22-33` | P1 | Replace with a hashed lookup + `timingSafeEqual` |
| ~~G2.6~~ | ~~No origin → tenant map endpoint for the wallet UI to call~~ | — | — | **Deleted.** The UI is served *from* the tenant's origin, so it knows its tenant by construction — no lookup, no attacker-controlled hint |

Verbatim, `plugins/auth.ts:22-33`:

```ts
function timingSafeIncludes(keys: string[], candidate: string): boolean {
  // constant-time-ish comparison across the configured key set
  let matched = false;
  for (const key of keys) {
    if (key.length === candidate.length) {
      let diff = 0;
      for (let i = 0; i < key.length; i++) diff |= key.charCodeAt(i) ^ candidate.charCodeAt(i);
      if (diff === 0) matched = true;
    }
  }
  return matched;
}
```

### G3 — Config architecture

**This is now the bulk of the remaining work.** The refactor is structural, not a find-and-replace.
`app.ts:41-50` and `:74` build `challenges`, `sessions`, `bundler`, `publicClient`, `adminApiKeys`,
`PolicyConfig` and the rate-limit options **once at registration**. Only two config values are read per
request (`OPEN_REGISTRATION` at `routes/webauthn.ts:127`, and the
`RP_ID`/`EXPECTED_ORIGINS`/`FACTORY_ADDRESS` reads inside handler bodies). A **per-request tenant
resolver** must replace boot-time capture for everything that becomes per-tenant.

`src/services/userop-policy.ts` is already pure functions taking an injected `PolicyConfig` — that is
the pattern to copy everywhere else.

`config.ts` cannot express the target model. Verbatim, `config.ts:89-104`:

```ts
    // RP ID sanity (P3.5): passkeys bind to RP_ID irreversibly, so verification-time
    // failures are too late. Every expected origin's host must equal RP_ID or be a
    // subdomain of it (registrable-domain opt-in).
    for (const origin of env.EXPECTED_ORIGINS) {
      let host: string;
      try {
        host = new URL(origin).hostname;
      } catch {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['EXPECTED_ORIGINS'], message: `not a valid origin: ${origin}` });
        continue;
      }
      if (host !== env.RP_ID && !host.endsWith(`.${env.RP_ID}`)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['RP_ID'],
          message: `RP_ID "${env.RP_ID}" is not valid for expected origin ${origin} — the origin's host must equal RP_ID or be a subdomain of it`,
        });
      }
    }
```

There is no way to say "origins A belong to RP A, origins B to RP B".

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| G3.1 | All per-tenant config captured in boot-time closures | `app.ts:41-50,74` | **P0** | Per-request tenant resolver; inject resolved config |
| G3.2 | `superRefine` cannot express multiple RPs | `config.ts:89-104` | **P0** | Move the RP/origin invariant to the `tenants` write path, per row |
| G3.3 | `RP_ID`, `RP_NAME`, `EXPECTED_ORIGINS` are scalars | `config.ts:27-30` | **P0** | Per tenant. **Load-bearing** — this is what makes G1.2 and G1.3 safe to downgrade |
| G3.4 | `USEROP_MAX_*` (4), `USEROP_ALLOWED_TARGETS`, `USEROP_ALLOWED_PAYMASTERS` deployment-wide | `config.ts:43-50`, `app.ts:85-92` | **P1** | Per tenant. Tenant A's allowlist must not authorize B's calls |
| G3.5 | `OPEN_REGISTRATION` is a single global toggle — one tenant in demo mode opens registration for **every** tenant | `config.ts:57-60`, `routes/webauthn.ts:127` | **P0** | Per tenant |
| G3.6 | `CORS_ORIGINS` is one global allowlist with `credentials: true`, registered **only if non-empty** | `app.ts:49-51` | P1 | Per tenant; fail closed |
| G3.7 | `SESSION_TTL_SECONDS`, `CHALLENGE_TTL_SECONDS` scalars | `config.ts:39-40` | P2 | Per tenant (session TTL at least) |

**Stays global** given the one-chain decision: `NODE_ENV`, `HOST`, `PORT`, `LOG_LEVEL`, `DATABASE_URL`,
`RUN_MIGRATIONS`, `CHAIN_ID`, `RPC_URL`, `BUNDLER_URL`, `ENTRYPOINT_ADDRESS`, `FACTORY_ADDRESS`.

### G4 — Wallet address derivation

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| ~~G4.1~~ | ~~Same passkey ⇒ same wallet address across tenants~~ | `src/services/wallet-address.ts:11-25`, `GianoSmartWalletFactory.sol:91-92` | P2 | **Largely dissolved** — passkeys are RP-bound, so a user holds a distinct credential and key per tenant ([§3.3](#33-wallet-address-collision-across-tenants-dissolves)). Document that the address is tenant-agnostic by construction; the `nonce` salt lever stays available if key import or shared ECDSA owners are ever supported. Prove the assumption with [V8](#10-verification-strategy) |
| G4.2 | Submitted `factory` address is **never validated** against `config.FACTORY_ADDRESS` | zero `FACTORY_ADDRESS` refs in `routes/userops.ts`, `src/services/userop-policy.ts` | P1 | Add a policy rule (pre-existing defect, not tenancy-specific) |

### G5 — Quota and rate limiting

`@fastify/rate-limit` is registered `{ global: false }` (`app.ts:48`), so the **only** rate-limited
endpoints are the three `/v1/webauthn/*` routes (`routes/webauthn.ts:92-96`), keyed by **client IP**, in
an in-memory store that does not survive horizontal scaling.

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| G5.1 | No per-tenant quota anywhere | `app.ts:48` | **P1** | Per-tenant buckets in a shared store (Redis or Postgres) |
| G5.2 | `/v1/userops` is **unlimited** — one tenant can exhaust the shared bundler and executor balance | `routes/userops.ts:76-174` | **P1** | Per-tenant relay quota. A shared-resource denial of service across clients — **the sharpest remaining risk of a shared backend**, and the one the origin decision does nothing about |
| G5.3 | All `/v1/me*`, all `/v1/admin/*`, `/.well-known/webauthn`, `/metrics` unlimited | `app.ts:48` | P2 | Rate-limit |
| G5.4 | Rate limits keyed by IP only | `routes/webauthn.ts:92-96` | P1 | Key by tenant + IP |

### G6 — Observability and audit

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| G6.1 | **No metric carries a tenant label** — `giano_userop_relayed_total{status}`, `giano_userop_policy_rejections_total{rule}`, `giano_ceremony_failures_total{kind}`, `giano_userop_relay_seconds` (no labels) | `plugins/metrics.ts:26-49` | **P1** | Add a `tenant` label. Without it there is no per-tenant billing, alerting or capacity story |
| G6.2 | `/metrics` is **unauthenticated** — would expose every tenant's volumes to anyone reaching the port | `plugins/metrics.ts:53` | **P1** | Auth, or bind to an internal interface |
| G6.3 | No tenant in error logs | `plugins/error-handler.ts:40` | P1 | Add tenant to the log context |
| G6.4 | `BundlerRpcError` messages echoed verbatim to clients — can leak shared-provider quota detail across tenants | `plugins/error-handler.ts:33-35` | P1 | Sanitize |
| G6.5 | `userop_log` cannot be attributed per tenant (see G1.6) | `schema.ts:64-79` | P1 | Add `tenant_id` |

### G7 — Wallet origin (frontend)

| ID | Gap / defect | Evidence | Sev | Required change |
|---|---|---|---|---|
| G7.1 | `externalUserId` is **minted in the browser** and forgeable | `services/wallet-web/src/wallet.ts:6-20`; server accepts any string, `routes/webauthn.ts:111,152` | **P1** *(was P0)* | Should come from the tenant's auth system via a signed grant. Downgraded — `localStorage` is origin-partitioned, so the cross-tenant merge path is gone ([§3.4](#34-browser-level-partitioning-removes-two-frontend-gaps)) |
| G7.2 | Config is a boot-time `envsubst` singleton; runtime built before any dApp input | `services/wallet-web/docker/entrypoint.sh:22`; `src/config.ts:18-24`; `main.tsx:9-16`; `App.tsx:14-15` | **P1** | **Depends on [D2](#d2--one-ui-deployment-per-origin-or-one-serving-many-hosts).** One static build per origin ⇒ works as-is, no code change. One deployment serving N hosts ⇒ Host-aware `/config.json` |
| G7.3 | `getRegistrationGrant` **not wired**, so the shipped UI needs `OPEN_REGISTRATION=true` ⇒ **any browser can mint a user row in the shared DB unauthenticated**, IP-limited at 30/min | `wallet.ts:39-48`; `routes/webauthn.ts:127-129` | **P0** | Wire it. Unaffected by the origin decision — the shared database is what makes it serious |
| G7.4 | Grant headers reach **only** `/v1/webauthn/options`; both `verify` calls and `/v1/userops` send none | `create-wallet-api-injection.ts:102-107` vs `:116,131,171` | **P1** *(was P0)* | Narrower now — the grant authorizes *who may register*; the tenant comes from the origin. Still fix, so registration authorization is not bypassable at `verify` |
| ~~G7.5~~ | ~~Single `giano:session-token` key for the whole origin — tenants overwrite each other~~ | `wallet.ts:7,43-47` | — | **Deleted.** `localStorage` is origin-scoped; per-tenant origins partition it automatically |
| G7.6 | Origin allowlist **fails open**: `allowed.length === 0` permits any origin, and the env default is `[]` | `packages/wallet-transport/src/host.ts:82-85`; `docker/entrypoint.sh:12` | **P0** | Fail closed. Still critical — this guards which *dApp* may drive a tenant's wallet |
| G7.7 | `dappOrigin` displayed but never bound to the session nor logged | `packages/wallet-transport/src/host.ts:5-9`; `views/*.tsx` | P1 | Bind to session; record in `userop_log` |
| G7.8 | CSP `connect-src` baked at boot | `docker/nginx.conf.template:10` | P2 | Per-origin config makes this **better** than shared-origin (no union across tenants) — just render per origin |
| G7.9 | Per-tenant logo **forbidden by CSP** (`img-src 'self' data:`); `logoUrl` typed but unrendered | `docker/nginx.conf.template:10`; `docker/config.json.template:10-12`; `App.tsx:43-45` | P2 | Widen the CSP deliberately, or inline as a `data:` URI |

### G8 — Related Origin Requests

**ROR is not required for the popup architecture.** Ceremonies run on the wallet origin, so
`app.keo.com` never invokes WebAuthn and needs no ROR entry. ROR matters only for embedded/same-origin
ceremonies, which `EXECUTION-PLAN.md` D2 explicitly defers. So ROR work is **P2** — except these two,
which are defects live today:

| ID | Gap / defect | Evidence | Sev | Required change |
|---|---|---|---|---|
| G8.1 | `GET /.well-known/webauthn` is an unauthenticated, **unfiltered** `SELECT` with no `WHERE` — publishes every tenant's origins to the public internet | `routes/well-known.ts:19` | **P1** | Filter by `Host` → tenant. A customer-list leak independent of any WebAuthn consideration |
| G8.2 | Any tenant's admin key can add or delete any tenant's origins; the global `origin` unique makes `onConflictDoUpdate` silently no-op instead of erroring | `routes/admin.ts:19,43-44,61`; `schema.ts:83` | **P1** | Scope by tenant (G2.2) + `UNIQUE (tenant_id, origin)` |
| G8.3 | `ror_origins` has no tenant FK, so the document cannot be filtered | `schema.ts:81-85` | P2 | Add FK to `tenants` |
| G8.4 | **Chrome caps the list at 5 eTLD+1 labels** — no enforcement or comment in the code | `README-ROR.md:86` | P2 | Enforce at write time if ROR is ever enabled. Note per-tenant ROR documents make this a **per-tenant** budget rather than a global ceiling — a real improvement over the shared-origin model |

**ROR is the wrong tool for tenant isolation, and using it as one is a security downgrade.** Listing
tenant B's origin under tenant A's RP ID makes their credentials mutually usable at the WebAuthn layer.
Under origin-per-tenant this cannot happen by accident — but it *can* be configured wrongly, which is
what the `expected_origins`-vs-`rp_id` write validation ([§5.2](#52-resolution-is-authoritative-not-a-hint))
keeps shut.

### G9 — SDK and transport

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| ~~G9.1~~ | ~~Handshake carries no tenant id, and adding one is not backward-compatible~~ | `packages/wallet-transport/src/protocol.ts:10,19-35,95-98` | — | **Deleted.** Tenant = origin, so nothing needs to travel the transport. `PROTOCOL_VERSION` stays at 1 ([§3.5](#35-no-transport-or-sdk-change-is-needed)) |
| G9.2 | dApp SDK cache key `'giano:sdk:session'` is unnamespaced — two providers on one dApp origin overwrite each other and answer with the wrong account **without opening a popup** | `packages/connector/src/thin/create-giano-wallet-provider.ts:40,155-160` | **P1** | Namespace by `walletUrl` + `chainId`. Still real: one dApp origin could legitimately address two wallet origins |
| G9.3 | `eth_chainId` served from cache with **no chain check** | `create-giano-wallet-provider.ts:158-160` | P1 | Validate against the configured chain |
| G9.4 | `sdkVersion` captured but **never gated** against a minimum, despite `COMPATIBILITY.md` | `packages/wallet-transport/src/host.ts:38,100,118` | P1 | Enforce a minimum; reject stale clients. **More important now** — we do not control when a tenant's origin upgrades |
| G9.5 | `encodeUserId` packs a fixed 41 bytes with no room for a tenant discriminator | `create-wallet-api-injection.ts:149-168` | P2 | Only matters if the tenant must be recoverable from the WebAuthn `user.id`; the RP ID already carries it |
| G9.6 | `GET /v1/userops/:hash/receipt` is fully public — any tenant can poll any other's userop hash | `routes/userops.ts:216-229` | P2 (decision) | Defensible (on-chain public data) but make it explicit |

### G10 — Migrations

`services/wallet-api/migrations/0001_init.sql` is the only migration. Runner `src/migrate.ts`: plain
SQL, no Drizzle Kit, no snapshots; files discovered by
`readdirSync(...).filter(f => f.endsWith('.sql')).sort()` (`:16-19`) — **filename-lexicographic**, so
the next file is `0002_tenants.sql`. Each file runs in one transaction (`:33-42`) under
`pg_advisory_lock(0x67_69_61_6e_6f)` (`:11,:25`).

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| G10.1 | `schema.ts` is **hand-maintained in parallel** with the SQL — no generation step, so every column is written twice and can drift | `src/db/schema.ts` vs `migrations/0001_init.sql` | P1 | Discipline + a drift test, or adopt Drizzle Kit |
| G10.2 | **Constraint-name footgun.** `0001_init.sql:13` declares `external_id text NOT NULL UNIQUE` inline, so Postgres names it **`users_external_id_key`** — *not* Drizzle's `users_external_id_unique`. A `DROP CONSTRAINT` that guesses wrong fails the whole migration | `0001_init.sql:13` | **P1** | Verify the live name before writing the DROP |

Standard three-step for a `NOT NULL tenant_id`: add nullable → backfill to a synthetic default tenant →
set `NOT NULL` and swap the unique indexes. All expressible in one file given the transactional runner.

### G11 — Tests and deployment artifacts

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| G11.1 | The integration suite creates users **only through HTTP** with bare ids (`'user-1'`, `'user-auth'`, …). A `NOT NULL tenant_id` breaks it as *"the API has no way to say which tenant"* | `test/api.test.ts` | **P1** | Seed tenants in `startTestStack`; send a per-tenant `Origin` header. The breakage **forces** the resolution design — a feature |
| G11.2 | `test/setup.ts:9` stubs `eth_call` to always return one `TEST_WALLET_ADDRESS`, asserted at `api.test.ts:90` | `test/setup.ts:9` | P2 | Only needs changing if the `nonce` salt is ever adopted (G4.1) |
| G11.3 | **E2E cannot prove tenant isolation** — one `WALLET_URL` | `e2e/tests/helpers.ts:3` | **P1** | Add a second wallet origin + second tenant. Now cheap: two `*.localhost` hosts give two real RP IDs, so the isolation being tested is the real mechanism |
| G11.4 | All four compose files, the Helm chart and `openapi/generate.ts:15-25` assume one tenant | `deploy/*`, `openapi/generate.ts` | P1 | Update (no back-compat required per [§2](#2-decisions-taken)) |

### G12 — Custom-domain onboarding *(new — created by this decision)*

See [§4](#4-what-it-costs-custom-domain-onboarding) for detail.

| ID | Gap | Sev | Required change |
|---|---|---|---|
| G12.1 | No TLS certificate issuance flow for domains we do not own | **P0** | ACM (or equivalent) per tenant domain, DNS-validated. Blocks onboarding entirely |
| G12.2 | No certificate-renewal monitoring — silent failure if the tenant removes the validation record | **P1** | Alert on approaching expiry, not only on failure |
| G12.3 | Edge routing limits undocumented (ALB defaults to 25 certificates per HTTPS listener; CloudFront requires the certificate in `us-east-1`) | P1 | Document; know the ceiling before onboarding client 26 |
| G12.4 | No onboarding runbook | **P1** | DNS record → certificate request → validation → tenant row → admin key → `giano-doctor` acceptance run |
| G12.5 | No UI deployment story per origin | **P1** | See [D2](#d2--one-ui-deployment-per-origin-or-one-serving-many-hosts) |

---

## 8. Decisions still required

### D1 — `RP_ID` per tenant *(irreversible per tenant)*

Each tenant's `RP_ID` must be **the host of its wallet origin** (`wallet.keo.com`) — the shape that
already ships and already validates
([§3.2](#32-rp_id--the-wallet-host-which-is-the-config-shape-that-already-ships)).

The open sub-question is whether to offer the **registrable parent** (`keo.com`) to tenants who want
credentials usable from `app.keo.com` as well. That requires the `rpId` plumbing fix first, and it is
irreversible once the tenant's first passkey exists.

**Recommend:** default to the wallet host; offer the registrable parent only after the plumbing fix
lands, and require written sign-off per tenant. Record the chosen value in the tenant row at creation
and never allow it to be edited.

### D2 — One UI deployment per origin, or one serving many hosts

| Option | Code change | Cost | Notes |
|---|---|---|---|
| **One static build per origin** ← recommended to start | **None.** `envsubst` already renders per-container config | ~$2–3/month per origin on S3 + CloudFront | Each tenant's `/config.json`, CSP and branding are naturally isolated. Deletes G7.2 |
| One deployment, Host-aware config | Dynamic `/config.json` keyed by `Host`; move `App.tsx`'s `useMemo` construction behind resolution | One distribution | Consolidates ops but reintroduces a runtime resolution path in the browser |

**Recommend the per-origin static build.** The UI is a static SPA, so N copies is trivial and needs no
code change at all — which means the frontend does not block the backend work. Revisit if the origin
count passes ~20.

### D3 — Remaining decisions

| # | Decision | Recommendation |
|---|---|---|
| D3.1 | Is `externalId` tenant-supplied via a signed grant, or server-minted? | **Tenant-supplied via a signed grant.** It is the documented purpose of the seam and the only way the id means anything |
| D3.2 | Where must grant headers apply? | **Both `verify` calls too**, not just `options` (G7.4), so registration authorization is not bypassable |
| D3.3 | Shared or per-tenant paymaster? | **Per-tenant**, each funding its own EntryPoint deposit, scoped via `USEROP_ALLOWED_PAYMASTERS`. A shared paymaster means one tenant drains another's gas |
| D3.4 | Session token scope | **One session per tenant.** Origin partitioning gives this for free in the browser; enforce it server-side too (G2.3) |
| D3.5 | Admin key model | **Per-tenant hashed keys in a table**, plus a separate global operator key for cross-tenant operations |
| D3.6 | `/metrics` | **Operator-only behind auth**, with a `tenant` label |
| D3.7 | Public receipt endpoint | Keep public (on-chain data is public anyway), but record the decision (G9.6) |
| D3.8 | Fix the `rpId` plumbing? | **Yes, but not as a blocker.** It unlocks registrable-parent RP IDs and activates ROR. P2 |

---

## 9. Work breakdown

**M1–M3 are the safety floor.** Running multi-tenant before M3 means shipping C1 and the authorization
gaps to production.

| Phase | Content | Exit criterion |
|---|---|---|
| **M0** Decide | D1, D2 signed off; onboarding runbook drafted | RP-ID rule and UI deployment model fixed |
| **M1** Schema + resolver | `tenants` table; `tenant_id` on `users`, `credentials`, `challenges`, `ror_origins`, `userop_log`; `tenantId` in `SessionContext`; per-request resolver by `Origin`/`Host` replacing boot closures; `0002_tenants.sql` | Two tenants on two origins coexist; test suite green with per-tenant `Origin` headers |
| **M2** Close C1 + RP resolution | `UNIQUE (tenant_id, external_id)`; per-tenant `RP_ID`/`EXPECTED_ORIGINS` with write-time validation (**G3.3 — what makes C2/C3 safe**); credential and challenge tenant scoping | Every negative test in [§10](#10-verification-strategy) passes. **This is the gate** |
| **M3** Auth + admin | Key→tenant resolution; scoped admin routes; session tenant assertion; fail-closed origins and CORS; `timingSafeEqual`; wire `getRegistrationGrant` | No admin key can touch another tenant's data; `OPEN_REGISTRATION=false` works |
| **M4** Custom-domain onboarding | Certificate issuance + renewal monitoring; edge routing; per-origin UI deployment; runbook | A second tenant onboarded from the runbook alone |
| **M5** Policy + quota | Per-tenant `PolicyConfig`, `OPEN_REGISTRATION`, per-tenant relay quota, paymaster scoping | One tenant cannot exhaust the shared bundler |
| **M6** Observability | `tenant` label on all metrics; auth on `/metrics`; tenant in logs and `userop_log` | Per-tenant dashboard exists |
| **M7** Artifacts + tests | Compose, Helm, E2E second origin, `openapi/generate.ts` | Isolation proven end to end in CI |

M4 can run in parallel with M2–M3 — it is operations work, not application code. M6 can run in parallel
with M5.

---

## 10. Verification strategy

**No gap is closed until a negative test proves it.** C1 in particular *succeeds silently* — it is
invisible to every happy-path test. The matrix below does not exist today and cannot be written before
M1.

| # | Test | Asserts | Closes |
|---|---|---|---|
| V1 | Register `externalId: "user-1"` on tenant A's origin, then on tenant B's | **Two distinct `users` rows, two distinct wallets.** Currently one row | C1 |
| V2 | Replay tenant A's credential id against tenant B's origin | **Rejected** — and assert it is rejected by *our* tenant check, not only by `rpIdHash`, so the guard is proven independently | C2 |
| V3 | Issue a challenge on tenant A's origin, consume it on tenant B's | **Rejected** | C3 |
| V4 | Call `/v1/webauthn/options` for tenant A with tenant B's admin key | **401**, no credential ids disclosed | G2.1, G2.4 |
| V5 | Use tenant A's session token against tenant B's origin | **401** | G2.3 |
| V6 | Tenant A's admin key adds/deletes a ROR origin owned by B | **403** | G2.2, G8.2 |
| V7 | `GET /.well-known/webauthn` on each origin | Returns **only** that tenant's origins | G8.1 |
| V8 | Create a wallet on each of two origins with the **same authenticator** | **Different credentials and different wallet addresses** | G4.1 |
| V9 | Tenant B submits a userop whose hash tenant A already submitted | Idempotency preserved, **no `duplicate: true` leak** of A's submission | G1.6 |
| V10 | Exhaust tenant A's relay quota | Tenant B's relay **unaffected** | G5.2 |
| V11 | Insert a tenant row whose `expected_origins` is not under its `rp_id` | **Rejected at write time** | G3.2, G3.3 |
| V12 | Full E2E across two wallet origins with two tenants | Flow isolated end to end | G11.3 |

V1, V2, V3, V8 and V11 must exist before any client traffic. `test/api.test.ts:107-118` already asserts
cross-**user** challenge reuse fails — the natural home for the cross-**tenant** equivalents.

**V8 deserves emphasis.** Much of the severity downgrading in this document rests on *"passkeys are
RP-bound, so a user gets a distinct key per tenant"*. That is correct per specification, but the
architecture now leans on it. Prove it in a real browser with the CDP virtual authenticator
(`e2e/tests/helpers.ts:11-26`) rather than trusting the reasoning.

---

## Appendix A: pre-existing bugs found en route

Not tenancy issues. Recorded so they are not lost.

| Bug | Evidence |
|---|---|
| `RP_NAME` is validated in config and **never read anywhere** in `src/` | `config.ts:28`; zero `config.RP_NAME` references |
| `useropLatency` timer started at `routes/userops.ts:91` but `stopTimer()` only on the success path (`:162`) — rejected and failed ops never observe the histogram | `routes/userops.ts:91,162` |
| The policy pipeline **never validates the submitted `factory` address** against `config.FACTORY_ADDRESS` — a client can deploy against an arbitrary factory | zero `FACTORY_ADDRESS` refs in `routes/userops.ts`, `src/services/userop-policy.ts` |
| `preVerificationGas` is in `PolicyUserOp` but **no rule caps it** | `src/services/userop-policy.ts:39` |
| nginx `add_header` inheritance: `location = /config.json` and `location /assets/` each declare their own `add_header`, so **both silently lose** the server-level CSP, `X-Frame-Options`, `nosniff` and `Referrer-Policy` | `services/wallet-web/docker/nginx.conf.template:9-12,41-47` |
| `sdkVersion` captured but never gated against a minimum, despite `COMPATIBILITY.md` | `packages/wallet-transport/src/host.ts:38,100,118` |
| `challenges.prune()` and `sessions.revokeAllForUser()` are dead code — no scheduler calls either | `src/services/challenges.ts:46`, `src/services/sessions.ts:53` |
| `timingSafeIncludes` leaks key length and is not `crypto.timingSafeEqual` | `plugins/auth.ts:22-33` |
| `process.env.GIANO_VERSION` read directly, bypassing the zod schema | `app.ts:76` |

---

## Appendix B: what the shared-origin alternative would have cost

A single Giano-owned origin serving all tenants was considered and rejected. It would have saved
per-tenant DNS and TLS onboarding (G12 — roughly a day of operations work per tenant, plus renewal
monitoring) and a few dollars a month in CDN distributions.

Against that, it would have required all of the following, **none of which are needed now**:

- **Application-level credential isolation as the only control.** One RP ID for all tenants means the
  browser offers any tenant's passkey in the picker, so C2 becomes a live account-takeover path guarded
  solely by server code being correct on every present and future code path.
- **A prohibition on discoverable-credential / conditional-UI autofill**, because autofill bypasses
  `allowCredentials` by design.
- **A tenant discriminator reaching the browser.** The transport handshake cannot carry one
  ([§3.5](#35-no-transport-or-sdk-change-is-needed)), so it would have travelled in the popup URL —
  attacker-controlled — requiring a new authoritative origin→tenant endpoint to cross-check it.
- **Per-tenant wallet-address salting** via the factory `nonce`: an irreversible change requiring server
  and client derivation to agree exactly, or funds land at an unreachable counterfactual address.
- **Namespaced browser storage** for sessions and external user ids, since all tenants would share one
  `localStorage`.
- **Runtime multi-tenant configuration in the SPA**, replacing the boot-time `envsubst` model.
- **A one-way door on migration:** a tenant moving from Giano's UI to its own would change RP ID and
  force every user to re-register.

The trade was a few days of recurring operations work against a permanent, systemic security
obligation. **Do not reverse this decision without re-reading this list.**
