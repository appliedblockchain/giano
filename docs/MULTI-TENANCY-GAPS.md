# Multi-Tenancy Gap Analysis

**What is missing to run one standalone Giano instance for many clients — with bring-your-own wallet
UI.**

Status: draft · Last updated 2026-07-27 · Owner: Giano team
Companion documents: [`PRODUCT-STRATEGY.md`](./PRODUCT-STRATEGY.md) · [`COST-MODEL.md`](./COST-MODEL.md)

> This document **supersedes** `PRODUCT-STRATEGY.md` §5.2 (topology T2) and roadmap item P4b, which
> named this work but never specified it.

---

## Contents

- [1. Scope and target architecture](#1-scope-and-target-architecture)
- [2. Decisions taken](#2-decisions-taken)
- [3. Two premise corrections — read first](#3-two-premise-corrections--read-first)
- [4. The tenancy model](#4-the-tenancy-model)
- [5. Critical defects (C1–C3)](#5-critical-defects-c1c3)
- [6. Living with a shared origin](#6-living-with-a-shared-origin)
- [7. Gap inventory](#7-gap-inventory)
- [8. Decisions still required](#8-decisions-still-required)
- [9. Work breakdown](#9-work-breakdown)
- [10. Verification strategy](#10-verification-strategy)
- [Appendix A: pre-existing bugs found en route](#appendix-a-pre-existing-bugs-found-en-route)

---

## 1. Scope and target architecture

One Applied-Blockchain-operated Giano instance — **one `wallet-api` process, one Postgres database,
one bundler, one chain** — serving many client projects. Each client either uses the shared
Giano-hosted wallet UI or builds its own.

```
   app.acme.com ─┐                    ┌─► wallet.giano.com  (ours, SHARED by N tenants)
   app.beta.com ─┼── popup ───────────┤
   app.keo.com  ─┴────────────────────┴─► wallet.keo.com    (KEO's own, 1 tenant)
                                              │
                          ══════════════ trust boundary ═════
                                              │
                     ┌────────────────────────▼─────────────────────────┐
                     │  ONE standalone Giano instance                   │
                     │  wallet-api · ONE Postgres · Alto · contracts    │
                     └──────────────────────────────────────────────────┘
```

### Non-goals

| Not in scope | Why |
|---|---|
| Client-facing dashboard | Explicitly excluded. Setup is manual. |
| Self-serve onboarding / billing | Manual setup by an engineer is acceptable. |
| Per-tenant chain | One chain for all tenants (§2). |
| Single-tenant back-compatibility | Multi-tenant becomes the only model (§2). |
| Iframe-embedded wallet | `frame-ancestors 'none'` is deliberate. |

### Terms used precisely throughout

- **Gap** — a capability that does not exist. Costs work.
- **Defect** — a control that is *wrong today* and becomes exploitable under multi-tenancy. Costs
  work *and* carries risk until fixed.
- **Tenant** — one client project.
- **Wallet origin** — a browser origin serving a wallet UI. Carries exactly one RP ID.

Headline finding: a repo-wide grep for `tenant|multi-tenan|clientId|client_id|appId|projectId` across
`services/`, `packages/` and `deploy/` returns **zero application hits**. There is no tenancy
dimension anywhere — not in the schema, not in config, not in the SDK, not in the transport protocol.
`services/wallet-api/README.md:5-6` states the current model plainly: *"every client project deploys
it in its own stack (Giano is never centrally hosted)."*

---

## 2. Decisions taken

| Question | Decision | Consequence |
|---|---|---|
| How does the Giano-hosted UI serve many clients? | **One shared origin** | One RP ID for all hosted tenants ⇒ **credential isolation becomes application-level, not cryptographic.** Drives most of the P0 work — see [§6](#6-living-with-a-shared-origin). |
| Chain scope | **One chain for all tenants** | `CHAIN_ID`, `RPC_URL`, `BUNDLER_URL`, `ENTRYPOINT_ADDRESS`, `FACTORY_ADDRESS` stay global. Removes a large block of work — but see [G4](#g4--wallet-address-collision) for the sting in the tail. |
| Tenant resolution | **dApp origin → tenant, plus a per-tenant key for registration** | Reuses the existing `allowedDappOrigins` and `getRegistrationGrant` seams. No public SDK signature change. |
| Back-compatibility | **None — multi-tenant is the only model** | Every deployment gets a `tenants` table, even with one row. All four compose files, the Helm chart, the E2E suite, `test/setup.ts` and `openapi/generate.ts` need updating. |

---

## 3. Two premise corrections — read first

Both change what the reader should expect. Neither was obvious before reading the code.

### 3.1 `RP_ID = giano.com` does not work today — it must equal the wallet host

The natural reading of "shared origin" is RP ID = the registrable parent, `giano.com`, so that
`wallet.giano.com` and any future `*.giano.com` origin share one credential namespace. **That
configuration boots successfully and then fails every ceremony.**

**No code anywhere sets `rp.id` or `rpId`.** Registration calls:

```ts
// packages/wallet-core/src/provider.ts:422
const credential = await createWebAuthnCredential({
  user: { name: credentialName, id: await injection.encodeUserId(...) },
  challenge: credentialInfo.challenge,
  // ← no `rp`
```

and authentication:

```ts
// packages/wallet-core/src/account/get-credential.ts:27-32
publicKey: {
  challenge: options.challenge,
  userVerification: options.userVerification ?? DEFAULT_USER_VERIFICATION_REQUIREMENT,
  allowCredentials: getAllowCredentials(options.credentialId),
  // ← no `rpId`
},
```

A grep for `rp:`/`rpId` across `wallet-core`, `connector` and `wallet-web` `src/` returns **only** the
dead field at `services/wallet-web/src/config.ts:14` and `:42`. So the browser defaults `rp.id` to
`window.location.hostname` = `wallet.giano.com`, while the server verifies with
`expectedRPID: config.RP_ID` = `giano.com` (`services/wallet-api/src/routes/webauthn.ts:181`,
`:266`) → `rpIdHash` mismatch → `400 verification-failed`.

Worse: the boot validator **permits** the mismatch, because it only checks that origins are at-or-under
`RP_ID`. So the failure surfaces at ceremony time, in production, per user — the worst available
failure mode. Every shipped config quietly avoids it by setting `RP_ID` exactly equal to the wallet
host: `deploy/docker-compose.e2e.yml:53` and `deploy/sepolia.env.example:60` (`wallet.localhost`),
`deploy/docker-compose.dev.yml:56` (`localhost`), `deploy/docker-compose.reference.yml:37`
(`e.g. wallet.clientapp.com`).

**Therefore `RP_ID` for the shared origin must be `wallet.giano.com`.** Using the registrable parent
requires fixing the `rpId` plumbing first — the same fix that would activate ROR. This is a **P0
decision**, and it is irreversible once the first passkey is created. See [§8](#8-decisions-still-required).

### 3.2 Related Origin Requests is not needed — but its endpoint leaks today

ROR looks load-bearing for multi-tenancy. It is not. In the popup architecture, **ceremonies run on
the wallet origin, never on the dApp origin** — so `app.acme.com` never invokes WebAuthn and needs no
ROR entry. ROR only matters for same-origin ceremonies, which the popup architecture does not use.
BYO-UI tenants have their own RP ID and need it even less.

So ROR work is **P2** — with two exceptions that are not optional, because they are defects rather
than gaps. Both are in [G8](#g8--related-origin-requests).

And a warning worth recording so nobody designs around it: **ROR is the wrong tool for tenant
isolation, and using it as one is a security downgrade.** Listing tenant B's origin under tenant A's
RP ID makes their credentials mutually usable at the WebAuthn layer, and nothing downstream
re-establishes the boundary.

---

## 4. The tenancy model

### 4.1 Tenant and RP are orthogonal — model them separately

Because hosted tenants share an origin while BYO-UI tenants each have their own, tenant and RP are
**not the same axis**:

```
                          RP = wallet.giano.com        RP = wallet.keo.com
                     ┌───────────────────────────┬──────────────────────────┐
   wallet.giano.com  │  tenant A, B, C, …        │            —             │
   wallet.keo.com    │            —              │       tenant KEO         │
                     └───────────────────────────┴──────────────────────────┘
                          N tenants : 1 RP            1 tenant : 1 RP
```

Collapsing these into one column cannot express both. The shape that can:

```sql
wallet_origins (id, origin, rp_id, rp_name, branding jsonb, ...)   -- 1 row per wallet origin
tenants        (id, slug, wallet_origin_id → wallet_origins.id, policy jsonb, ...)
```

`EXPECTED_ORIGINS` becomes a property of the wallet origin; policy caps, quotas and allowed dApp
origins become properties of the tenant.

### 4.2 How a tenant is resolved per request

| Call | Resolution | Authority |
|---|---|---|
| `POST /v1/webauthn/options` | Per-tenant key in the grant headers | **Authoritative** — a secret |
| `POST /v1/webauthn/registration/verify` | Tenant from the consumed **challenge row** | Authoritative — server-issued |
| `POST /v1/webauthn/authentication/verify` | Tenant from the challenge row, cross-checked against `credentials.tenant_id` | Authoritative |
| `POST /v1/userops`, `/v1/me*` | Tenant from `SessionContext` | Authoritative — bearer token |
| Wallet UI config lookup | Wallet origin (Host) + tenant hint | **Hint only** |

**Two rules the implementation must not violate:**

1. **`Origin` is identification, never authorization.** A request header is attacker-controlled.
   Origin selects *which tenant config to load*; a secret (the per-tenant key, or a session token
   already bound to a tenant) is what authorizes anything.
2. **Registration must carry tenant authority from the server, not the client.** The challenge row is
   the correct carrier — it is server-issued, single-use and already exists. See [C3](#c3--challenge-binding-is-discarded).

### 4.3 Where the tenant hint can travel to the wallet UI

The transport handshake **cannot** carry it. `packages/wallet-transport/src/protocol.ts:27-35`:

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

Three blockers: zod `z.object` **strips unknown keys**, so a `tenantId` from a newer SDK to an older
wallet host is silently dropped with no error; `giano: z.literal(PROTOCOL_VERSION)` (`:10`) means any
version bump makes `parseTransportMessage` return `null` (`:95-98`) and the message is discarded with
no diagnostic, surfacing only as `HANDSHAKE_TIMEOUT` after 15s; and the origin-allowlist decision
happens at `host.ts:96` **before** the payload is read at `:100`, so a handshake-borne tenant arrives
too late to select the allowlist anyway.

**The available channel is the popup URL.** `PopupManager` navigates to `options.walletUrl` verbatim
(`packages/wallet-transport/src/popup-manager.ts:51,55`) and the dApp controls it fully
(`packages/connector/src/thin/create-giano-wallet-provider.ts:55`), so
`https://wallet.giano.com/t/acme` works and survives the SPA `try_files` fallback. It is
attacker-controlled, so it must be cross-checked against an authoritative origin → tenant map from
`wallet-api`. **No such endpoint exists** (`src/routes/` = `admin, credentials, health, userops,
webauthn, well-known`).

---

## 5. Critical defects (C1–C3)

These are not "missing features". Each is an account-takeover or leak path that activates the moment
one backend serves two clients. All three are **P0**.

### C1 — Silent cross-tenant account merge

`services/wallet-api/src/routes/webauthn.ts:196-201`:

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

**Attack / accident:** tenant B registers `externalUserId: "user-1"`. The conflict resolves to tenant
A's existing `users` row, and B's passkey is appended to A's user as an additional credential. Since
`MultiOwnable` treats every credential's public key as an owner of the same wallet, **B's user
becomes a co-owner of A's user's wallet.** No error is raised, nothing is logged.

It does not require malice. `"user-1"`, `"1"`, `"admin@example.com"` are exactly the ids two
independent clients pick.

**Required:** `UNIQUE (tenant_id, external_id)`, and the conflict target changes accordingly.

### C2 — Unauthenticated credential resolution with no tenant filter

`POST /v1/webauthn/authentication/verify` accepts **no `externalUserId` and no tenant**
(`routes/webauthn.ts:228-303`) — identity comes purely from the credential id:

```ts
// routes/webauthn.ts:255
const credential = await db.query.credentials.findFirst({ where: eq(credentials.credentialId, response.id) });
```

then, at `:293-294`:

```ts
const user = await db.query.users.findFirst({ where: eq(users.id, credential.userId) });
const session = await sessions.create(credential.userId, credential.id);
```

**This is where the shared-origin decision bites.** All hosted tenants share one RP ID, so the browser
credential picker will offer **any** passkey for that RP — including passkeys the user created with a
different tenant. Tenant B starts an authentication ceremony, the user selects their tenant-A passkey
(it looks legitimate; same RP, and `credentialName` is the only per-tenant label), verification
succeeds against the shared `expectedRPID`, and **B receives a valid session for A's user** —
including A's `walletAddress` and `externalUserId` (echoed at `:299`).

WebAuthn cannot prevent this. Only server-side scoping can.

**Required:** resolve the tenant from the challenge row; store `tenant_id` (and `rp_id`) on
`credentials`; **reject when `credential.tenant_id ≠ request tenant`**;
`UNIQUE (tenant_id, credential_id)`.

Amplifier: `POST /v1/webauthn/options` discloses another tenant's credential ids
(`routes/webauthn.ts:131-132` looks the user up by the global `external_id` and returns their
credential list), which feeds C2 directly.

### C3 — Challenge binding is discarded

`services/wallet-api/src/services/challenges.ts:29-43` atomically consumes a challenge and **returns
the bound user**:

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
`:250-253` for authentication.

**Consequence:** a challenge issued for tenant A's user is redeemable in a tenant-B ceremony with a
tenant-B `externalUserId`. Under one tenant this is a self-inflicted mismatch; under multi-tenancy it
is a cross-tenant primitive that composes with C1.

**Required:** add `tenant_id` to `challenges`; return it from `consume()`; make both verify routes use
the **consumed challenge's** tenant and user, and reject any body value that disagrees. This is the
cheapest of the three fixes — the carrier already exists.

---

## 6. Living with a shared origin

The decision to serve all hosted tenants from one origin has one dominant consequence, and it must be
stated without hedging:

> **WebAuthn provides no tenant isolation on a shared origin.** Credential discovery is scoped by RP
> ID. Every hosted tenant's passkeys live in one namespace. Tenant isolation is therefore
> **entirely application-level** — it holds only as long as every server-side check in §5 is correct.

Practical rules that follow:

| Rule | Why |
|---|---|
| `/v1/webauthn/options` must **always** return a non-empty, tenant-scoped `allowCredentials` | An empty list lets the browser offer every RP credential — i.e. every tenant's |
| **Discoverable-credential / conditional-UI autofill is prohibited** on the shared origin | Autofill bypasses `allowCredentials` by design |
| `authentication/verify` must reject on `credential.tenant_id ≠ request tenant` | The only backstop if a user picks the wrong passkey (C2) |
| The UI must let a user hold passkeys for several tenants, without revealing which others they use | One human legitimately uses two client apps |
| Per-tenant `credentialName` is the only tenant hint the authenticator shows | Set it deliberately; the RP label stays shared |

**BYO-UI tenants have a materially better threat model.** `wallet.keo.com` has its own RP ID, so the
browser enforces isolation cryptographically and C2 is structurally impossible for them. The document
should be read as: hosted tenants need every control in §5; BYO-UI tenants need them only as
defence-in-depth.

This asymmetry is worth surfacing commercially — BYO-UI is not just cheaper for us
([`COST-MODEL.md`](./COST-MODEL.md) §4), it is *safer for the client*.

---

## 7. Gap inventory

Severity: **P0** unsafe to run multi-tenant without it · **P1** required for a usable product ·
**P2** operational maturity.

### G1 — Data model

`services/wallet-api/src/db/schema.ts` — six tables, no tenant column anywhere.

| ID | Gap / defect | Evidence | Sev | Required change |
|---|---|---|---|---|
| G1.1 | `users.external_id` globally unique | `schema.ts:9` | **P0** | `UNIQUE (tenant_id, external_id)` (defect — see [C1](#c1--silent-cross-tenant-account-merge)) |
| G1.2 | `credentials.credential_id` globally unique; **no `rp_id` column** | `schema.ts:20` | **P0** | `UNIQUE (tenant_id, credential_id)` + store `rp_id`; verify against it (defect — [C2](#c2--unauthenticated-credential-resolution-with-no-tenant-filter)) |
| G1.3 | `challenges` has no tenant column and `consume()`'s binding is unused | `schema.ts:32-44`, `challenges.ts:29-43` | **P0** | Add `tenant_id`; return and enforce it (defect — [C3](#c3--challenge-binding-is-discarded)) |
| G1.4 | `SessionContext` carries no tenant | `services/sessions.ts:8-14` | **P0** | Add `tenantId` — **highest-leverage single change**, every route's authorization derives from this type |
| G1.5 | `ror_origins.origin` globally unique | `schema.ts:83` | P1 | `UNIQUE (wallet_origin_id, origin)` — today two tenants cannot register the same origin |
| G1.6 | `userop_log` has no tenant column; no dApp origin recorded | `schema.ts:64-79` | P1 | Add `tenant_id` (and consider `dapp_origin`) for attribution and billing |
| G1.7 | No `tenants` / `wallet_origins` tables | — | **P0** | Create per [§4.1](#41-tenant-and-rp-are-orthogonal--model-them-separately) |
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

| ID | Gap / defect | Evidence | Sev | Required change |
|---|---|---|---|---|
| G2.1 | `isAdminRequest` returns a **boolean, not an identity** — no route can know which tenant a key belongs to | `plugins/auth.ts:39-42` | **P0** | Resolve key → tenant; return the tenant |
| G2.2 | Every admin route is deployment-wide: any tenant's key can mutate any tenant's data | `routes/admin.ts:19,43-44,61` | **P0** | Scope all admin routes by resolved tenant (defect) |
| G2.3 | `requireSession` sets `request.session` with **no tenant assertion** — a valid token is accepted on any tenant's endpoint | `plugins/auth.ts:50-60` | **P0** | Assert session tenant matches the resolved request tenant |
| G2.4 | No origin → tenant map endpoint exists | `src/routes/` | **P0** | New endpoint; the popup-URL hint is worthless without it ([§4.3](#43-where-the-tenant-hint-can-travel-to-the-wallet-ui)) |
| G2.5 | `ADMIN_API_KEYS` is a flat in-memory list with no tenant mapping | `config.ts:62`, `app.ts:74` | **P0** | Hashed per-tenant keys in a table |
| G2.6 | `timingSafeIncludes` leaks key length, is not `crypto.timingSafeEqual`, and is an O(keys × len) scan that degrades as tenant keys accumulate | `plugins/auth.ts:22-33` | P1 | Replace with a hashed lookup + `timingSafeEqual` |

Verbatim, `services/wallet-api/src/plugins/auth.ts:22-33`:

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

The refactor is **structural, not a find-and-replace**. `src/app.ts:41-50` and `:74` build
`challenges`, `sessions`, `bundler`, `publicClient`, `adminApiKeys`, `PolicyConfig` and the rate-limit
options **once at registration**. Only two config values are read per request (`OPEN_REGISTRATION` at
`routes/webauthn.ts:127`, and the `RP_ID`/`EXPECTED_ORIGINS`/`FACTORY_ADDRESS` reads inside handler
bodies). A **per-request tenant resolver** must replace boot-time capture for everything that becomes
per-tenant.

The good news: `src/services/userop-policy.ts` is already pure functions taking an injected
`PolicyConfig` — that is the pattern to copy everywhere else.

`config.ts` cannot express the target model at all. Verbatim, `services/wallet-api/src/config.ts:89-104`:

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
| G3.2 | `superRefine` cannot express multiple RPs | `config.ts:89-104` | **P0** | Move RP/origin validation into the `wallet_origins` write path |
| G3.3 | `RP_ID`, `RP_NAME`, `EXPECTED_ORIGINS` are scalars | `config.ts:27-30` | **P0** | Per **wallet origin** |
| G3.4 | `USEROP_MAX_*` (4), `USEROP_ALLOWED_TARGETS`, `USEROP_ALLOWED_PAYMASTERS` are deployment-wide | `config.ts:43-50`, `app.ts:85-92` | **P1** | Per tenant. Tenant A's allowlist must not authorize B's calls |
| G3.5 | `OPEN_REGISTRATION` is a single global toggle — one tenant in demo mode opens registration for **every** tenant | `config.ts:57-60`, `webauthn.ts:127` | **P0** | Per tenant |
| G3.6 | `CORS_ORIGINS` is one global allowlist with `credentials: true`, registered **only if non-empty** | `app.ts:49-51` | P1 | Per tenant; fail closed |
| G3.7 | `SESSION_TTL_SECONDS`, `CHALLENGE_TTL_SECONDS` scalars | `config.ts:39-40` | P2 | Per tenant (session TTL at least) |

**Stays global** given the one-chain decision: `NODE_ENV`, `HOST`, `PORT`, `LOG_LEVEL`,
`DATABASE_URL`, `RUN_MIGRATIONS`, `CHAIN_ID`, `RPC_URL`, `BUNDLER_URL`, `ENTRYPOINT_ADDRESS`,
`FACTORY_ADDRESS`.

### G4 — Wallet address collision

This is the one place the "one chain for all tenants" simplification costs something.

The address is a pure function of `(owners, nonce, factoryAddress, initCodeHash)` — **no tenant, no
user id**. On-chain salt, `packages/contracts/src/GianoSmartWalletFactory.sol:91-92`:

```solidity
function _getSalt(bytes[] calldata owners, uint256 nonce) internal pure returns (bytes32) {
    return keccak256(abi.encode(owners, nonce));
}
```

`nonce` defaults to `0n` and **no call site in the repo ever passes one** — server at
`routes/webauthn.ts:194` (`computeWalletAddress(publicClient, config.FACTORY_ADDRESS, x, y)`, nonce
omitted), client at `packages/wallet-core/src/account/toGianoSmartAccount.ts:72`.

With one shared chain + factory, **the same passkey yields the same wallet address in every tenant**.
A shared RP ID makes reusing one passkey across tenants easy, and `credentials.wallet_address` is
non-unique (`schema.ts:29`) so the database accepts it silently.

Consequences: two tenants' sessions become authoritative over one wallet (policy authorizes against
`session.walletAddress`, `routes/userops.ts:116`), and `userop_log.sender` interleaves both tenants'
history with no attribution. Every per-tenant quota, policy and audit assumption keyed on
`wallet_address` or `sender` breaks.

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| G4.1 | Same passkey ⇒ same wallet address across tenants | `wallet-address.ts:11-25`, `GianoSmartWalletFactory.sol:91-92` | **P0** | Decision required — see [§8](#8-decisions-still-required). `nonce` is the plumbed lever |
| G4.2 | Submitted `factory` address is **never validated** against `config.FACTORY_ADDRESS` | `routes/userops.ts`, `src/services/userop-policy.ts` (zero references) | P1 | Add a policy rule (pre-existing defect, not tenancy-specific) |

### G5 — Quota and rate limiting

`@fastify/rate-limit` is registered `{ global: false }` (`app.ts:48`), so the **only** rate-limited
endpoints are the three `/v1/webauthn/*` routes (`routes/webauthn.ts:92-96`), keyed by **client IP**,
in an in-memory store that does not survive horizontal scaling.

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| G5.1 | No per-tenant quota anywhere | `app.ts:48` | **P1** | Per-tenant buckets in a shared store (Redis or Postgres) |
| G5.2 | `/v1/userops` is **unlimited** — one tenant can exhaust the shared bundler and executor balance | `routes/userops.ts:76-174` | **P1** | Per-tenant relay quota. This is a shared-resource denial-of-service across clients |
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
| G7.1 | **`externalUserId` is minted in the browser** and forgeable | `wallet-web/src/wallet.ts:6-20`; server accepts any string, `routes/webauthn.ts:111,152` | **P0** | Must come from the tenant's auth system via a signed grant — see below |
| G7.2 | Config is a boot-time singleton — runtime built before any dApp input | `entrypoint.sh:22`; `config.ts:18-24`; `main.tsx:9-16`; `App.tsx:14-15` | **P0** | Keyed cache + dynamic config endpoint; move construction behind tenant resolution |
| G7.3 | `getRegistrationGrant` **not wired**, so the shipped UI needs `OPEN_REGISTRATION=true` ⇒ **any browser can mint a user row in the shared DB unauthenticated**, IP-limited at 30/min | `wallet.ts:39-48`; `webauthn.ts:127-129` | **P0** | Wire it |
| G7.4 | Grant headers reach **only** `/v1/webauthn/options`; both `verify` calls and `/v1/userops` send none | `create-wallet-api-injection.ts:102-107` vs `:116,131,171` | **P0** | Server enforcement must not depend on this hook alone. Easily missed |
| G7.5 | Single `giano:session-token` key for the whole origin — tenants overwrite each other, last ceremony wins | `wallet.ts:7,43-47` | **P0** | Namespace per tenant |
| G7.6 | Origin allowlist **fails open**: `allowed.length === 0` permits any origin, and the env default is `[]` | `wallet-transport/src/host.ts:82-85`; `entrypoint.sh:12` | **P0** | Fail closed |
| G7.7 | `dappOrigin` is displayed but never bound to the session nor logged | `wallet-transport/src/host.ts:5-9`; `views/*.tsx` | P1 | Bind to session; record in `userop_log` |
| G7.8 | CSP `connect-src` baked at boot; with N tenants it becomes the union of all RPC + bundler URLs | `nginx.conf.template:10` | P1 | Accept the union (one chain limits the blast radius) or per-tenant origins |
| G7.9 | Per-tenant logo **forbidden by CSP** (`img-src 'self' data:`); `logoUrl` typed but unrendered | `nginx.conf.template:10`; `config.json.template:10-12`; `App.tsx:43-45` | P2 | Widen CSP deliberately or inline as `data:` |

On G7.1 — four independent reasons a per-browser random id cannot survive multi-tenancy:

```ts
// services/wallet-web/src/wallet.ts:13-20
function getOrCreateExternalUserId(): string {
  let id = localStorage.getItem(USER_ID_KEY);
  if (!id) {
    id = crypto.randomUUID().replace(/-/g, '');
    localStorage.setItem(USER_ID_KEY, id);
  }
  return id;
}
```

1. It is scoped to `(browser profile, wallet origin)` — **not to a tenant**. Two tenants sharing
   `wallet.giano.com` share one `localStorage`, therefore one external id, therefore **one `users`
   row**. Cross-tenant credential and wallet disclosure *by construction*, before any attack.
2. Authentication ignores it entirely anyway ([C2](#c2--unauthenticated-credential-resolution-with-no-tenant-filter)), so namespacing it is necessary but not sufficient.
3. `localStorage` is not durable identity. Cleared site data, Safari ITP eviction or private browsing
   produces a new UUID while the passkey survives — the user re-registers under a second `users` row,
   `giano_restoreAccount` silently fails (`packages/wallet-core/src/provider.ts:249-293`), and
   orphaned rows accumulate with no tenant to clean up by.
4. It carries no assertion from any tenant's auth system, defeating the documented purpose of the
   seam — *"the R6a binding point between app auth and credentials"*
   (`create-wallet-api-injection.ts:16`).

### G8 — Related Origin Requests

Per [§3.2](#32-related-origin-requests-is-not-needed--but-its-endpoint-leaks-today), ROR is **P2** —
except these two, which are **defects live today**:

| ID | Gap / defect | Evidence | Sev | Required change |
|---|---|---|---|---|
| G8.1 | `GET /.well-known/webauthn` is an unauthenticated, **unfiltered** `SELECT` with no `WHERE` — publishes every tenant's origins to the public internet | `routes/well-known.ts:19` | **P1** | Filter by wallet origin (Host). A customer-list leak independent of WebAuthn |
| G8.2 | Any tenant's admin key can add or delete any tenant's origins; the global `origin` unique makes `onConflictDoUpdate` silently no-op instead of erroring | `routes/admin.ts:19,43-44,61`; `schema.ts:83` | **P1** | Scope by tenant (G2.2) + `UNIQUE (wallet_origin_id, origin)` |
| G8.3 | `ror_origins` has no `rp_id`, so the document cannot be filtered per RP | `schema.ts:81-85` | P2 | Add FK to `wallet_origins` |
| G8.4 | **Chrome caps the list at 5 eTLD+1 labels** — a hard global ceiling of ~4 external tenant domains, forever, with no enforcement or comment in the code | `README-ROR.md:86` | P2 | Enforce at write time if ROR is ever enabled |

### G9 — SDK and transport

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| G9.1 | Handshake carries no tenant id and adding one is **not backward-compatible** | `wallet-transport/src/protocol.ts:10,19-35,95-98` | **P0** | Use the popup URL + server cross-check ([§4.3](#43-where-the-tenant-hint-can-travel-to-the-wallet-ui)); avoid a protocol bump |
| G9.2 | dApp SDK cache key `'giano:sdk:session'` is unnamespaced — two providers on one origin overwrite each other and answer with the wrong tenant's account **without opening a popup** | `create-giano-wallet-provider.ts:40,155-160` | **P1** | Namespace by `walletUrl` + `chainId` (+ tenant) |
| G9.3 | `eth_chainId` served from cache with **no chain check** | `create-giano-wallet-provider.ts:158-160` | P1 | Validate against the configured chain |
| G9.4 | `sdkVersion` captured but **never gated** against a minimum, despite `COMPATIBILITY.md` | `wallet-transport/src/host.ts:38,100,118` | P1 | Enforce a minimum; reject stale clients |
| G9.5 | `encodeUserId` packs a fixed 41 bytes with no room for a tenant discriminator | `create-wallet-api-injection.ts:149-168` | P2 | Only matters if tenant must be recoverable from the WebAuthn `user.id` |
| G9.6 | `GET /v1/userops/:hash/receipt` is fully public — any tenant can poll any other's userop hash | `routes/userops.ts:216-229` | P2 (decision) | Defensible (on-chain public data) but make it an explicit decision |

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

Standard three-step for a `NOT NULL tenant_id`: add nullable → backfill to a synthetic default tenant
→ set `NOT NULL` and swap the unique indexes. All expressible in one file given the transactional
runner.

### G11 — Tests and deployment artifacts

| ID | Gap | Evidence | Sev | Required change |
|---|---|---|---|---|
| G11.1 | The whole integration suite creates users **only through HTTP** with bare ids (`'user-1'`, `'user-auth'`, …). A `NOT NULL tenant_id` breaks it as *"the API has no way to say which tenant"* | `test/api.test.ts` | **P1** | Seed a tenant in `startTestStack`; thread a selector through the helpers. The breakage **forces** the resolution design — a feature |
| G11.2 | `test/setup.ts:9` stubs `eth_call` to always return one `TEST_WALLET_ADDRESS`, asserted at `api.test.ts:90` | `test/setup.ts:9` | P1 | Make key-aware if G4.1 lands |
| G11.3 | **E2E cannot prove tenant isolation** — one `WALLET_URL` | `e2e/tests/helpers.ts:3` | **P1** | Add a second origin + second tenant |
| G11.4 | All four compose files, the Helm chart and `openapi/generate.ts:15-25` assume one tenant | `deploy/*`, `openapi/generate.ts` | P1 | Update (no back-compat required per §2) |

---

## 8. Decisions still required

Each blocks implementation. Recommendations given; **the first two are irreversible.**

### D1 — RP ID for the shared origin *(irreversible)*

| Option | Works today | Cost |
|---|---|---|
| **`wallet.giano.com`** ← recommended | ✅ Yes | None. Ceremonies work immediately |
| `giano.com` (registrable parent) | ❌ No — see [§3.1](#31-rp_id--gianocom-does-not-work-today--it-must-equal-the-wallet-host) | Fix the `rpId` plumbing first: thread the server's `rpId` (already returned at `webauthn.ts:138`, discarded at `create-wallet-api-injection.ts:103`) into `createWebAuthnCredential({ rp })` and `navigator.credentials.get({ publicKey: { rpId } })` |

**Recommend `wallet.giano.com`.** Ship it, and fix the `rpId` plumbing as separate work — it also
activates ROR. Passkeys bind permanently, so this needs written sign-off.

### D2 — Wallet address salt *(irreversible for deployed wallets)*

| Option | Effect |
|---|---|
| **`nonce = f(tenant_id)`** ← recommended | One wallet per (passkey, tenant). Tenant B cannot see or act on A's wallet. Per-tenant quota, policy and audit all become coherent |
| Keep `nonce = 0` | One wallet per passkey, shared across tenants. Two tenants' sessions authoritative over one wallet; attribution impossible |

**Recommend per-tenant.** Critical caveat: **server and client derivation must agree exactly** —
`services/wallet-api/src/services/wallet-address.ts` and
`packages/wallet-core/src/account/toGianoSmartAccount.ts` — or funds land at an unreachable
counterfactual address. Add a cross-check test (one already exists in spirit for the base case).

### D3 — Tenant-id transport

**Recommend the popup URL hint + authoritative server-side origin→tenant cross-check.** No protocol
bump, no lockstep rollout. A handshake field requires `PROTOCOL_VERSION` 1→2 and coordinated
deployment across every tenant's wallet origin *and* every tenant's dApp, and still arrives too late
in the message ordering to select the origin allowlist ([§4.3](#43-where-the-tenant-hint-can-travel-to-the-wallet-ui)).

### D4 — Remaining decisions

| # | Decision | Recommendation |
|---|---|---|
| D4.1 | Is `externalId` tenant-supplied via signed grant, or server-minted? | **Tenant-supplied via a signed grant.** It is the documented purpose of the seam and the only way the id means anything |
| D4.2 | Where must grant headers apply? | **All ceremony calls + `/v1/userops`**, not just `options` (G7.4). Or drop the dependency entirely and derive tenant server-side from the challenge row |
| D4.3 | Shared or per-tenant paymaster? | **Per-tenant**, each funding its own EntryPoint deposit, scoped via `USEROP_ALLOWED_PAYMASTERS`. A shared paymaster means one tenant drains another's gas |
| D4.4 | Session token scope | **One session per tenant.** A token that spans tenants re-creates C2 at the session layer |
| D4.5 | Admin key model | **Per-tenant hashed keys in a table**, plus a separate global operator key for cross-tenant ops |
| D4.6 | `/metrics` | **Operator-only behind auth**, with a `tenant` label. Do not expose per-tenant volumes publicly |
| D4.7 | Public receipt endpoint | Keep public (on-chain data is public anyway), but record the decision (G9.6) |

---

## 9. Work breakdown

Each phase has a binary exit criterion. **M1–M3 are the safety floor** — running multi-tenant before
M3 completes means shipping C1–C3 to production.

| Phase | Content | Exit criterion |
|---|---|---|
| **M0** Decide | D1, D2, D3 signed off in writing | Decisions recorded; RP ID and salt formula fixed |
| **M1** Schema + resolver | `tenants` + `wallet_origins` tables; `tenant_id` on `users`, `credentials`, `challenges`; `tenantId` in `SessionContext`; per-request tenant resolver replacing boot closures; `0002_tenants.sql` | Two tenants coexist; test suite green with a tenant selector |
| **M2** Close C1–C3 | Scoped uniques; challenge-carried tenant authority; `credentials.tenant_id`/`rp_id` enforcement in `authentication/verify`; tenant-scoped `allowCredentials` | **Every negative test in [§10](#10-verification-strategy) passes.** This is the gate |
| **M3** Auth + admin | Key→tenant resolution; scoped admin routes; session tenant assertion; fail-closed origins and CORS; `timingSafeEqual` | No admin key can touch another tenant's data |
| **M4** Policy + quota | Per-tenant `PolicyConfig`, `OPEN_REGISTRATION`, per-tenant relay quota, paymaster scoping | One tenant cannot exhaust the shared bundler |
| **M5** Wallet origin | Dynamic per-tenant config; wire `getRegistrationGrant`; namespaced storage; tenant-scoped external ids; ROR filtering (G8.1/G8.2) | One `wallet-web` deployment serves two tenants with distinct branding and isolated sessions |
| **M6** Observability | `tenant` label on all metrics; auth on `/metrics`; tenant in logs and `userop_log` | Per-tenant dashboard exists |
| **M7** Artifacts + docs | Compose, Helm, E2E second origin, `openapi/generate.ts`, onboarding runbook | A new tenant onboarded manually from the runbook alone |

Dependency note: M5 depends on M1 (needs the origin→tenant endpoint) but not on M4. M6 can run in
parallel with M4–M5.

---

## 10. Verification strategy

**No gap is closed until a negative test proves it.** Every defect in §5 is invisible in a
happy-path test — C1 in particular *succeeds silently*. The isolation matrix below does not exist
today and cannot be written without M1.

| # | Test | Asserts | Closes |
|---|---|---|---|
| V1 | Register `externalId: "user-1"` in tenant A, then in tenant B | **Two distinct `users` rows, two distinct wallets.** Currently one row | C1 |
| V2 | Authenticate with tenant A's credential against a tenant-B-resolved request | **Rejected.** Currently issues a valid session for A's user | C2 |
| V3 | Issue a challenge in tenant A, consume it in a tenant-B ceremony | **Rejected** | C3 |
| V4 | `POST /v1/webauthn/options` for tenant A with tenant B's key | **401**, and no credential ids disclosed | G2.1, G2.5 |
| V5 | Use tenant A's session token on a tenant-B-resolved endpoint | **401** | G2.3 |
| V6 | Tenant A's admin key adds/deletes a ROR origin owned by B | **403** | G2.2, G8.2 |
| V7 | `GET /.well-known/webauthn` on origin X | Returns **only** X's origins | G8.1 |
| V8 | Register the **same passkey** in tenants A and B | **Different wallet addresses**; server and client derivations agree | D2, G4.1 |
| V9 | Tenant B submits a userop whose hash tenant A already submitted | Idempotency preserved, **no `duplicate: true` leak** of A's submission | G1.6 |
| V10 | Exhaust tenant A's relay quota | Tenant B's relay **unaffected** | G5.2 |
| V11 | Two tenants' flows in one browser on the shared origin | Independent sessions; neither overwrites the other | G7.5 |
| V12 | E2E across two wallet origins with two tenants | Full flow isolated end to end | G11.3 |

V1, V2, V3 and V8 are the ones that must exist before any client traffic. `test/api.test.ts:107-118`
already asserts cross-**user** challenge reuse fails — the natural home for the cross-**tenant**
equivalents.

---

## Appendix A: pre-existing bugs found en route

Not tenancy issues. Recorded so they are not lost.

| Bug | Evidence |
|---|---|
| `RP_NAME` is validated in config and **never read anywhere** in `src/` | `config.ts:28`; zero `config.RP_NAME` references |
| `useropLatency` timer started at `routes/userops.ts:91` but `stopTimer()` only on the success path (`:162`) — rejected and failed ops never observe the histogram | `routes/userops.ts:91,162` |
| The policy pipeline **never validates the submitted `factory` address** against `config.FACTORY_ADDRESS` — a client can deploy against an arbitrary factory | zero `FACTORY_ADDRESS` refs in `routes/userops.ts`, `src/services/userop-policy.ts` |
| `preVerificationGas` is in `PolicyUserOp` but **no rule caps it** | `services/userop-policy.ts:39` |
| nginx `add_header` inheritance: `location = /config.json` and `location /assets/` each declare their own `add_header`, so **both silently lose** the server-level CSP, `X-Frame-Options`, `nosniff` and `Referrer-Policy` | `wallet-web/docker/nginx.conf.template:9-12,41-47` |
| `sdkVersion` captured but never gated against a minimum, despite `COMPATIBILITY.md` | `wallet-transport/src/host.ts:38,100,118` |
| `challenges.prune()` and `sessions.revokeAllForUser()` are dead code — no scheduler calls either | `services/challenges.ts:46`, `services/sessions.ts:53` |
| `timingSafeIncludes` leaks key length and is not `crypto.timingSafeEqual` | `plugins/auth.ts:22-33` |
| `process.env.GIANO_VERSION` read directly, bypassing the zod schema | `app.ts:76` |
