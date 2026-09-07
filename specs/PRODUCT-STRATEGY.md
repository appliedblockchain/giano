# Giano Product Strategy

**How we get from "a repo we deploy for each project" to "a product every project uses" — without
building the product first.**

Status: draft · Last updated 2026-07-27 · Owner: Giano team
Companion document: [`docs/COST-MODEL.md`](./COST-MODEL.md)

---

## Contents

- [1. Where we are and where we are going](#1-where-we-are-and-where-we-are-going)
- [2. Purpose and non-goals](#2-purpose-and-non-goals)
- [3. What "bring your own UI" means](#3-what-bring-your-own-ui-means)
- [4. The three-layer product model](#4-the-three-layer-product-model)
- [5. The constraint that decides the roadmap: one RP ID per backend](#5-the-constraint-that-decides-the-roadmap-one-rp-id-per-backend)
- [6. Modularity seams](#6-modularity-seams)
- [7. The three-tier integration contract](#7-the-three-tier-integration-contract)
- [8. Roadmap](#8-roadmap)
- [9. How we work](#9-how-we-work)
- [10. Risk register](#10-risk-register)

---

## 1. Where we are and where we are going

Giano today is packaged as **self-hosted artifacts a customer deploys into their own
infrastructure**. Every client project stands up its own Postgres, `wallet-api`, `wallet-web` and
bundler. This is the target state the current architecture was built for: *every client project
deploys itself as services in its own stack (Giano is never centrally hosted)*, with a dedicated
wallet origin — `wallet.clientapp.com` — served by a Giano container.

That model is correct for a customer who wants full custody of their infrastructure. It is a poor
model for **us**, because every new project repeats a deployment from scratch and we amortise
nothing.

The change of direction is this:

> **We run one internal Applied Blockchain deployment of Giano as a standalone service. KEO is the
> first integrator. KEO builds its own wallet origin — `wallet.keo.com` — against a Giano SDK,
> talking to our backend and database. There is no dashboard and no product surface.**

The important refinement, and the thing that distinguishes this from the architecture as shipped:
today the wallet origin is **always a Giano-shipped container**
(`giano-wallet-web`). Under bring-your-own-UI the wallet origin is a **client-built application** that
happens to use our SDK. Everything below the origin — backend, database, bundler, contracts — stays
ours.

Self-hosting does not go away. We are adding distribution modes, not replacing the first.

The end goal is Giano as a standalone product any project can adopt. **We deliberately do not build
toward that goal directly.** We build the smallest thing that makes KEO successful, and let each
subsequent client pull the next capability out of us. Every phase in [§8](#8-roadmap) is shippable on
its own and creates no obligation to build the next one.

---

## 2. Purpose and non-goals

### In scope for the first milestone

- One internal Giano deployment — `wallet-api`, Postgres, bundler — operated by us on managed AWS.
- **A published wallet-side SDK** that lets KEO build `wallet.keo.com` in-house.
- KEO's own dApp UI *and* its own wallet origin, both built by KEO.
- Enough operational maturity to be genuinely reliable: health checks, metrics, alerting, backups.
- A conformance checklist, because KEO's origin becomes part of the trust boundary.

### Explicit non-goals (for now)

| Not building | Why not yet | When |
|---|---|---|
| Admin dashboard | KEO does not need one; a dashboard is a product, and we do not have a product | P6 |
| User management UI | Same | P6 |
| A Giano-operated wallet origin shared across clients | **Rejected architecturally**, not deferred — see [§5.3](#53-every-tenant-owns-its-wallet-origin--and-that-removes-the-one-way-door). Every client owns its origin | Never |
| Multiple wallet origins on **one** backend | Needs multi-RP support — see [§5](#5-the-constraint-that-decides-the-roadmap-one-rp-id-per-backend). One origin per backend covers KEO; a stack per client stays viable at 1–5 clients | P4 |
| Logical multi-tenancy in `wallet-api` | Infrastructure-level isolation is cheap enough at 1–5 clients (see cost model) | P6 |
| Self-serve signup / billing | No demand signal | Not scheduled |
| Multi-chain in a single stack | KEO needs one chain | P5 |
| Iframe-embedded wallet | `frame-ancestors 'none'` is deliberate; the popup transport is the only supported mode | Not scheduled |

Writing these down matters as much as the roadmap. The failure mode for this kind of project is
building P6 during P1.

---

## 3. What "bring your own UI" means

There are **two** UIs in this system and they have completely different answers. Conflating them is
the main source of confusion.

| | **dApp UI** | **Wallet UI (the wallet origin)** |
|---|---|---|
| What it is | The client's application | The passkey + consent surface |
| Example host | `app.keo.com` | `wallet.keo.com` |
| Our reference | `services/custom-example`, `e2e/dapp` | `services/wallet-web` |
| Holds credentials? | No — zero WebAuthn code | **Yes — this is the trust boundary** |
| Passkey binds to it? | No | **Yes — the RP ID is this host** |
| SDK it uses | `giano-connector` (thin dApp SDK) | `giano-wallet-core` + `giano-wallet-transport` (+ the wallet client package we must extract) |
| **BYO today?** | **Yes, fully supported** | **No — the SDK is not packaged** |

### 3.1 The dApp UI is already solved

A dApp installs `@appliedblockchain/giano-connector`, calls `createGianoWalletProvider({ walletUrl,
chain })`, and gets a standard EIP-1193 provider — usable raw, or via the shipped wagmi connector or
RainbowKit wallet. No WebAuthn, credential, bundler or signing code is reachable from that surface.

The proof is in the repo: `e2e/dapp/main.ts` is plain TypeScript with **no framework** and drives the
complete flow, while `services/custom-example` does the same in React + Chakra UI v3. Two totally
different UIs, one unchanged SDK.

### 3.2 The wallet UI is the actual request

This is what "bring your own UI" means for KEO, stated as the target topology:

```
  ┌────────────────────────┐        ┌────────────────────────────────┐
  │  app.keo.com           │        │  wallet.keo.com                │
  │  KEO's dApp UI         │◄──────►│  KEO's WALLET UI  (in-house)   │
  │  giano-connector       │postMsg │  ─ built by KEO                │
  │                        │ popup  │  ─ uses the Giano wallet SDK   │
  └────────────────────────┘        │  ─ RP ID = wallet.keo.com      │
                                    │  ─ passkeys bind HERE          │
                                    └───────────────┬────────────────┘
                                                    │ HTTPS (bearer)
                    ══════════════════ trust boundary ══════════════
                                                    │
                  ┌─────────────────────────────────▼──────────────────┐
                  │  OUR standalone Giano instance                     │
                  │  wallet-api · Postgres · Alto bundler · contracts  │
                  │  (the same instance a Giano-hosted UI would use)   │
                  └────────────────────────────────────────────────────┘
```

KEO replaces exactly one component: **`services/wallet-web`**. Everything below it is ours.

> **A precision worth stating, because it defines the boundary.** The wallet origin is served by the
> **`wallet-web`** container (nginx + a static Vite SPA), not by `wallet-api`. The nginx layer
> proxies `/api` and `/.well-known/webauthn` through to `wallet-api` same-origin, and sets the
> security headers. So "bring your own wallet UI" means replacing `wallet-web` — the SPA *and* the
> nginx responsibilities — while keeping `wallet-api` and everything behind it.

### 3.3 What KEO takes on by owning the wallet origin

This is not just "write some React". Owning the wallet origin means owning part of the trust
boundary. The checklist below becomes the conformance contract:

| Responsibility | Today handled by | KEO must |
|---|---|---|
| Serve the SPA over TLS at a stable host | `wallet-web` nginx | Serve it, and **never change the host** — see [§5.3](#53-every-tenant-owns-its-wallet-origin--and-that-removes-the-one-way-door) |
| Reach `wallet-api` | nginx same-origin proxy `/api` | Either proxy it themselves, or call it cross-origin (viable — see below) |
| `X-Frame-Options: DENY` + `frame-ancestors 'none'` | `docker/nginx.conf.template` | Reproduce both. **We cannot enforce this.** Without it the wallet is iframe-embeddable and the trust model is gone |
| CSP `connect-src` restricted to RPC + bundler | Same template | Reproduce |
| Open only in a popup, in a user gesture | `wallet-web` + transport | Preserve |
| Pin the calling dApp origin | `TransportHost({ allowedOrigins })` | Configure — and it must **fail closed** (see P0) |
| Show the dApp origin on every consent screen | `views/*` | Reproduce — this is the anti-phishing control |
| Render call data and sign payloads truthfully | `describeCallData()`, `renderPayload()` | Use our exported helpers, not their own |
| Serve `/.well-known/webauthn` if using ROR | nginx proxy → `wallet-api` | Proxy or serve it from `wallet.keo.com` |

**The cross-origin path works today**, which is a genuinely useful finding. Sessions are opaque
bearer tokens sent as `Authorization: Bearer` — there are no cookies — and
`createWalletApiInjection({ apiUrl })` takes an arbitrary base URL. So `wallet.keo.com` can call
`api.giano.example.com` directly. It needs only:

- `CORS_ORIGINS` to include `https://wallet.keo.com` (note: today the CORS plugin is **not
  registered at all** when `CORS_ORIGINS` is empty — P0 fixes that);
- `EXPECTED_ORIGINS` to include `https://wallet.keo.com`;
- `RP_ID` to be compatible with it — and that is the constraint in [§5](#5-the-constraint-that-decides-the-roadmap-one-rp-id-per-backend).

A same-origin proxy on KEO's side is still preferable — it keeps the CSP tight and avoids preflight
latency — but it is an optimisation, not a blocker.

### 3.4 The one thing BYO-UI can never mean

**A truly headless Giano is impossible.** `navigator.credentials.create()` / `.get()` are browser
APIs bound to an origin. They are called in `packages/wallet-core/src/account/get-credential.ts` and
`packages/wallet-core/src/provider.ts`, and the WebAuthn signature is assembled in
`packages/wallet-core/src/account/toGianoSmartAccount.ts`. None of this can move to a server.

So there must always be **a real browser origin, served by someone, running our SDK**. BYO-UI changes
*who serves that origin* — it does not remove it. Any proposal for a pure server-side API with no
wallet origin is a rewrite of the security model, not a feature.

---

## 4. The three-layer product model

```
┌──────────────────────────────────────────────────────────────────────────┐
│ Layer 3 — EXPERIENCE                                 client-specific     │
│                                                                          │
│   dApp UI            │   Wallet origin UI                                │
│   KEO builds it      │   KEO builds it (BYO) ── or brands ours (Tier A)  │
│   ref: custom-example│   ref: services/wallet-web                        │
└──────────────────────┴───────────────────────────────────────────────────┘
                                   ▲  both consume Layer 2, never Layer 1
┌──────────────────────────────────────────────────────────────────────────┐
│ Layer 2 — RUNTIME SDK                                the product (npm)   │
│                                                                          │
│   giano-connector          giano-wallet-core      giano-wallet-transport  │
│   (dApp side) ◄──postMessage──►  (wallet side)    (the popup protocol)    │
│                            giano-wallet-client  ◄── TO BE EXTRACTED (P1)  │
└──────────────────────────────────────────────────────────────────────────┘
                                   ▲  HTTPS + bearer session
┌──────────────────────────────────────────────────────────────────────────┐
│ Layer 1 — PLATFORM                          the service (we run it)      │
│                                                                          │
│   wallet-api (Fastify + Postgres)   Alto bundler   contracts             │
│   WebAuthn ceremonies · sessions · policied userop relay · audit log     │
└──────────────────────────────────────────────────────────────────────────┘
```

Only Layer 3 is client-specific. **Layer 2 is the product we must actually ship** — and today only
its dApp half is publishable. Layer 1 is the service we operate.

The gap this document exists to close: `services/wallet-web` is small (616 lines including all four
views), but the ~280 lines that are *not* views — `src/config.ts`, `src/wallet.ts`, `src/host.ts`,
`src/requests.ts` — are the wallet runtime: chain and bundler wiring, fee estimation, the paymaster
stub, session persistence, the consent gate, the request store, error mapping. They live inside a
`"private": true` application. **KEO cannot install them.** Extracting them is the critical path.

---

## 5. The constraint that decides the roadmap: one RP ID per backend

This is the most consequential technical fact in this document, and it directly constrains the
"shared backend, client-owned wallet origin" model.

### 5.1 `wallet-api` supports exactly one RP ID

- `RP_ID` is a single value: `RP_ID: z.string().min(1)` (`services/wallet-api/src/config.ts`).
- Boot validation **rejects any expected origin not under it**: for every entry in
  `EXPECTED_ORIGINS`, `if (host !== env.RP_ID && !host.endsWith('.' + env.RP_ID))` → config error
  *"RP_ID … is not valid for expected origin … the origin's host must equal RP_ID or be a subdomain
  of it"*.
- Both verify routes hardcode `expectedRPID: config.RP_ID` and `expectedOrigin:
  config.EXPECTED_ORIGINS` (`src/routes/webauthn.ts`).
- The schema has **no RP or tenant column anywhere**. `users.externalId` is globally `.unique()`;
  `credentials.credentialId` is globally `.unique()`; `credentials` has no `rpId`. `ror_origins` is a
  flat global table.

**Consequence:** `wallet.keo.com` (RP ID `wallet.keo.com`) and `wallet.acme.app` (RP ID `wallet.acme.app`)
**cannot share one `wallet-api` process today.** The service would refuse to boot. This is not a
hardening gap — it is a load-bearing design decision that must change before two differently-named
wallet origins can share a backend.

### 5.2 Two topologies, and only one works today

**T1 — one wallet origin per backend deployment. Works today, zero code changes.**

```
  wallet.keo.com  ──►  wallet-api (RP_ID=wallet.keo.com) ──► DB_keo
                              ↑ KEO's own logical stack on our shared substrate
  wallet.acme.com ──►  wallet-api (RP_ID=wallet.acme.com) ──► DB_acme
```

Each client gets its own `wallet-api` task set, its own database, its own `RP_ID` — on **one shared
substrate** (one ALB, one RDS instance, one bundler per chain). Marginal cost ≈ $29/month per client;
see [`docs/COST-MODEL.md`](./COST-MODEL.md) §3. This is what "the same standalone instance" means in
practice: one operated service, one deployment pattern, one substrate — with per-client isolation
that we get for free because it is already how the config works.

**T2 — many wallet origins on one backend. Needs new work.**

```
  wallet.keo.com  ─┐
  wallet.beta.io   ─┼──►  ONE wallet-api  ──►  ONE DB
  wallet.acme.com  ─┘     (multi-RP)
```

To make T2 safe, all of the following are required:

1. `RP_ID` / `RP_NAME` / `EXPECTED_ORIGINS` become a **per-wallet-origin registry** (config or a
   table), not scalars.
2. Ceremony routes **resolve which RP applies per request.** The request `Origin` header identifies
   the calling wallet origin, but an `Origin` header alone must not be authorisation — pair it with a
   per-origin API key so one client cannot mint credentials under another's RP.
3. `credentials` gains an RP scope, so a credential registered under `wallet.keo.com` **cannot
   authenticate under a different RP**. Without this you have cross-tenant credential confusion —
   a security defect, not a limitation.
4. `users.externalId` stops being globally unique and becomes unique *per tenant*, or two clients
   collide on the same user id.
5. Policy caps, CORS, allowed dApp origins, paymaster and `ror_origins` all become per-tenant.

That list *is* the tenancy work. **T2 is a genuine re-architecture of `config.ts` and `schema.ts`, so
it gets its own phase (P4) and is not on KEO's critical path.**

> **T2 is now fully specified in [`docs/MULTI-TENANCY-GAPS.md`](./MULTI-TENANCY-GAPS.md)** — the gap
> inventory, three critical cross-tenant defects, required decisions and the isolation test matrix.
> Two corrections that document makes to this section: a shared wallet origin means `RP_ID` must equal
> the wallet host (not the registrable parent) until the `rpId` plumbing is fixed; and Related Origin
> Requests is **not** required for the popup architecture, though its endpoint leaks every tenant's
> origins today.

### 5.3 Every tenant owns its wallet origin — and that removes the one-way door

**Architectural rule, decided:** every client provides its own wallet origin —
`wallet.keo.com`, `wallet.acme.app` — and points it at either Giano's stock UI or a UI they built.
**We do not operate a shared wallet origin serving multiple clients.**

The reason is that a shared origin means a shared RP ID, and WebAuthn scopes credential discovery by
RP ID. All tenants' passkeys would live in one namespace, so the browser credential picker would offer
any tenant's passkey to any tenant's ceremony — making cross-tenant session issuance a live
account-takeover path guarded only by server code being correct. With distinct RP IDs the browser
refuses, and `verifyAuthenticationResponse` refuses again on `rpIdHash`. Isolation becomes
cryptographic instead of a permanent obligation on us.
Full reasoning and the rejected alternative: [`docs/MULTI-TENANCY-GAPS.md`](./MULTI-TENANCY-GAPS.md)
§3 and Appendix B.

**The consequence that matters commercially: the one-way door disappears.** Because the *client* owns
the origin, changing what is served there — our stock UI today, their own SPA later — does not change
the RP ID. Every passkey keeps working. So:

> **Giano's UI is an on-ramp to bring-your-own-UI, not a fork.** A client can start on our UI to get
> live quickly and migrate to their own later with **zero user re-registration**.

Passkeys still bind permanently to the RP ID, so two things need written sign-off per client before
first deploy:

- **The host is permanent.** `wallet.keo.com` cannot later become `wallet.keo.io` or
  `passkeys.keo.com` without every user re-registering. Pick it once, deliberately.
- **`RP_ID` must equal the wallet host** — `wallet.keo.com`, not `keo.com`. This is not a preference:
  no code in the repo sets `rp.id`, so the browser defaults it to the current hostname while the
  server verifies against `RP_ID`. A registrable-parent value **boots fine and then fails every
  ceremony** with `400 verification-failed`. Using `keo.com` requires the `rpId` plumbing fix first
  (which is also what activates ROR) — see `MULTI-TENANCY-GAPS.md` §3.2 and D1.

Note what ROR does and does not do: it lets several *app* origins share credentials under **one** RP
ID (`app.keo.com` and `admin.keo.com` under `keo.com`); it does **not** let one credential work under
two different RP IDs. It is not a tenancy mechanism.

**What the client takes on:** a DNS record and a TLS certificate for their domain pointing at our
edge. That is the price of the isolation, and it is an operations cost rather than a security
obligation — see `MULTI-TENANCY-GAPS.md` §4.

---

## 6. Modularity seams

Seven axes along which Giano must become pluggable. Nothing else in the system is allowed to become
client-specific.

| # | Seam | Today | Target | Phase |
|---|---|---|---|---|
| **S1** | dApp UI | Pluggable via `giano-connector` ✅ | Published, semver'd, documented | **P0** |
| **S2** | Wallet origin UI | Baked into the `wallet-web` image | Tier A brandable; **Tier B replaceable via a published wallet SDK** | **P1** |
| **S3** | Registration & identity | Global `OPEN_REGISTRATION` boolean | `getRegistrationGrant` — the integrator's backend authorises who may register | **P0** |
| **S4** | Policy & sponsorship | Env-var gas caps + `PermissivePaymaster` | Per-integrator policy + a production `VerifyingPaymaster` with its own funded deposit | **P3** |
| **S5** | **RP / origin identity** | **Single `RP_ID`; no RP scope in the schema** | **Multi-RP registry; RP-scoped credentials** | **P4** |
| **S6** | Chain | One `CHAIN_ID` per stack | Stack-per-chain, then multi-chain in one stack | **P5** |
| **S7** | Tenancy | One deployment = one tenant | Shared infrastructure substrate → logical tenancy in `wallet-api` | **P2** / **P6** |

S5 is new in this revision and is the direct consequence of [§5](#5-the-constraint-that-decides-the-roadmap-one-rp-id-per-backend).

### S2 — the wallet SDK is the critical path

KEO cannot start until the wallet-side runtime is installable. Extract
`@appliedblockchain/giano-wallet-client` from `services/wallet-web/src/{config,wallet,host,requests}.ts`:

- runtime construction (chain, bundler, paymaster stub, fee estimator);
- the consent gate and its method classification (`eth_sendTransaction`, `personal_sign`, `eth_sign`,
  `eth_signTypedData_v4`);
- the pending-request store, upgraded from **one slot to a real queue** — today a second concurrent
  request is rejected with `-32603 "another request is already pending"`;
- error mapping (`NotAllowedError`/`AbortError` → `4001`, not-connected → `4900`);
- **pluggable storage** for the session token and external user id, instead of the hardcoded
  `giano:session-token` / `giano:external-user-id` `localStorage` keys the app assumes today;
- the security-relevant display helpers: `describeCallData()` from `views/ReviewTransaction.tsx` and
  `renderPayload()` from `views/SignMessage.tsx` (which handles the `personal_sign` vs `eth_sign`
  parameter-order swap). A shared `decodeCalls` helper was planned for the thin-SDK work and never
  shipped.

Two things must not be lost:

1. **The fee-estimation fix in `src/wallet.ts`.** Its comment records that without real on-chain fee
   estimation, `wallet-core` falls back to a hardcoded 200 gwei `maxFeePerGas`, which on a low-fee
   chain inflates the required paymaster prefund ~180× and trips `AA31 paymaster deposit too low`. A
   naive reimplementation silently reintroduces this.
2. **`services/wallet-web` must be refactored onto the extracted package**, not left as a parallel
   copy. If our own UI does not consume the SDK, the SDK will rot.

### S3 — a live bug, not just a gap

`createWalletApiInjection` accepts `getRegistrationGrant`, whose whole purpose is to let a client
backend mint a scoped grant authorising a registration. **`wallet-web` never passes it** — the only
references in the repo are its own definition and a unit test. Consequently:

- the shipped wallet UI can only register users when `OPEN_REGISTRATION=true`;
- our customer template `deploy/docker-compose.reference.yml:54` sets `OPEN_REGISTRATION=false`.

**The documented production configuration cannot register a user with the shipped UI.** Every compose
file that actually runs the flow (`dev`, `e2e`, `sepolia`) sets it to `true`. This must be fixed
before KEO — and it is precisely the seam that lets KEO's backend decide who is allowed a wallet.

### The `rpId` plumbing must be fixed for BYO wallet UI to be correct

`POST /v1/webauthn/options` returns `rpId` (`src/routes/webauthn.ts`), but
`createWalletApiInjection` types the response as `{ kind, challenge, credentialIds }` — `rpId` is
never read. Neither `createWebAuthnCredential` (`packages/wallet-core/src/provider.ts`) nor the
`publicKey` options in `get-credential.ts` set `rp` / `rpId` at all, so the browser defaults to the
current hostname. And `wallet-web`'s `config.ts` declares an `rpId` field nothing else in `src/`
consumes — `GIANO_RP_ID` is threaded through the entrypoint, the config template and the Helm chart
to populate a value that is never read.

Today this accidentally works, because the wallet is always served from a host equal to or under
`RP_ID`. It breaks the moment a client wants `RP_ID = keo.com` while serving from `wallet.keo.com`
and expects credentials usable from `app.keo.com` too. Threading the server's `rpId` into
`createWebAuthnCredential({ rp })` and `navigator.credentials.get({ publicKey: { rpId } })`:

- makes the registrable-parent RP ID discussed in [§5.3](#53-every-tenant-owns-its-wallet-origin--and-that-removes-the-one-way-door) possible at all;
- **activates Related Origin Requests**, which is fully implemented (`GET /.well-known/webauthn`, the
  `ror_origins` table, admin CRUD, nginx routing) but unreachable, because the browser only fetches
  that document when a client requests an `rp.id` differing from its own origin.

This is a P1 deliverable, not a P4 nice-to-have.

---

## 7. The three-tier integration contract

Rather than one vague promise of "bring your own UI", three clearly-bounded tiers with different
costs, different support burdens, and different security ownership.

**The client's own wallet origin is now common to Tiers A and B** ([§5.3](#53-every-tenant-owns-its-wallet-origin--and-that-removes-the-one-way-door)).
The tiers differ only in **who writes the SPA served there** — which is what makes A → B a migration
rather than a fork.

| | **Tier A — Our UI, their origin** | **Tier B — Their UI, their origin** | **Tier C — Self-host everything** |
|---|---|---|---|
| Wallet origin | **Theirs** (`wallet.keo.com`) | **Theirs** (`wallet.keo.com`) | Theirs |
| Who wrote the SPA | Us — they brand it | **Them, against our SDK** | Either |
| Backend + DB | Ours | **Ours** | Theirs |
| Who owns the trust boundary | Us (they own DNS + TLS) | **Shared** | Them |
| Security fixes | Automatic — we redeploy | They must upgrade the SDK | They must upgrade everything |
| Effort for them | DNS + TLS + branding config | Above, plus an SPA and conformance | A full deployment |
| **Migration path** | → **B with zero re-registration** | — | — |
| **KEO** | — | **This one** | — |

### Tier A — Our UI, their origin

The client provides `wallet.<their-domain>` (DNS + TLS pointing at our edge) and we serve the standard
`giano-wallet-web` build there, branded via the runtime-injected `/config.json`. One image serves every
origin: `docker/entrypoint.sh` `envsubst`s `docker/config.json.template` at container start, so
branding — and the per-origin `RP_ID`, allowed dApp origins and CSP — is deployment configuration, not
a build. Zero client code, zero fork, and every client inherits security fixes when we redeploy.

Because each origin gets its own rendered config, **serving one static build per tenant origin needs no
code change at all**. That is the recommended starting point; see `MULTI-TENANCY-GAPS.md` D2.

Plumbing to finish — it is 90% there:

- `WalletConfig.branding` already carries `{ name: string; logoUrl?: string }`
  (`services/wallet-web/src/config.ts`), but `docker/config.json.template` renders only `name`.
  **`logoUrl` is typed and unreachable** — wire it through.
- Add a small set of CSS custom-property overrides. `src/styles.css` is already built on CSS
  variables with a light/dark `prefers-color-scheme` split, so this is contained: accept a `theme`
  object in `/config.json` and set the variables on `:root` at boot.
- Publish the exact list of brandable tokens as the supported contract.

Tier A remains the **default recommendation** for clients without a strong reason to write their own
wallet UI — it is cheaper for them and far cheaper for us to support, and because they already own the
origin they can move to Tier B later without their users re-registering.

### Tier B — Their UI, their origin *(KEO)*

The client builds and serves its own SPA at `wallet.<their-domain>`, using `giano-wallet-client` +
`giano-wallet-core` + `giano-wallet-transport`, against our `wallet-api` and database. Passkeys bind to
their host — the same host as Tier A, which is why the migration is non-destructive. Requirements:
everything in [§3.3](#33-what-keo-takes-on-by-owning-the-wallet-origin), plus the RP ID sign-off in
[§5.3](#53-every-tenant-owns-its-wallet-origin--and-that-removes-the-one-way-door).

**Because the client's origin becomes part of the trust boundary, Tier B needs a conformance gate,
not just documentation.** Deliverables:

- a written conformance checklist derived from the [§3.3](#33-what-keo-takes-on-by-owning-the-wallet-origin) table;
- the Playwright suite (`e2e/tests/wallet-flow.spec.ts`) made **pointable at an arbitrary wallet
  origin**, so it can be run against `wallet.keo.com` as an acceptance test — it already drives two
  real origins with a CDP virtual authenticator, including the hostile-origin and popup-blocked
  paths;
- a header/CSP check in the same run, since `X-Frame-Options: DENY` and `frame-ancestors 'none'` are
  the controls we can no longer enforce ourselves.

### Tier C — Self-host everything

The existing model, unchanged: `deploy/docker-compose.reference.yml` or `deploy/helm/giano`. Stays
supported; no new work.

### The rule

> Client-specific behaviour lands as **configuration or SDK usage**, never as a fork of our images.
> If a client needs something Tier A cannot express, that is a signal to widen the config contract or
> move them to Tier B — not to branch the image.

---

## 8. Roadmap

Each phase is one shippable slice with a binary exit criterion. **P0–P3 are committed. P4 onward are
conditional on real client demand.**

The critical path changed with the BYO-wallet-UI refinement: **the wallet SDK (P1) now blocks KEO**,
where it was previously a speculative P4.

### P0 — Make the seams real *(prerequisite for everything)*

Closing the gap between what the code supports and what a third party can use.

- **Publish** `giano-connector`, `giano-wallet-core`, `giano-wallet-transport` at `0.1.x`. Resolve
  the registry conflict first: routing the whole `@appliedblockchain` scope to GitHub Packages
  collides with pulling public packages under that scope (see `GAPS-TO-COMPLETION.md` §6).
- **Wire `getRegistrationGrant`** in `wallet-web` so `OPEN_REGISTRATION=false` is usable (S3).
- **Add `getMe()` / `listCredentials()`** to the injection. `views/Settings.tsx` currently raw-
  `fetch`es `/v1/me` and `/v1/me/credentials` with locally re-declared types — the one place a UI is
  coupled to the wire format, and a trap for anyone writing their own. Consider generating types from
  the committed `services/wallet-api/openapi/openapi.json`, which is CI drift-checked but consumed by
  nothing.
- **Fail closed on origins.** `packages/wallet-transport/src/host.ts` returns
  `allowed.length === 0 || allowed.includes(origin)` — an empty allowlist permits any origin — and
  `@fastify/cors` is not registered at all when `CORS_ORIGINS` is empty. Both are tolerable in a
  single-origin dev stack and unacceptable once we host a client-operated origin.
- **Rotate the committed CDP bundler keys** still in git history under `services/custom-example`.

> **Exit:** KEO can `pnpm add` the packages from a clean machine and register a user against a stack
> running `OPEN_REGISTRATION=false`.

### P1 — Ship the wallet SDK *(the new critical path)*

- **Extract and publish `@appliedblockchain/giano-wallet-client`** per [§6 S2](#s2--the-wallet-sdk-is-the-critical-path).
- **Refactor `services/wallet-web` onto it**, so our own UI is the SDK's first consumer.
- **Fix the `rpId` plumbing** end to end — server value → injection → `createWebAuthnCredential({ rp })`
  → `navigator.credentials.get({ publicKey: { rpId } })`.
- **Write the Tier B conformance checklist** and parameterise the Playwright suite by wallet origin.
- Tier A branding completed alongside (`logoUrl` + theme tokens), since it is nearly free and keeps
  Tier A viable for future clients.

> **Exit:** a wallet origin built from the published SDK — not our image — passes the Playwright
> suite against a local stack.

### P2 — KEO pilot on testnet

- Stand up the shared AWS substrate (cost model §2) with **one logical stack for KEO** — topology T1.
- **`RP_ID` decision signed off in writing.** Recommendation: `keo.com`, wallet origin
  `wallet.keo.com`. Irreversible.
- `CORS_ORIGINS` + `EXPECTED_ORIGINS` include `https://wallet.keo.com`; `allowedDappOrigins` includes
  `https://app.keo.com`.
- KEO builds `wallet.keo.com` and its dApp UI. We run the conformance checklist against both.
- `pnpm run doctor chain` as the acceptance gate.

> **Exit:** KEO completes create wallet → connect → sponsored transaction → receipt on Sepolia,
> through **KEO's own wallet origin**, against our hosted backend.

### P3 — Mainnet gate

Ethereum Mainnet with real value is gated on four things, all Tier 1 in `GAPS-TO-COMPLETION.md`.
These have long external lead times — **start procurement during P1.**

- **Independent contract security audit** of Giano's additions to the Coinbase fork (multi-owner, the
  passkey path, `AuthenticatedStaticCaller`, the EntryPoint v0.6→v0.7 migration).
- **Production `VerifyingPaymaster`.** Only `PermissivePaymaster` exists; it sponsors anything from
  anyone and on a live network would be drained immediately.
- **Self-hosted Alto validated on a public network with `--safe-mode true`.** Only ever exercised with
  safe mode off. Drives a hard dependency on a trace-capable RPC provider (`debug_traceCall`).
- **Account recovery.** The contracts support multiple owners; nothing productises adding a second
  device or recovering a lost passkey. Shipping a wallet without recovery ships a way to lose funds.

Note the audit scope now includes the Tier B boundary: a client-operated wallet origin is a new trust
assumption and should be in scope for review.

> **Exit:** audit findings resolved, checklist signed off, contracts deployed to chain 1 and
> registered in `packages/contracts/addresses.ts` (mainnet is not in the registry today).

### P4 — More clients, and/or our own wallet UI — *on demand*

Two independent sub-tracks; do either or both as demand dictates.

- **P4a — more clients on T1.** Templatise onboarding: an IaC module, a runbook, a `giano-doctor`
  acceptance run. Proves the marginal-cost figure in the cost model. *Exit: a new client onboarded in
  under a week with zero code changes.*
- **P4b — multi-RP (topology T2), needed only if two differently-named wallet origins must share one
  backend** — which is now every case beyond the first client, since each owns its origin. **Specified in
  detail in [`docs/MULTI-TENANCY-GAPS.md`](./MULTI-TENANCY-GAPS.md)** (gap inventory, defects C1–C3,
  required decisions, phased breakdown M0–M7). *Exit: two wallet origins with different RP IDs on one
  `wallet-api`, with the full isolation test matrix green — in particular a test proving a credential
  from one tenant cannot authenticate against another.*

**Prefer P4a.** T1 costs ~$29/month per client and no engineering; T2 costs a schema migration and a
new class of security bug. Only do P4b when a shared reference UI is genuinely required.

### P5 — Multi-chain — *on demand*

Per-request chain selection instead of a single `CHAIN_ID` per stack, and a real
`wallet_switchEthereumChain` (currently a placeholder). Cheap for contracts — CREATE2 with the fixed
salt already yields identical addresses on every chain, guarded by `determinism.yml`. Not cheap for
`wallet-api`, whose config is single-valued throughout.

> **Exit:** one stack serves two chains with one passkey per user.

### P6 — Dashboard and full tenancy — *only once there is a product*

Builds on P4b: `tenants` and `api_keys` tables, `users.externalId` scoped per tenant, per-tenant
policy and origins; then the admin dashboard and user management on top.

> **Exit:** a client is onboarded without an engineer touching infrastructure.

### Sequence

```
P0 foundations ──► P1 wallet SDK ──► P2 KEO pilot (T1, testnet) ──► P3 mainnet gate
                                            │
                                            ├──► P4a more clients on T1   ──┐
                                            └──► P4b multi-RP (T2) ─────────┼──► P6 dashboard
                                                 P5 multi-chain ────────────┘
```

---

## 9. How we work

- **One seam per phase.** A phase that opens two seams is two phases.
- **Vertical slices.** Every phase ends with something a user can do end-to-end, not a layer that is
  "ready for integration".
- **Our own UI eats the SDK.** `services/wallet-web` must be a consumer of `giano-wallet-client`, not
  a parallel implementation. This is the only reliable defence against the SDK rotting.
- **Configuration or SDK usage over forks.** See the rule in [§7](#7-the-three-tier-integration-contract).
- **Lockstep upgrades.** Per `COMPATIBILITY.md`: `wallet-api` (+ migrations) → wallet origin → dApp
  SDK. Tier B makes this harder — we no longer control when a client's wallet origin upgrades — so
  the handshake version check and a stated support window become contractual, not advisory.
- **A changeset per user-visible change.** The moment packages are public, undocumented breaking
  changes cost us client trust.
- **`giano-doctor` is the acceptance gate.** It probes the chain live and exits non-zero on failure,
  so it belongs in the onboarding runbook and in CI.
- **Every client-facing promise gets a test.** The Playwright suite already covers two real origins
  with a virtual authenticator; each new seam extends it rather than accreting manual QA.

---

## 10. Risk register

| Risk | Impact | Mitigation | Phase |
|---|---|---|---|
| **Client-operated wallet origin weakens the trust boundary** | KEO omits `X-Frame-Options`/CSP or shows no dApp origin on consent → phishing or clickjacking against wallets on our backend | Conformance checklist + parameterised Playwright + header checks as an acceptance gate; include Tier B in audit scope | **P1/P2** |
| **Wallet SDK not packaged** | KEO cannot start; blocks the entire milestone | P1 is the critical path; our own UI must consume it | **P1** |
| **`RP_ID` chosen wrongly / one-way door** | Irreversible; every user re-registers; credentials never portable between wallet origins | Written sign-off before first deploy; recommend the registrable parent (`keo.com`) | **P2** |
| **Shared backend + multiple RP IDs attempted without S5** | `wallet-api` refuses to boot; if forced, cross-tenant credential confusion | T1 for KEO; T2 only as P4b with RP-scoped credentials and a negative test | **P4b** |
| **No security audit** | Cannot hold real value; single largest blocker | Commission during P1; amortise over 24 months | P3 |
| **`PermissivePaymaster` on a live chain** | Fee budget drained by anyone, immediately | Build `VerifyingPaymaster`; never deploy the testing paymaster outside a devnet; scope `USEROP_ALLOWED_PAYMASTERS` | P3 |
| **Alto unproven in safe mode on a public chain** | Userops silently fail in production | Validate on Sepolia during P2 under `--safe-mode true` | P3 |
| **Trace-capable RPC dependency** | Recurring cost that can exceed all compute; vendor outage stops transactions | Price explicitly (cost model §4); documented fallback provider | P2 |
| **No account recovery** | A lost device means lost funds — reputational, not just technical | Design during P2, ship in P3 | P3 |
| **Origin allowlists fail open** | `TransportHost` empty list allows any origin; CORS unregistered when unset. Far more dangerous with a client-operated origin | Fail closed | **P0** |
| **Committed CDP bundler keys in git history** | Live credentials under `services/custom-example` | Rotate before anything is published | **P0** |
| **Packages unpublished** | KEO blocked on day one | First task of P0 | **P0** |
| **Client upgrade drift under Tier B** | A stale client wallet origin runs known-vulnerable SDK code against our backend | Handshake `sdkVersion` check, minimum-supported-version enforcement in `wallet-api`, stated support window | P2 |
| **Gas cost on Ethereum Mainnet** | A single sponsored transaction can cost more than a day of infrastructure | Pass-through billing with a prepaid deposit; policy caps; cost model §5 | P2 |

---

## A note on Ethereum Mainnet

The first production integration targets Ethereum Mainnet. Two multipliers stack there, both
quantified in [`docs/COST-MODEL.md`](./COST-MODEL.md) §5:

1. **P-256 verification cost.** Giano verifies passkey signatures via the RIP-7212 precompile when
   the chain has one, and falls back to an in-contract FreshCryptoLib implementation when it does not
   — roughly 5k gas versus roughly 330k. Whether Ethereum Mainnet exposes the precompile must be
   **checked live, not assumed**: `pnpm run doctor chain --rpc <mainnet-rpc> --chain-id 1`. Stale
   comments in this repo about Sepolia were already wrong on exactly this point.
2. **L1 gas prices**, orders of magnitude above any L2.

Our recommendation, for the record: **pilot on Sepolia, launch on an L2, and treat Ethereum Mainnet
as a supported target rather than the default.** The gas saving is two to three orders of magnitude
and it decides whether gasless UX is affordable at all. If Mainnet is a firm requirement it is
entirely workable — the cost model prices it — but sponsorship must be a prepaid, capped,
pass-through budget rather than a bundled feature.
