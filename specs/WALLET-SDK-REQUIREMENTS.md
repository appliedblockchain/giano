# Giano wallet SDK — requirements

A Giano **wallet origin** — the trusted popup that runs every passkey ceremony, holds the
wallet-api session, gates consent, and now serves wallet management — is not a screen. It is a
few hundred lines of load-bearing orchestration sitting between a handful of published primitives
and whatever the tenant chooses to render. Today that orchestration exists **twice**: once in
Giano's stock wallet (`services/wallet-web`, React) and once, re-written by hand, in the
bring-your-own-UI reference (`e2e/wallet-byo`, vanilla TypeScript). A tenant building its own wallet
UI has no third option but to write it a third time.

This document specifies a single **wallet SDK** — a framework-agnostic package that packages that
orchestration once, so that Giano's own wallet and a tenant's wallet are the *same logic behind
different pixels*. It is a requirements document, not an implementation plan.

It serves [`BUSINESS-REQUIREMENTS.md`](./BUSINESS-REQUIREMENTS.md) **BR-06** and **BR-19** (an
integrator builds on a supported SDK, not on internal detail) and **BR-18** (a tenant serves its
own branded wallet interface). It is the packaging half of what
[`WALLET-MANAGEMENT-REQUIREMENTS.md`](./WALLET-MANAGEMENT-REQUIREMENTS.md) **WM-60/WM-61** require —
that every capability be reachable by a tenant's own interface — turning "re-implement the reference"
into "depend on a package."

Status: **draft, in review.**

> **Numbering.** Requirements are `WK-nn`, globally unique within this document. They are unrelated
> to the `BR-nn`, `MC-nn`, `R-nn` and `WM-nn` series, which are cited here rather than restated.
> "The kit" throughout means the package this document specifies; its name is provisional
> ([Q1](#7-open-questions)).

---

## Contents

1. [The problem](#1-the-problem)
2. [Goal and scope](#2-goal-and-scope)
3. [Key decisions](#3-key-decisions)
4. [Requirements](#4-requirements)
5. [The load-bearing invariants the kit exists to hold](#5-the-load-bearing-invariants-the-kit-exists-to-hold)
6. [Accepted limitations and roadmap](#6-accepted-limitations-and-roadmap)
7. [Open questions](#7-open-questions)
8. [Glossary](#8-glossary)

---

## 1. The problem

### 1.1 The reusable pieces are primitives, not a wallet

Giano publishes the parts a wallet origin is *built from*:

- `@appliedblockchain/giano-wallet-transport` — the `TransportHost`, the versioned postMessage
  protocol, and chain negotiation.
- `@appliedblockchain/giano-wallet-core` — `createGianoProvider`, the wallet-api injection
  (`createWalletApiInjection`), and the wallet-management primitives (owner-set enumeration,
  fingerprints, the self-call encoders, `createWalletManagementApi`, the deposit ceremony).

What it does **not** publish is the layer that turns those into a working wallet origin: the
per-chain runtime wiring, the transport-host-with-consent glue, the single-slot consent queue, the
sponsorship pre-flight, and the wallet-management flow orchestration. `@appliedblockchain/giano-
connector` looks adjacent but is the **dApp** side — "connect a dApp to a deployed wallet origin" —
and carries none of it.

### 1.2 So the orchestration is written twice, by design

The stock wallet and the BYO reference duplicate the same logic:

| Layer | Stock (`services/wallet-web`) | BYO reference (`e2e/wallet-byo`) |
|---|---|---|
| Per-chain runtime: bundler client, fee-before-paymaster ordering, paymaster hooks, provider, sponsorship pre-flight | `src/wallet.ts` | `src/runtime.ts` — *"Vanilla-TS port of wallet.ts — the whole SDK surface a BYO UI needs"* |
| Transport host + consent gate + `giano_openWalletManagement` | `src/host.ts` | `src/main.ts` |
| Single-slot consent store | `src/requests.ts` | `src/requests.ts` — *"Verbatim copy"* |
| Management flow (open slot → deposit → fingerprint compare → per-chain apply → bind) | `src/views/manage/*` | `src/manage.ts` |

The duplication is not an accident: `WALLET-MANAGEMENT-REQUIREMENTS.md` **D11 / WM-61** deliberately
had the BYO reference *re-implement* to prove the raw API is sufficient — *"an API that only the
stock interface can drive is not a supported API."* That is a good test property, and this document
must not throw it away ([D5](#d5--sufficiency-is-preserved-by-construction-not-by-a-retained-raw-consumer)).
But it is the wrong default for a real customer, who wants to **restyle**, not re-derive.

### 1.3 What re-deriving actually costs a customer

The duplicated layer is exactly where the non-obvious, correctness-critical decisions live — the
ones a customer re-implementing from the primitives is most likely to get subtly wrong, and whose
failure modes are the least legible:

- **Fees must be resolved before the paymaster hooks run.** A validating paymaster signs the
  operation's gas fees; resolving fees afterwards issues an authorisation over one set of fees and
  submits under another, which fails on-chain as `AA34` long after anything can explain why.
- **Sponsorship pre-flight must precede consent and therefore the passkey prompt.** Offering an
  approve button for an operation that will be refused walks the user through a ceremony that could
  never have succeeded (WM-68).
- **In wallet management, the chain is written before the registry** (WM-15), the owner set is read
  from the chain and joined by owner bytes (WM-01/WM-02), and the cross-device fingerprint is
  recomputed from the key as received (WM-20).
- **Credentials must be discoverable** (`residentKey: 'required'`), because silent account restore
  and discoverable sign-in depend on it.
- **One chain per session, negotiated in the handshake** (MC-01…MC-06), and one shared injection
  across per-chain runtimes so the session is not duplicated (MC-76).

None of these is visible in the API's shape. All of them are currently guarded only by "read the
other implementation carefully."

---

## 2. Goal and scope

### 2.1 Goal

One package that both Giano's stock wallet and a bring-your-own-UI tenant depend on to build a
Giano wallet origin. It packages every decision *between* the published primitives and the rendered
view — and stops exactly there, so the view, the branding, and the framework stay the tenant's.
Giano's wallet and a tenant's wallet become the same logic behind different pixels.

### 2.2 In scope for v1

- A **runtime layer**: `createWalletRuntimes(config)` — validated config in, per-chain runtimes out
  (bundler, fee estimation, paymaster hooks, provider, sponsorship pre-flight), memoised, one shared
  injection.
- A **host layer**: `createWalletHost({ runtimes, … })` — the `TransportHost` wired with a consent
  gate and the management method, **headless**: it calls back to the UI for consent and never owns a
  pixel.
- A **consent model**: the single-slot request queue, as data the UI subscribes to.
- A **wallet-management controller**: a headless state machine for viewing, naming, adding (this
  device, second device, externally-owned account) and removing owners — emitting state, accepting
  user actions, holding the WM ordering invariants once.
- **Config loading and validation** with fatal, field-named errors.
- Optional **thin framework adapters** (a React-hooks entry point) that expose the headless core as
  idiomatic state — additive, never required.
- **Migration** of both `services/wallet-web` and `e2e/wallet-byo` onto the kit, which is what
  proves it is sufficient for two visibly different UIs.
- The kit's surface **documented** in the tenant integration guide (extends WM-62).

### 2.3 Out of scope for v1

Deferred, with reasoning in [§6](#6-accepted-limitations-and-roadmap):

- **Any rendering.** No components, no DOM, no CSS ship in the kit ([D1](#d1--the-kit-is-headless-logic-only-no-views)).
- **A hosted or drop-in wallet UI.** The kit is not a wallet you deploy; it is what you build one
  with. A reference UI is the stock wallet-web, which is not a kit deliverable.
- **Non-EVM chain families**, which the provider does not yet serve.
- **Any change to the transport protocol or the wallet-api surface.** The kit is a client of both as
  they stand.
- **Bundling a framework.** Beyond a React adapter behind its own entry point, no framework is a
  dependency.

### 2.4 What this must not change

The kit is a **repackaging**, not a new capability and not a new authority. It introduces no
endpoint, no privilege, and no server-side power over any wallet (BR-02, BR-03); it changes no
signature the wallet already produces; and it is built on the same published primitives and
documented wallet-api a tenant could call directly. Any version that becomes a *privileged* path —
something the stock wallet can do that a tenant on the raw API cannot — is wrong regardless of
convenience ([D5](#d5--sufficiency-is-preserved-by-construction-not-by-a-retained-raw-consumer)).

---

## 3. Key decisions

### D1 — The kit is headless: logic only, no views

The kit owns the orchestration and owns no pixel. It exposes **state and actions**; the tenant
renders. Consent is requested through a callback the host UI supplies, never through a component the
kit draws.

*Rejected:* shipping a themeable component library. Themeable is not the same as *the tenant's own*,
BR-04/BR-18 want the latter, and a component library drags in a framework and a styling system that
become everyone's whether they wanted them or not.

*Consequence:* the kit cannot be *seen* working on its own; it is proven only through a UI that
consumes it, which is why migrating both wallet-web and wallet-byo onto it is a v1 deliverable
(WK-30).

### D2 — Framework-agnostic core, optional thin adapters

The core is plain TypeScript with no framework dependency, so a vanilla-DOM tenant and a React
tenant use the same core. A React-hooks adapter MAY ship behind its own entry point, adding nothing
the core cannot do — it only wraps the core's subscriptions as idiomatic hooks.

*Rejected:* a React-first core with a "vanilla escape hatch". The BYO reference is framework-free on
purpose (it proves the boundary is a real API, not React state), and a React-first core would make
the framework-free path the second-class one.

### D3 — Built on the published primitives, not around them

The kit depends on `giano-wallet-core` and `giano-wallet-transport` and the documented wallet-api,
exactly as a tenant would. It adds no import a tenant lacks and reaches into no internal path.

*Consequence:* the kit is itself evidence the primitives are sufficient — it is a worked example
that happens to be shippable.

### D4 — Every Giano-built wallet UI uses the kit

There is no wallet UI Giano ships that is deliberately kept off the kit. The stock wallet
(`services/wallet-web`) and the bring-your-own-UI reference (`e2e/wallet-byo`) both build on it, and
any future Giano-built wallet UI does too. The kit is not a stock-only convenience with the
reference re-implementing around it — it is the one way a Giano wallet origin is built, which is the
whole point: Giano's wallet and a tenant's wallet are the same logic behind different pixels.

*Rejected:* keeping one consumer — the BYO reference — permanently on the raw primitives as a
standing "proof the raw API is sufficient." That buys a test property at the cost of a forever
duplicated implementation and a reference that drifts from how tenants are actually told to build,
which is the opposite of the single-SDK goal. Sufficiency is instead preserved structurally (D5),
not by a retained re-implementation.

*Consequence:* the BYO reference's job changes from "prove the raw API" to "prove the kit drives a
**visibly different** UI" (WK-31) — the same end-to-end coverage, a different thing proven.

### D5 — Sufficiency is preserved by construction, not by a retained raw consumer

Dropping the second implementation (D4) must not quietly drop the property it was defending — that a
tenant *could* build a wallet origin from what Giano publishes. It stays true because the kit **is**
that build: a thin, in-repo layer over the published primitives (`giano-wallet-core`,
`giano-wallet-transport`) and the documented wallet-api, adding no privileged path (D3). A tenant who
wants to build from scratch, or in another language, still can — the documented API (WM-62) is
unchanged and the kit reaches nothing a tenant cannot.

*Rejected:* leaning on documentation alone with nothing exercising the raw endpoints. It is not
needed: the wallet-api's own integration suite drives those endpoints directly, and the kit exercises
them end-to-end through both wallet UIs.

*Consequence:* WM-61's "the raw API is sufficient" property is carried by the wallet-api integration
tests (which call the endpoints directly, WK-29) rather than by a bespoke second wallet UI.

### D6 — The invariants are encoded once, where they cannot be skipped

Every correctness-critical ordering from [§1.3](#13-what-re-deriving-actually-costs-a-customer) lives
inside the kit's runtime and controller, not in guidance a tenant must remember. A tenant using the
kit gets fee-before-paymaster, preflight-before-consent, chain-before-registry, discoverable
credentials and one-chain-per-session **by construction**, not by discipline.

*Consequence:* the kit's own tests, not each tenant's, are what defend these invariants — so they
are worth over-testing there ([§4.7](#47-testing)).

### D7 — Consent is the UI's, surfaced as a promise the kit awaits

The kit requests consent by handing the UI a description and awaiting a resolution; approval and
rejection are the UI's to raise. The kit supplies the single-slot queue and the 4001-on-reject
mapping so those are not re-derived, but it never assumes what a consent screen looks like.

---

## 4. Requirements

### 4.1 Runtime construction

**WK-01** — The kit MUST expose a runtime factory that takes a validated wallet configuration and
returns per-chain runtimes, each carrying that chain's read client, bundler client, fee estimator,
paymaster hooks, Giano provider and sponsorship pre-flight (the surface currently duplicated in
`wallet.ts` and `runtime.ts`).

**WK-02** — Runtimes MUST be resolved lazily and memoised per chain: a session that uses one chain
MUST construct one chain's runtime (MC-44).

**WK-03** — All runtimes MUST share **one** wallet-api injection, so a session is never duplicated
(MC-76). The kit MUST NOT expose a way to construct a runtime with its own injection.

**WK-04** — Fee estimation MUST be resolved before the paymaster hooks run, and the kit MUST NOT
offer a construction order in which it is not. A tenant MUST NOT be able to assemble a runtime that
signs a paymaster authorisation over unset fees.

**WK-05** — The kit MUST support the three sponsorship modes the stock config supports —
service (ERC-7677), permissive test paymaster, and off — with the same fall-through behaviour, and
MUST refuse the permissive test paymaster in a production build unless explicitly opted in.

### 4.2 Configuration

**WK-06** — The kit MUST validate configuration and fail fatally on a bad or incomplete chain
entry, naming the chain and the field (MC-42). It MUST accept both the multi-chain list and the
single-chain shorthand, and MUST reject supplying both.

**WK-07** — Configuration MUST be supplied by the host, not fetched by the kit from a fixed
location: a tenant's deployment decides where its config lives. The kit MAY offer a helper that
loads the stock `/config.json` shape, as a convenience, not a requirement.

### 4.3 The transport host and consent

**WK-08** — The kit MUST expose a host factory that wires a `TransportHost` with the served-chain
list, origin pinning, chain negotiation, and a consent gate — the surface currently duplicated in
`host.ts` and `main.ts`.

**WK-09** — Consent MUST be requested through a host-supplied callback that resolves on approval and
rejects on refusal; the kit MUST map a refusal to EIP-1193 `4001` and MUST NOT render any consent
UI itself (D7).

**WK-10** — The kit MUST provide the single-slot consent model as subscribable state, so a second
request while one is pending is refused rather than queued silently, matching current behaviour.

**WK-11** — The host MUST name the negotiated chain on every consent request (MC-80, MC-81), and
MUST refuse `wallet_switchEthereumChain` / `wallet_addEthereumChain` with the existing typed error
(MC-14).

**WK-12** — On a signing or transaction request landing on a runtime whose in-memory account was
lost (the ephemeral-popup case), the kit MUST attempt a silent account restore before requesting
consent, with no extra passkey prompt — as the stock host does today.

### 4.4 Sponsorship pre-flight

**WK-13** — The kit MUST expose the sponsorship pre-flight as the stock and BYO runtimes do: given a
transaction, it answers `sponsored` / `refused` / `unavailable` / `not-applicable` **before** an
approve button or passkey prompt is offered (WM-68, R-21).

**WK-14** — The pre-flight MUST encode calldata with the account's own encoder, so what the rules
engine decodes is byte-identical to what will be submitted, and MUST be evaluated per chain, never
reused across chains (MC-71).

**WK-15** — A refusal MUST carry the machine-readable reason, so the UI keys its copy off the reason
and never off prose. The kit MUST NOT bundle user-facing copy for refusals; copy is the tenant's
(the stock wallet's copy map stays in wallet-web).

### 4.5 The wallet-management controller

**WK-16** — The kit MUST expose a headless controller for wallet management that drives the whole
of [`WALLET-MANAGEMENT-REQUIREMENTS.md`](./WALLET-MANAGEMENT-REQUIREMENTS.md) §4 — viewing the
owner set, naming, adding on this device, adding from a second device, adding an externally-owned
account, and removal — emitting state and accepting user actions, so the view is pure rendering.

**WK-17** — The controller MUST read the owner set from the chain and reconcile it against the
registry by owner bytes, surfacing divergence, unreadable chains, and rows-without-owners honestly
(WM-01…WM-06). It MUST NOT expose a construction that reports an owner set the chain does not back.

**WK-18** — The controller MUST hold the ordering invariants: the chain is written before the
registry binds (WM-15), the removal index is re-read per chain immediately before use (WM-29), and
the cross-device fingerprint is recomputed from the key as received (WM-20). A tenant using the
controller MUST get these without implementing them.

**WK-19** — The controller MUST NOT expose `removeLastOwner` or any construction that reaches it
(WM-28), and MUST refuse the last-owner removal legibly rather than by a bare revert.

**WK-20** — Passkey creation driven by the controller MUST request a **discoverable** credential
(`residentKey: 'required'`), so a credential it adds is usable by silent restore and discoverable
sign-in.

**WK-21** — Owner changes MUST be applied per served chain with per-chain progress surfaced as state
(WM-42, WM-44), sponsorship pre-flighted before any passkey prompt (WK-13), and every outcome both
emitted as state and written to the browser console (WM D10). The path used (chain-bound today; see
the wallet-management implementation report) MUST be a single point in the kit, so a future switch to
the chain-independent path is one change, not a change in every tenant.

### 4.6 Framework adapters and packaging

**WK-22** — The kit's core MUST have no framework dependency and MUST be usable from plain
TypeScript/DOM, proven by the BYO reference consuming it (WK-31).

**WK-23** — A React adapter MAY be provided under a separate entry point (e.g. `/react`), exposing
the core's subscriptions as hooks and adding no capability the core lacks (D2).

**WK-24** — The kit MUST ship types and MUST NOT export internal paths of `wallet-core` or
`wallet-transport` as its own surface; it re-exports only what a wallet UI needs.

**WK-25** — The kit MUST follow the repository's fixed-version release policy and its
wallet-api/wallet-web/SDK compatibility ordering (COMPATIBILITY.md), and MUST NOT require a
wallet-api newer than the one a tenant runs.

**WK-26** — The kit MUST NOT reach a standard EIP-1193 method or the `giano_`-namespaced transport
convention differently from how the stock wallet does; the management open path stays `giano_`-namespaced (WM-55).

### 4.7 Testing

**WK-27** — The kit's own tests MUST cover each load-bearing invariant of
[§5](#5-the-load-bearing-invariants-the-kit-exists-to-hold) directly — fee-before-paymaster,
preflight-before-consent, chain-before-registry, one-chain-per-session, discoverable credentials —
because these move out of each tenant's tests and into the kit's (D6).

**WK-28** — The management controller MUST be covered by unit tests over its state machine
(transitions, refusals, the last-owner guard, the fingerprint recompute) independent of any view.

**WK-29** — The wallet-api's own integration suite MUST continue to exercise the documented
management endpoints **directly** — not through the kit — so the endpoints stay proven drivable
without it (D5), and so the kit cannot silently acquire a dependency on behaviour the raw API does
not offer.

### 4.8 Migration and parity

**WK-30** — `services/wallet-web` MUST be migrated onto the kit, so Giano's own wallet is the kit's
first consumer and its React views are the kit's first rendering (D4).

**WK-31** — The `e2e/wallet-byo` reference MUST be migrated onto the kit's **core** (framework-free),
and MUST remain covered by the same end-to-end scenarios as the stock wallet — proving the kit drives
a visibly different UI (WM-61), not only Giano's.

**WK-32** — Every capability reachable through the stock wallet MUST remain reachable through a
kit-built tenant wallet, with no Giano-specific privilege (WM-60); the migration MUST NOT introduce
one.

**WK-33** — The kit's surface — the runtime factory, the host factory, the consent model and the
management controller — MUST be documented in the tenant-facing integration guide, extending the
API surface WM-62 already requires there.

---

## 5. The load-bearing invariants the kit exists to hold

These are the decisions a tenant re-deriving from the primitives is most likely to get wrong, and
whose failure is least legible. The kit's value is that it holds them once, by construction (D6).
Each MUST be encoded in the kit and defended by the kit's own tests (WK-27).

| Invariant | Why it is load-bearing | Failure mode if a tenant gets it wrong |
|---|---|---|
| Fees resolved before paymaster hooks | The paymaster signs over the fees | On-chain `AA34`, unexplained, long after submission |
| One `prepareUserOperation`, not estimate-then-prepare, with a paymaster attached | Each call re-runs the hooks and picks a fresh nonce key | Two signed authorisations and two reservations per tx; the tenant's available balance silently halves |
| Sponsorship pre-flight before consent and the passkey prompt | A refusal after consent asks for a ceremony that could never succeed | The user is walked through a passkey prompt that then fails |
| One chain per session, negotiated in the handshake | The chain travels the wire and is enforced end-to-end | A transaction reaches a different chain than the user believes |
| One shared injection across runtimes | The injection holds the session | Duplicating it duplicates (and desynchronises) the session |
| Chain written before registry binds | The chain governs; the registry is a cache | The registry claims an owner the chain does not have |
| Removal index re-read per chain immediately before use | A stale index reverts (`WrongOwnerAtIndex`) | A bare, illegible on-chain revert |
| Fingerprint recomputed from the key as received | The user, not the backend, chooses what is added | The operator can substitute a key; BR-03 falls |
| Discoverable credentials (`residentKey: 'required'`) | Silent restore and discoverable sign-in need them | An added credential that later cannot be found to sign in |

---

## 6. Accepted limitations and roadmap

### 6.1 Accepted in v1

**The kit cannot be seen on its own.** It is proven only through a consuming UI (D1); "does the kit
work" is answered by wallet-web and wallet-byo, not by the kit in isolation.

**No wallet UI is kept off the kit.** The stock wallet and the BYO reference both build on it (D4);
the raw-API guarantee is carried by the wallet-api integration suite driving the endpoints directly
(WK-29), not by a retained second wallet implementation. This removes the duplication that exists
today rather than relocating it.

**Copy and views stay the tenant's.** The kit ships no user-facing strings and no components; a
tenant that wants Giano's exact wording and look copies them from wallet-web, which is not a kit
deliverable.

**One framework adapter to start.** Only a React adapter is planned (D2); a Vue/Svelte tenant uses
the framework-free core until an adapter for it exists.

### 6.2 Roadmap

1. **The React adapter**, once the core is stable and wallet-web has migrated onto the core.
2. **Adapters for other frameworks**, driven by tenant demand.
3. **A hosted reference UI** a tenant can fork, distinct from the kit — the kit is what it is built
   with, not the thing itself.
4. **The chain-independent owner-change path**, folded in at the single point WK-21 requires, once
   the paymaster can sponsor a chain-independent operation (the deferred multichain work the
   wallet-management implementation report records).

---

## 7. Open questions

**Q1 — What is the package called, and where does it live?** `@appliedblockchain/giano-wallet-kit`
is the working name. Alternatives on the table: `giano-wallet-host` (names what it wires),
`giano-wallet-ui-core`. It publishes to GitHub Packages alongside the others. **Needs a naming
decision.**

**Q2 — Is there one SDK per side, or one umbrella?** The kit is the **wallet-origin** side; the
existing `giano-connector` is the **dApp** side, and the dApp demos (`services/custom-example`,
`e2e/dapp`) build on the connector. Every UI Giano ships now sits on a shared SDK — a wallet UI on
the kit, a dApp on the connector — with nothing re-implemented by hand. Whether the two are left as
two focused packages (recommended: they solve different problems and a dApp must not be able to
import wallet-origin trust code) or presented under one documentation umbrella is a packaging and
docs call, not a code-sharing one.

**Q3 — Is the management controller one controller or several?** A single controller for all of
view/add/remove keeps one state machine; splitting per flow (add-device, add-address, remove) keeps
each smaller. The React views are already split per flow, which argues for per-flow controllers
with a shared owner-set reader.

**Q4 — How much of the stock config loader belongs in the kit?** WK-07 makes config the host's to
supply, but the stock `/config.json` shape and its validation are genuinely reusable. Whether the
loader ships in the kit (as a helper) or stays in wallet-web is a boundary call.

**Q5 — Does the kit own the ephemeral-popup lifecycle, or only the restore?** WK-12 requires the
silent restore; whether the kit also owns *when the popup closes itself* (currently the dApp-side
connector's `dismissPopup`) touches the transport client, which is the dApp side — likely out, but
worth stating.

---

## 8. Glossary

| Term | Meaning |
|---|---|
| **The kit** | The package this document specifies: the framework-agnostic orchestration a Giano wallet origin is built from. Provisional name `@appliedblockchain/giano-wallet-kit` |
| **Wallet origin** | The trusted popup that runs passkey ceremonies, holds the wallet-api session, gates consent, and serves wallet management. Giano's is `wallet-web`; a tenant's is its own |
| **Runtime** | The per-chain unit the kit builds: read client, bundler, fee estimator, paymaster hooks, provider and sponsorship pre-flight for one served chain |
| **Host** | The `TransportHost` wired with consent gating and the management method — the kit's transport-facing half |
| **Headless** | Owning logic and state but no rendering: the kit emits state and actions; the tenant draws the pixels |
| **Primitives** | The lower-level published packages the kit is built on: `giano-wallet-core` and `giano-wallet-transport` |
| **Bring-your-own UI** | A tenant serving its own wallet interface (BR-18). With the kit, it depends on a package rather than re-implementing the reference |
| **Raw-API sufficiency** | The property (WM-61) that Giano's wallet API is drivable from scratch, without the stock interface or the kit — preserved by construction (the kit is a published-only layer, D5) and kept tested by the wallet-api integration suite (WK-29) |

---

## Related documents

- [`specs/WALLET-MANAGEMENT-REQUIREMENTS.md`](./WALLET-MANAGEMENT-REQUIREMENTS.md) — D11/WM-60/WM-61,
  which this packages; the management controller (§4.5) drives its §4
- [`specs/WALLET-MANAGEMENT-IMPLEMENTATION-REPORT.md`](./WALLET-MANAGEMENT-IMPLEMENTATION-REPORT.md) —
  the chain-bound-vs-replayable owner-change path WK-21 isolates to a single point
- [`specs/MULTICHAIN_REQUIREMENTS.md`](./MULTICHAIN_REQUIREMENTS.md) — the per-chain runtime, chain
  negotiation and one-chain-per-session invariants the kit holds (MC-01…MC-06, MC-43, MC-44, MC-71,
  MC-76, MC-80, MC-81)
- [`specs/PAYMASTER-REQUIREMENTS.md`](./PAYMASTER-REQUIREMENTS.md) — the sponsorship pre-flight and
  platform wallet-management rule the runtime surfaces (R-05, R-21, R-65)
- [`specs/INTEGRATION.md`](./INTEGRATION.md) — must gain the kit's surface alongside the WM-62 API
  surface
- [`specs/ARCHITECTURE.md`](./ARCHITECTURE.md) — the wallet origin and transport boundary the kit
  sits inside
