# Giano multi-chain — requirements

Giano submits every transaction to one blockchain, fixed at deployment time. This work makes a
single Giano deployment serve **several chains**, with the **dApp choosing the chain** through the
SDK.

The chain is chosen once, when the dApp constructs the SDK, and is then fixed for the life of that
provider instance. A user keeps **one passkey**, and that passkey controls **the same wallet address
on every chain** — that address identity is a hard requirement of this work, not an incidental
property, and most of what follows exists to make it structurally true rather than accidentally
true.

This document states *what* the system must do and *why* the main decisions were made. It contains
no implementation detail and no code.

Status: **requirements, agreed.** All thirteen questions in [§7](#7-open-questions) have been
answered and the answers are recorded there in place, with the requirements each one settled.

> **Numbering.** Requirements are `MC-nn` and are globally unique. Decisions are `D1`…`Dn` and are
> **local to this document** — [`PAYMASTER-REQUIREMENTS.md`](./PAYMASTER-REQUIREMENTS.md) has its own
> `D1`…`D16` and its own `R-nn`, and the two sets are unrelated.

---

## Contents

1. [The problem](#1-the-problem)
2. [Goal and scope](#2-goal-and-scope)
3. [Key decisions](#3-key-decisions)
4. [Requirements](#4-requirements)
5. [Security posture](#5-security-posture)
6. [Accepted limitations and roadmap](#6-accepted-limitations-and-roadmap)
7. [Open questions](#7-open-questions)
8. [Glossary](#8-glossary)

---

## 1. The problem

A Giano deployment is pinned to one chain by scalar configuration — one chain id, one RPC endpoint,
one bundler endpoint — and every user of that deployment transacts there and nowhere else. Three
distinct problems follow, and only the third is the one usually asked about.

### 1.1 The dApp cannot say which chain it wants, and cannot detect getting the wrong one

The dApp already declares a chain when it constructs the SDK, and uses it to answer reads locally.
But the popup handshake between the dApp and the wallet origin **carries no chain information at
all**. The wallet origin decides the chain unilaterally, from its own configuration, and the dApp
has no way to state a preference and no way to discover a disagreement.

So a dApp built for one chain, pointed at a wallet origin configured for another, does not fail. It
transacts on the wallet origin's chain, silently, while the dApp's own read path reports balances
and state from the chain it thinks it is on. The consent screen shows the user nothing that would
reveal it, because it does not display a chain either.

**This is a correctness defect today, with one chain configured.** It is not a multi-chain problem;
multi-chain merely makes it constant rather than occasional. Closing it is the first thing this work
must do, and it would be worth doing even if nothing else here were built.

### 1.2 Serving a second chain today means fragmenting the user's identity

The only way to serve a second chain now is to stand up a second deployment. A second deployment
means a second wallet origin, and a wallet origin's host **is** its WebAuthn relying party — the
property the browser itself enforces, and which Giano treats as immutable once a tenant's first
passkey exists.

A second origin therefore means a second passkey. The user registers again, holds two credentials,
and controls two unrelated wallets. "Your wallet on Base" and "your wallet on Optimism" become
different wallets with different addresses and different funds. No amount of interface work hides
that, because the constraint is in the browser, not in Giano.

The whole value of a passkey wallet is that the credential *is* the identity. A design in which the
identity is per chain gives that up.

### 1.3 The stack is unevenly ready, so the cost is concentrated rather than diffuse

Giano is not uniformly single-chain, and knowing which layers are already prepared is what makes
this work estimable:

- **The contracts and the address registry are already multi-chain.** The registry is keyed by chain
  id, the factory produces an address that does not depend on chain id, and the account contract
  already has a mechanism for replaying owner-set changes onto every chain.
- **The gas-sponsorship layer is already chain-keyed throughout.** Every sponsorship table carries a
  chain id — most in the primary key — and every sponsorship service already takes the chain as a
  parameter. It is simply handed the same constant everywhere.
- **The wallet-api process, the wallet origin's runtime, the popup protocol and the SDK are
  genuinely single-chain**, and this is where the work is.

The consequence is that the request as usually stated — "let the SDK pick the chain" — is the
*smallest* part of the job. The wire change is a handful of fields. The substance is making one
backend serve N chains without ever losing track of which chain a given operation is for, and
holding the address-identity guarantee while doing it.

---

## 2. Goal and scope

### 2.1 Goal

**One passkey. One wallet address. One wallet origin. Several chains, chosen by the dApp.**

A user registers a single passkey against a single wallet origin and thereby controls a single smart
account address. A dApp names the chain it wants when it constructs the SDK. The wallet origin either
serves that chain or refuses explicitly, and the user is told on every consent screen which chain
they are approving. Funds sent to the user's address on any served chain reach the same wallet.

### 2.2 In scope for v1

- A dApp declaring its chain to the wallet origin, and the wallet origin accepting or **explicitly
  refusing** it.
- One wallet origin serving several chains.
- One wallet-api process serving several chains, with a closed, explicitly configured list of them.
- The **same smart account address on every served chain for the same passkey**, guaranteed by
  construction and verified rather than assumed.
- Keeping a passkey's owner set consistent across chains as owners are added and removed.
- Gas sponsorship on each served chain, with per-chain tenant configuration, balances and funding.
- Chain identity on every consent screen, and in the relay audit trail.
- Per-chain health, metrics and operational verification.
- **Two deployment profiles from one set of artefacts**: on-premises, which serves one chain, and
  standalone, which serves several. The chain list is configuration in both.
- A **two-chain end-to-end stack** as the default local and CI environment, with cross-chain
  coverage in the test suite.
- **Cross-chain submission in both demonstration applications** — the barebones Playwright fixture
  and the example app — so the behaviour is exercised and visible.

### 2.3 Out of scope for v1

Deliberately deferred, with reasoning in [§6](#6-accepted-limitations-and-roadmap):

- **Mid-session chain switching.** `wallet_switchEthereumChain` stays unimplemented, and must be
  refused explicitly rather than ignored (MC-14). A dApp that wants a different chain constructs a
  new provider.
- **Concurrent multi-chain in one session.** A provider instance addresses exactly one chain, so a
  dApp cannot submit to two chains at once from one instance.
- **Chain abstraction.** No bridging, no cross-chain intents, no unified balance, no automatic chain
  routing. The user's funds remain per chain.
- **Non-EVM chains.**
- **Removing a chain** from a live deployment ([Q11](#7-open-questions)).
- **Pooled cross-chain gas balances.** Tenants fund per chain, as they do now.

### 2.4 Two profiles: on-premises is single-chain, standalone is multi-chain

Giano is deployed in two shapes, and the number of chains is the main thing that differs between
them.

**On-premises.** Giano runs inside a client's own infrastructure. These deployments will, in almost
every case, serve exactly **one** chain — the client's own network, or the one public chain their
product uses. They are also the deployments with the least appetite for operational surface: every
additional chain is another endpoint to run, another submission account to fund, and another thing
to monitor, for no benefit if only one chain is used.

**Standalone.** The deployment Giano operates, serving many tenants, is where several chains are
actually wanted, and where a tenant may reasonably want its users on more than one.

**Both run the same artefacts.** The profile is configuration, not a build, not a flag, and not a
code path (D13). One chain is the degenerate case of N, not a separate mode — but it is the *common*
case, and it must stay as simple as it is today.

Concretely: a single-chain deployment must remain configurable exactly as it is now, must require no
knowledge of the multi-chain configuration shape, and must acquire no per-chain ceremony in its
requests, its consent screens or its operations beyond naming the one chain it serves. If a
multi-chain feature would put a chain picker, a chain column or a per-chain step in front of an
on-premises operator or their users, it must disappear when one chain is served (MC-89).

---

## 3. Key decisions

Twelve decisions shape everything else. Each records what was chosen, what was rejected, and — where
it matters — the consequence that has to be lived with.

### D1 — The chain is fixed for the life of an SDK instance

A dApp names its chain when it constructs the provider. That chain does not change afterwards. To
address a different chain, the dApp constructs another provider.

*Rejected: a mutable current chain driven by `wallet_switchEthereumChain`.* It is the standard
mechanism, and standard dApp tooling knows how to drive it, so it is the natural v2
([§6.2](#62-roadmap)). It is not v1 because the chain would become mutable state living across an
ephemeral popup boundary, coupled to a cached session, a cached authenticated-read signature, an
in-memory account object and a sponsorship pre-flight, each of which would need coherent
invalidation on every switch. That is where the defects would be, and none of it is needed to make a
dApp able to choose its chain.

*Rejected for v1: a chain argument on every call.* It is the only shape that supports addressing two
chains concurrently, and it is additive on top of everything here, so it stays available as a later
extension. It is not standard, so no existing dApp tooling can drive it.

*Consequence:* dApp interfaces that offer a chain picker must rebuild their provider and reconnect
when the user changes chain, which costs a popup. Standard wallet tooling's chain-switching controls
will not work, and must fail visibly rather than appear to succeed (MC-14, MC-15).

### D2 — The dApp declares the chain; the wallet origin decides whether it serves it

The dApp states the chain it wants during the popup handshake. The wallet origin holds a closed list
of chains it serves, and either grants the requested one or refuses the connection outright, naming
what it does serve.

The dApp's declaration is a **request, never an instruction**. Nothing a caller sends can cause the
wallet origin or the backend to act on a chain that was not deliberately configured.

*Rejected: the wallet origin picking silently, as it does today.* That is the defect in
[§1.1](#11-the-dapp-cannot-say-which-chain-it-wants-and-cannot-detect-getting-the-wrong-one).

*Rejected: the dApp supplying an RPC endpoint or contract addresses for its chosen chain.* The whole
point of the wallet origin is that it is the trust boundary; letting the dApp name where transactions
go would dissolve it.

*Consequence:* a mismatch becomes a visible connection failure rather than an invisible wrong-chain
transaction. This will break integrations that are currently mismatched and working by accident.
That is the intended outcome, and it needs to be called out in release notes.

### D3 — One wallet-api serves every chain of a deployment

A single wallet-api process, with a single database, serves all of a deployment's chains, holding one
set of per-chain services rather than one process per chain.

*Rejected: one wallet-api per chain, sharing a database, fronted by one wallet origin.* This is a
genuine alternative and it is cheaper than it sounds — the schema is already chain-keyed and it keeps
one chain's failure from touching another's. It is recorded as [Q3](#7-open-questions) rather than
dismissed. It was not chosen because it multiplies deployment units, and per-chain failure isolation
is achievable inside one process through per-chain health reporting (MC-38, MC-39).

*Consequence:* one process now fails for several chains at once. Per-chain health and per-chain
degradation are therefore requirements, not niceties: one unreachable RPC endpoint must not take the
other chains down or report the whole service unhealthy.

### D4 — The wallet address is identical on every chain, and that is enforced, not hoped for

The same passkey resolves to the same smart account address on every chain a deployment serves. This
is the central product property of this work.

It is achievable because the account address is a deterministic function of the **factory address**,
the **implementation address**, the **owner set** and the **account nonce** — and of nothing else. The
chain id does not enter the derivation. So the address is identical on any two chains where the
factory and implementation sit at the same addresses.

That is a real precondition, not a given. It requires the same deterministic-deployment mechanism at
the same address on each chain, the same fixed salt, and byte-identical compiled contracts — which in
turn requires identical compiler version, optimiser settings and metadata. It already holds between
the two Base chains in the registry. It **does not** currently hold for every registered chain: one
chain carries a divergent factory address, evidently from a deployment made against different
sources or compiler settings ([Q1](#7-open-questions)).

The decision is therefore to make address identity a **precondition for a chain being served at
all**, checked at configuration load and refused loudly. A chain that cannot offer the canonical
factory is not a chain this deployment can serve.

*Rejected: per-chain wallet addresses.* Technically simpler — it needs only a table mapping a
credential to an address per chain — and it is what happens by default if the invariant is left
unenforced. It is rejected because it destroys the product: the user has one credential but several
wallets, funds sent to "their address" arrive somewhere that depends on the chain, and every
address-bearing surface in the system has to become chain-qualified.

*Consequence:* adding a chain acquires a hard prerequisite. A chain whose factory cannot be placed at
the canonical address cannot join, and that will occasionally be an external constraint rather than
something Giano can fix. The failure must be at configuration time with an explanation, never at a
user's first transaction.

*Consequence:* the storage of one address per credential becomes load-bearing. Keeping a single
address column is not merely "no migration needed" — it is the schema refusing to represent a
violation, so a broken invariant cannot be silently absorbed (MC-24).

### D5 — Owner sets are kept identical across chains by replaying owner-management operations

One address on many chains only behaves like one wallet if the **owner set** is the same on all of
them. Otherwise a passkey added while connected to one chain cannot sign on any other, and the user
discovers this at the worst possible moment — on a chain where they have funds and no working
credential.

The account contract already provides the mechanism: a reserved nonce key under which a small,
fixed set of operations — adding an owner, removing an owner, upgrading the account — may be signed
**without** binding the signature to a chain, so one signed operation can be submitted to every
chain.

The decision is to treat this as a first-class feature rather than a latent capability: every
owner-management operation is replayed to every served chain, the user is told that the change
applies everywhere, and divergence between chains is something the system detects and reports rather
than something a user discovers.

*Rejected: letting owner sets diverge and treating each chain independently.* It is what happens with
no work, and it converts the address-identity guarantee into a trap.

*Consequence:* owner changes are **eventually** consistent, not atomically so. Chains confirm at
different speeds and any of them can fail. So an owner change has per-chain state that the interface
must be honest about, and a chain added to a deployment later needs its existing accounts backfilled
([Q5](#7-open-questions)).

*Consequence:* this replay path is, by design, the one signature in the system that crosses chains.
Its bounds are enforced by the contract, which permits only those specific operations, and it must be
covered by tests on every chain rather than trusted.

### D6 — On the backend, the chain travels with each request

Client-side, the chain is fixed per connection (D1). Server-side, it is **per request**: every
operation the backend performs on behalf of a caller carries the chain it is for, and is resolved
against the closed configured list before anything else happens.

This follows the existing convention for the EntryPoint address — server-configured, never taken
from a request — extended to the chain. A caller can *name* a chain; only configuration can *admit*
one.

*Rejected: a per-connection or per-session chain on the backend.* It would put chain selection into
session state, which means a session's chain could be changed, or become stale, or disagree with what
a request is actually asking for. Making it explicit per request means it can always be validated,
and it can always be recorded in the audit trail.

*Consequence:* the operation hash — which commits to the chain and is what makes an operation valid
on one chain only — must be computed from the **resolved and validated** chain, never from an
unchecked value in a request body.

### D7 — Money stays per chain

Gas sponsorship is per chain: one paymaster deployment per chain, separately staked, separately
funded, with its own per-tenant balances and its own fee. A tenant operating on three chains funds
and monitors three balances.

This is already the shape of the sponsorship system and already recorded as an accepted limitation
there. This document does not change it; it makes it visible, because with several chains it stops
being a footnote and becomes something tenants encounter routinely.

*Rejected: a pooled balance spendable on any chain.* It needs bridging, and therefore bridge trust,
settlement risk and liquidity management. That is a separate product.

*Consequence:* a tenant enabling a new chain must fund and configure it explicitly, and sponsorship
must deny by default on any chain the tenant has not configured. "Nothing configured on this chain"
must be a distinct, actionable refusal, not indistinguishable from a rule refusal.

### D8 — A chain is a member of a closed configured list, never a value a caller invents

Both the wallet origin and the backend hold an explicit list of chains they serve. Anything outside
it is refused. There is no path by which a chain id arriving in a request, a handshake or a
configuration file's free text causes the system to reach an endpoint nobody chose.

This follows the pattern the paymaster operator console already uses: it is configured with a list
of deployments it may administer, and the list is the whole of what it can reach, precisely so that
switching between known environments is routine while reaching an unknown one by accident is
impossible.

*Consequence:* a useful secondary property — the set of chain values is bounded and known in advance,
so a chain label can be added to metrics without unbounded cardinality (MC-58).

### D9 — Passkeys, users and sessions remain chain-agnostic

A passkey belongs to a wallet origin, not to a chain. Users, credentials, sessions and WebAuthn
challenges therefore stay chain-agnostic, and nothing in this work adds a chain dimension to them.

Where a chain id has already leaked into credential identity — the WebAuthn user handle records the
chain in force when a credential was created — it must be demoted to informational. Nothing may
enforce it, because a credential created on one chain is valid on every chain.

*Consequence:* one authentication serves every chain. A user does not sign in per chain, and a
session is not chain-scoped.

### D10 — The consent screen names the chain

Consent is the entire purpose of the wallet origin. With several chains served, which chain an
operation targets is material to the decision the user is making, so it appears on every screen where
consent is given — connect, transaction review and message signing — by name rather than by number.

*Consequence:* the wallet origin must be able to render a human-readable name for every chain it
serves, which becomes part of chain configuration rather than something derived.

### D11 — A chain is verified before it is served

Before a deployment serves a chain, that chain is verified: the endpoint really is that chain, the
EntryPoint is present, the factory is present and at the canonical address, and — where sponsorship
is enabled — the paymaster is present, staked and funded. Verification happens at configuration load
and is repeatable on demand as an operational check.

*Rejected: discovering these at first use.* Every one of these failures surfaces to a user mid-flow,
after a passkey prompt, as an unexplained error. They are all knowable at boot.

*Consequence:* a wallet-api will refuse to start with a chain it cannot verify. That is deliberate:
the alternative is starting successfully and failing per user.

### D12 — Naming the chain is mandatory, and the wire change is not additive

The dApp MUST name its chain; a connection that names none is refused. There is no default chain
anywhere in the system.

This costs integrators nothing, which is what makes it affordable: the SDK's `chain` parameter is
already required today, so this work only puts a value the dApp has already supplied onto the wire.
No integration signature changes.

*Rejected: a declared default for dApps that name no chain.* It is the compatibility-friendly
choice, and it was this document's original position. It is rejected because the default *is* the
silent-mismatch path of [§1.1](#11-the-dapp-cannot-say-which-chain-it-wants-and-cannot-detect-getting-the-wrong-one)
— the one thing this work exists to eliminate — and because nothing is in production, so there is no
integration whose compatibility it would protect. A compatibility affordance nobody needs, which
preserves the defect, is not a trade worth making.

*Consequence:* the handshake change is **breaking**, not additive. Since no wallet origin and no
integration are deployed, that costs nothing now and would cost a great deal later — so the wire
format is frozen once the first tenant integrates (MC-148).

*Consequence:* the default chain had two other jobs, and both need new homes. The chain an account is
deployed on at registration becomes the **negotiated** chain, which is more correct anyway — the user
is transacting on that chain. And the reference against which every served chain's factory is
compared becomes an **explicitly frozen canonical constant**, which is stronger than deferring to a
reference chain that could itself be wrong (MC-19).

### D13 — Two deployment profiles, and the chain list is configuration

Giano ships in two shapes, and they differ only in configuration.

An **on-premises** deployment runs inside a client's own infrastructure and serves exactly one chain.
The **standalone** deployment — the one Giano operates — serves several, adopted on client demand
rather than from a fixed list (Q7). Both run the same published artefacts: the same SDK, the same
wallet interface, the same backend, the same operator console.

So the set of chains a deployment serves is **configuration**, applied at deployment time and read at
runtime. It is not a build-time constant, not a compile flag, and not a code branch. There is no
"single-chain build" and no "multi-chain build".

*Rejected: a build flag, or a separate single-chain artefact.* It doubles the release matrix, and it
puts on-premises clients — the deployments with the least tolerance for surprises — on a code path
that is not the one exercised most.

*Rejected: adding chains to a live deployment through an administrative API.* A chain needs verified
contract deployment and funded submission infrastructure before it can be served (MC-25, MC-98,
MC-146), and neither is something an API call can establish. Admitting a chain through an
authorisation check would also make the closed-list guarantee (D8) contingent on that check rather
than on configuration. Adding a chain stays a deployment action.

*Rejected: enforcing single-chain in the on-premises profile.* There is no code path to enforce it
against, and adding one would contradict this decision's own premise. Single-chain on-premises is an
assumption documented and supported, not a restriction imposed (Q12).

*Consequence:* an on-premises operator must never need to understand the multi-chain configuration
shape. The single-chain shape stays a complete configuration in its own right (MC-132), and every
multi-chain surface must reduce to nothing a single-chain operator or user has to act on (MC-89).

*Consequence:* because the chain count is fixed at boot, the closed list (D8), the bounded metric
cardinality (MC-102) and load-time verification (D11) are all achievable. A runtime-mutable chain
list would have cost all three.

---

## 4. Requirements

### 4.1 Chain selection and negotiation

**MC-01** — The SDK MUST let a dApp specify the chain it intends to transact on, and that chain MUST
be fixed for the life of the provider instance.

**MC-02** — The dApp's chain MUST be communicated to the wallet origin when the popup session is
established, before any request is served.

**MC-03** — The wallet origin MUST accept the requested chain only if it appears in its configured
list of served chains, and MUST otherwise refuse to establish the session.

**MC-04** — A refusal under MC-03 MUST be distinguishable by the dApp from every other connection
failure, MUST carry a machine-readable reason, and MUST state which chains the wallet origin does
serve, so an integrator can diagnose it without access to the wallet origin's configuration.

**MC-05** — On accepting a session, the wallet origin MUST tell the dApp which chain was actually
granted, and MUST also declare the full set of chains it serves.

**MC-06** — The SDK MUST verify the granted chain against the chain the dApp asked for, and MUST fail
loudly on any disagreement rather than proceeding. A silent difference between the chain a dApp
believes it is on and the chain its transactions reach MUST NOT be reachable.

**MC-07** — The chain reported to the dApp by the standard chain-id request MUST always be the granted
chain.

**MC-08** — Read requests the SDK answers locally MUST be answered against the granted chain, and
MUST NOT be answerable against any other.

**MC-09** — Cached connection state held by the SDK MUST remain namespaced per wallet origin **and**
per chain, so state for one chain can never answer a request for another.

**MC-10** — A dApp MUST be able to hold two provider instances against the same wallet origin for two
different chains without their sessions, caches or events interfering.

**MC-11** — Naming the chain MUST be mandatory. A connection attempt that names no chain MUST be
refused. There MUST be no default chain, and therefore no configuration in which a dApp's chain is
decided by anything other than the dApp *(decided: Q9)*.

**MC-12** — Naming the chain MUST cost an integrator nothing beyond what the SDK already requires.
The SDK's chain parameter is already mandatory; this work only puts its value on the wire, so no
integration signature changes and there is no shape to recommend over another *(decided: Q9)*.

**MC-13** — The set of served chains MUST be disclosed only in the response to a connection attempt.
There MUST NOT be an unauthenticated endpoint enumerating them: the refusal already carries the list
at the moment an integrator needs it, and an open endpoint would disclose the deployment's shape to
any origin that asks *(decided: Q8)*.

**MC-14** — Requests to switch or add a chain mid-session MUST be refused with an explicit
"unsupported method" error. They MUST NOT be silently ignored, MUST NOT be answered by the read path,
and MUST NOT appear to succeed.

**MC-15** — Any chain-switching capability the SDK's wallet-tooling adapters currently advertise MUST
either be withdrawn or MUST raise a typed, documented error. An adapter MUST NOT advertise a
capability the provider does not implement.

### 4.2 The wallet address is the same on every chain

This section is the core of the work. Every requirement in it is about making address identity
structurally true and detectable when it is not.

**MC-16** — For a given passkey, the smart account address MUST be identical on every chain a
deployment serves.

**MC-17** — Address identity MUST be guaranteed by construction — identical deterministic-deployment
inputs on every chain — and MUST NOT depend on any runtime translation, mapping table or
reconciliation step.

**MC-18** — The account address MUST NOT depend on the chain id. No future change to the account
factory may introduce a chain-dependent term into the address derivation without explicitly retiring
MC-16.

**MC-19** — The deployment MUST declare a single **canonical factory address and canonical
implementation address**, frozen from one build. A chain MUST NOT be admitted to a deployment's
served list unless its factory and implementation are at exactly those addresses. Canonical MUST be
an explicitly stated constant, never "whatever some reference chain happens to have" — otherwise a
fleet can agree unanimously on the wrong build *(decided: Q1, Q9)*.

**MC-20** — The check in MC-19 MUST run when configuration is loaded, MUST be performed against the
chains themselves rather than against a committed file, and MUST prevent the deployment from serving
a chain that fails it. It MUST NOT be deferred to a user's first transaction.

**MC-21** — The account nonce used to derive a user's address MUST be identical on every chain.

**MC-22** — The wallet address for a credential MUST be obtained from a served chain's own factory
rather than derived independently, and the deployment MUST verify at least once that every served
chain's factory returns the same address for the same owner set. This live cross-check MUST be
performed in addition to comparing addresses, because a factory at the right address running
different code would pass an address comparison alone.

**MC-23** — A violation of MC-16 discovered at any point MUST be reported as a fault and MUST NOT be
absorbed by falling back to per-chain addresses.

**MC-24** — Stored credential records MUST continue to hold exactly one wallet address per credential.
This is a deliberate constraint, not merely the absence of a migration: the storage layer MUST be
incapable of representing per-chain addresses, so an invariant violation cannot be silently
accommodated.

**MC-25** — The deterministic-deployment mechanism the deploy pipeline depends on MUST be present at
the expected address on a target chain before contracts are deployed there. The pipeline MUST verify
this and MUST either place it first or fail with a message that says exactly what is missing.

**MC-26** — The compiler identity that produces the canonical addresses — version, optimiser
settings, intermediate-representation setting, target EVM version and metadata configuration — MUST
be pinned, and any change to it MUST be treated as an address-breaking change to the whole
deployment.

**MC-27** — Continuous integration MUST assert that a fresh deployment reproduces the canonical
factory and implementation addresses, and MUST do so for **every** chain in the address registry, not
only one reference chain.

**MC-28** — Registry entries that predate the canonical freeze MUST be removed rather than carried as
legacy. No account exists under them that must be preserved, so retaining them would preserve only
the ambiguity about which build is canonical *(decided: Q1)*.

**MC-29** — Account deployment MUST remain lazy and per chain. Creating a credential MUST NOT require
deploying the account on every served chain, and the first operation on a chain where the account is
not yet deployed MUST deploy it as part of that operation.

**MC-30** — The wallet MUST be able to report, per chain, whether the account is deployed there, and
MUST NOT present "not yet deployed on this chain" as an error.

**MC-31** — Documentation MUST state to tenants and integrators that the address is the same on every
served chain, that funds sent to it on any served chain are controlled by the same passkey, and what
the limits of that guarantee are.

**MC-141** — EntryPoint v0.7 MUST be present at its canonical address on every served chain. The
account implementation hardcodes that address, so a chain carrying a different EntryPoint produces
different account bytecode and therefore different addresses for everything downstream — which is
precisely how the pre-freeze registry came to hold divergent entries. Where a chain lacks it, most
likely a private chain in an on-premises deployment, it MUST be deployed at the canonical address
**before** any Giano contract is deployed there *(decided: Q1, Q12)*.

### 4.3 Owner sets across chains

**MC-32** — Adding or removing an owner MUST be applied to every chain the deployment serves, so that
a passkey usable on one chain is usable on all of them.

**MC-33** — Owner-management operations MUST use the account contract's chain-independent
authorisation path, so a single user authorisation is sufficient for every chain. A user MUST NOT be
asked to authenticate once per chain for one owner change *(decided: Q5 — the replay path is
retained, scoped to wallet management exactly as the contract already scopes it)*.

**MC-34** — The chain-independent authorisation path MUST remain restricted to owner management and
account upgrade. No other operation may be signed without chain binding.

**MC-35** — The user MUST be told, at the point of consent, that an owner change applies to every
chain.

**MC-36** — An owner change MUST NOT be reported to the user as complete while it is outstanding on
any served chain. Per-chain progress MUST be observable, and outstanding applications MUST be
retryable without a further user authorisation where the authorisation is still valid.

**MC-37** — The system MUST be able to detect that an account's owner set differs between served
chains, MUST surface it as an operational alert, and MUST provide a means of reconciling it.

**MC-38** — When a chain is added to a deployment that already has accounts, an account whose owner
set on that chain is behind MUST be reconciled on **first use of that chain**, with a fresh user
authorisation. A stored authorisation MUST NOT be relied on for this: the sponsorship data is inside
the signed operation hash, so an operation signed earlier cannot be re-sponsored later *(decided:
Q5)*.

**MC-142** — The gas-sponsorship authorisation for **wallet-management operations only** MUST be
chain-independent, so that one signed owner-management operation carries byte-identical sponsorship
data on every chain. Without this the operation's hash differs per chain and the user's single
authorisation is valid on one chain only — and it cannot go unsponsored, because Giano accounts hold
no native token by design. Every other class of sponsorship authorisation MUST remain bound to one
chain *(decided: Q5)*.

**MC-143** — One wallet-management authorisation MUST reserve and settle against the tenant's balance
**on each chain it is applied to**. Gas is genuinely spent on every chain, so it MUST be accounted
for on every chain.

**MC-144** — Owner-management records MUST be durable and chain-independent, so that the system can
determine whether any account's owner set is behind on any chain — including a chain that was
removed from the deployment and later re-adopted, which MUST NOT silently resurrect a stale owner set
*(decided: Q5, Q11)*.

### 4.4 The wallet origin

**MC-39** — A wallet origin MUST be able to serve several chains, configured as an explicit list.

**MC-40** — Each configured chain MUST carry everything needed to serve it, including its
human-readable name, its read endpoint, its transaction-submission endpoint, its contract addresses
and its sponsorship settings.

**MC-41** — Chain configuration MUST be supplied at runtime rather than baked into a build, so one
published wallet-origin artefact can serve any deployment.

**MC-42** — A wallet origin MUST refuse to start serving a chain whose configuration is incomplete or
inconsistent, and MUST report which chain and which field.

**MC-43** — The wallet origin MUST hold the per-chain machinery for transaction submission, gas
estimation, sponsorship and account derivation **per chain**, so that no operation for one chain can
be submitted through another chain's endpoint. In particular, submission endpoints and sponsorship
services MUST NOT be shared between chains.

**MC-44** — Per-chain resources MUST be established only for chains actually used within a session,
so that serving many chains does not cost a session that uses one.

**MC-45** — The reference implementation for tenants building their own wallet interface MUST be
updated to the multi-chain configuration shape, since its shape is effectively public API.

### 4.5 The backend chain registry

**MC-46** — The wallet-api MUST accept a list of chains it serves, replacing single-chain scalar
configuration, and MUST validate it before serving traffic.

**MC-47** — Single-chain scalar configuration MUST continue to be accepted as a shorthand for a
one-chain list, so no existing deployment must be reconfigured to upgrade.

**MC-48** — For each configured chain, the wallet-api MUST verify at load time that: the read endpoint
reports the declared chain id; the EntryPoint contract is present at the configured address; the
account factory is present and at the canonical address (MC-19); and, where sponsorship is enabled,
that the paymaster is present.

**MC-49** — The chain-id cross-check in MC-48 MUST be treated as a fatal misconfiguration. An endpoint
that reports a different chain than declared is the exact failure this work exists to eliminate, and
MUST NOT be tolerated or warned past.

**MC-50** — The wallet-api MUST hold separate read, submission and sponsorship resources per chain,
and MUST NOT share any chain-bound resource between chains.

**MC-51** — Every request that acts on a chain MUST identify that chain explicitly, and the backend
MUST resolve it against the configured list before performing any work.

**MC-52** — A request naming a chain the deployment does not serve MUST be refused with a distinct,
machine-readable reason.

**MC-53** — Where a *backend request* omits the chain, the backend MUST apply it to the single
configured chain if exactly one is configured, and MUST refuse as ambiguous if more than one is. It
MUST NOT guess. This is a single-chain affordance for the on-premises profile (MC-88) and is not a
default chain: it never applies when several chains are served, and it has no counterpart in the
connection handshake, where naming the chain is mandatory (MC-11).

**MC-54** — Chain health MUST be reported per chain. One chain being unreachable MUST NOT cause the
deployment to report itself wholly unhealthy, and MUST NOT prevent it serving its other chains.

**MC-55** — A chain that cannot currently be served MUST be refused with a reason that distinguishes
"this deployment does not serve that chain" from "that chain is temporarily unavailable", since the
first is permanent and the second is worth retrying.

**MC-56** — The deployment MUST be able to report which chains it serves, and the health of each, on
its operational endpoints.

**MC-145** — Chain-bound resources MUST be isolated per chain, with per-chain request timeouts and
per-chain connection limits, so that one chain's unresponsive endpoint cannot exhaust the resources
another chain depends on. A single process serving several chains is only safe if this holds
*(decided: Q3)*.

### 4.6 Transaction submission and the audit trail

**MC-57** — The operation hash the backend computes MUST be derived from the resolved, validated chain
and the server-configured EntryPoint for that chain. It MUST NOT be derived from any unvalidated
value supplied by a caller.

**MC-58** — Operations MUST be submitted to the submission endpoint configured for the resolved chain,
and to no other.

**MC-59** — The relay audit trail MUST record the chain for every operation, so that "which chain did
this go to" is answerable directly rather than by inference or by joining through sponsorship
records.

**MC-60** — *(Removed — clean-state assumption, Q4. There are no existing audit records to attribute.
The id is retained because other documents cite it.)*

**MC-61** — Transaction policy allowlists that name addresses — permitted call targets and permitted
paymasters — MUST be stored and resolved **per chain, with no inheritance of any kind**. The same
address denotes different contracts on different chains. The storage MUST be incapable of expressing
a chain-agnostic address allowlist, so a cross-chain allow cannot arise from a resolution rule being
misread *(decided: Q4)*.

**MC-62** — Policy limits that are denominated in gas or in native token MUST be settable per chain,
because fee levels differ between chains by orders of magnitude and one figure cannot be correct for
all of them.

**MC-63** — A tenant's relay rate limit MUST be **shared across all chains**. Adding a chain MUST NOT
increase a tenant's effective ceiling; a tenant needing more capacity raises it through the existing
per-tenant policy override *(decided: Q6)*.

**MC-64** — Where the published API contract changes to carry the chain, the change MUST be reflected
in the generated interface description, and the existing drift check MUST be satisfied rather than
suppressed.

### 4.7 Gas sponsorship across chains

**MC-65** — Sponsorship MUST be available independently on each served chain, and a tenant MUST be
able to sponsor on one chain and not another.

**MC-66** — Tenant sponsorship configuration, balances, reservations, settlements and decisions MUST
be held per tenant **and** per chain.

**MC-67** — A tenant with no sponsorship configuration on a chain MUST sponsor nothing on that chain.
Configuration MUST NOT be inherited from another chain, and enabling a new chain MUST be an explicit
act.

**MC-68** — A refusal because the tenant has no configuration or no funds **on the requested chain**
MUST be distinguishable from a refusal by that tenant's rules, so the operator knows whether to fund
a balance or edit a rule.

**MC-69** — A sponsorship authorisation MUST be valid only on the chain it was issued for, and MUST
be unusable on any other served chain.

**MC-70** — The standard sponsorship service interface already carries the chain per request. The
service MUST route on it, MUST refuse chains it does not serve with a distinct reason, and MUST
validate the EntryPoint per chain.

**MC-71** — The sponsorship pre-flight the wallet performs before offering the user an approve button
MUST be performed for the chain the operation will actually be submitted to, and its answer MUST NOT
be reused across chains.

**MC-72** — One authorisation signing key MAY serve every chain, since authorisations are already
separated by chain and by paymaster instance. A key compromise MUST be containable on all chains at
once.

**MC-73** — Chain-state ingestion — settlement observation, reservation settlement and ledger
reconciliation — MUST run independently per chain, with independent progress and independent lag
reporting. One chain falling behind MUST NOT stall another.

**MC-74** — The platform fee and the overhead allowance MUST be configurable per chain, because gas
conditions and signature-verification costs differ materially between chains.

**MC-75** — Per-chain paymaster funding, staking and low-balance alerting MUST be documented as
recurring operational obligations that scale with the number of chains served.

### 4.8 Identity, credentials and sessions

**MC-76** — Users, credentials, sessions and authentication challenges MUST remain chain-agnostic. No
chain dimension may be added to them.

**MC-77** — One authentication MUST be sufficient for every served chain. A user MUST NOT be asked to
register or sign in per chain.

**MC-78** — The WebAuthn user handle MUST NOT contain a chain id. Every field it carries MUST be
chain-independent, so that a credential valid on every served chain cannot be read as belonging to
one. Retaining the field as "informational" is not sufficient: a value that is misleading by
construction will eventually be trusted *(decided: Q10)*.

**MC-79** — Existing credentials and sessions MUST continue to work unchanged. No user may be required
to re-register a passkey as a result of this work.

### 4.9 User experience and consent

**MC-80** — Every screen on which the user gives consent — connecting, reviewing a transaction, and
signing a message — MUST display the chain the operation targets.

**MC-81** — The chain MUST be shown by human-readable name, not by chain id alone.

**MC-82** — Where a message to be signed carries its own chain in its typed-data domain, a mismatch
with the session's chain MUST be surfaced to the user rather than silently accepted.

**MC-83** — A refusal because the requested chain is not served MUST be presented in terms the user or
integrator can act on, and MUST make clear that the application's operator resolves it.

**MC-84** — The wallet's own settings surface MUST show the chain by name, the account address, and
whether the account is deployed on that chain.

**MC-85** — A user MUST NOT be asked for a passkey ceremony for an operation that cannot proceed
because its chain is not served. The refusal MUST come first.

### 4.10 Deployment profiles and chain configurability

**MC-86** — The set of chains a deployment serves MUST be configuration, applied at deployment time
and read at runtime. It MUST NOT be a build-time constant, a compiled-in list, or selected by a code
branch.

**MC-87** — One published set of artefacts — SDK, wallet interface, backend, operator console — MUST
serve both the on-premises and the standalone profile. There MUST NOT be a separate single-chain
build.

**MC-88** — A deployment serving one chain MUST be configurable with no more information than a
single-chain deployment requires today. It MUST NOT require any multi-chain configuration to be
supplied, not even as an empty or default value.

**MC-89** — Where exactly one chain is served, every multi-chain surface MUST reduce to nothing the
user has to act on: no chain picker, no chain-selection step, no per-chain funding ceremony beyond
the one chain. The chain MUST still be named on consent screens (MC-80), which is correct in both
profiles.

**MC-90** — An operator of a single-chain deployment MUST NOT need to understand the multi-chain
configuration shape in order to deploy, operate or upgrade it. Documentation MUST present
single-chain as a complete configuration in its own right rather than as multi-chain with parts
omitted.

**MC-91** — Chains MUST NOT be addable to a live deployment through an API or an administrative
interface. Adding a chain MUST be a deployment action.

**MC-92** — Structural misconfiguration and unavailability MUST NOT share a failure mode. A chain
that fails structural verification — the endpoint reports a different chain id, the factory is
absent or at a non-canonical address, the EntryPoint is absent — MUST prevent the deployment from
starting. A chain that is merely unreachable at load time MUST NOT: the deployment MUST start, report
that chain unavailable, and serve its other chains (MC-54).

**MC-93** — The standalone deployment's chain list MUST be changeable without any tenant changing
or redeploying its dApp, and a tenant MUST NOT be affected by the addition of a chain it does not
use.

**MC-94** — The chain list MUST be expressible in every deployment mechanism the project supports —
container composition and the Helm chart — without either requiring a different configuration shape
from the other.

### 4.11 Configuration, deployment and operations

**MC-95** — Chain configuration MUST follow one shape across the wallet origin, the backend and the
operator console, rather than each introducing its own.

**MC-96** — A chain MUST NOT be reachable by a deployment unless it is in that deployment's configured
list. There MUST be no path — request field, free-text configuration or fallback — by which an
unconfigured endpoint is contacted.

**MC-97** — Adding a chain to a running deployment MUST be a configuration change plus a verified
contract deployment, and MUST NOT require changes to the SDK, the wallet interface or the database
schema.

**MC-98** — Each served chain requires its own transaction-submission infrastructure and its own
funded submission account. This MUST be documented as a per-chain cost, and per-chain funding MUST be
monitored.

**MC-99** — Contract deployment to a new chain MUST be repeatable, MUST produce the canonical
addresses, and MUST fail rather than deploy to divergent addresses.

**MC-100** — There MUST be an operational check that verifies a chain end to end — endpoint identity,
EntryPoint, factory address, account derivation, and paymaster where enabled — runnable against any
chain before it is served and afterwards on demand.

**MC-101** — The deployment tooling MUST support serving several chains from one deployment without
duplicating the wallet origin, the backend or the database.

**MC-146** — There MUST be a documented **chain adoption checklist**, and it MUST be a deliverable of
this work rather than tribal knowledge. Chains are adopted on client demand rather than from a fixed
list, so adoption is a routine operation and MUST be turnkey: verify the deterministic deployer,
verify or place the canonical EntryPoint (MC-141), deploy, assert the canonical addresses, fund the
submission account, stake and fund the paymaster, and confirm the per-chain verification passes
*(decided: Q7)*.

**MC-147** — The per-chain verification check MUST be an **adoption gate**, not an advisory. A chain
that has not passed it MUST NOT be added to a deployment's served list.

### 4.12 Observability

**MC-102** — Every metric describing chain-facing work MUST carry the chain as a label. Cardinality MUST
remain bounded, which the closed chain list (D8) guarantees.

**MC-103** — Endpoint reachability, submission-infrastructure health and chain-state ingestion lag MUST
be observable per chain.

**MC-104** — There MUST be an alert for a served chain whose factory or implementation address ceases to
match the canonical one.

**MC-105** — There MUST be an alert for an account whose owner set differs between served chains
(MC-37).

**MC-106** — Logs for any chain-facing operation MUST identify the chain.

### 4.13 Verification and coverage

**MC-107** — The automated test environment MUST run at least two chains, so that multi-chain behaviour
is exercised rather than reasoned about. [§4.14](#414-test-demo-and-example-stacks) states what that
environment and the demonstration applications must provide.

**MC-108** — There MUST be an end-to-end test that creates one passkey, transacts successfully on two
chains, and asserts the account address is identical on both.

**MC-109** — There MUST be an end-to-end test that a dApp requesting an unserved chain is refused at
connection time, with the served chains reported.

**MC-110** — There MUST be a test that an owner added while connected to one chain can sign on the
other.

**MC-111** — There MUST be a test that a sponsorship authorisation issued for one chain is rejected on
the other.

**MC-112** — There MUST be a test that a chain whose endpoint reports a different chain id than
declared is refused at configuration load (MC-49).

**MC-113** — There MUST be a test that an operation is submitted to the submission endpoint of its own
chain, and that changing the target chain changes the endpoint used. This closes a defect that is
latent today and would become live with more than one chain configured.

**MC-114** — There MUST be a test that a call target permitted on one chain is not permitted on
another (MC-61).

**MC-115** — Single-chain behaviour MUST remain covered, and a single-chain deployment MUST be
exercised in continuous integration alongside the multi-chain one.

### 4.14 Test, demo and example stacks

The requirements in this section are what make [§4.13](#413-verification-and-coverage) real: a suite
can only assert multi-chain behaviour against an environment that actually has more than one chain,
and the two demonstration applications are where the guarantee becomes visible to a person.

Two applications are involved and they have different jobs. The **demo fixture** is the barebones
static page the Playwright suite drives — stable element ids, no framework. The **example app** is
the real UI, and is the thing shown to people who want to see Giano working. Both need cross-chain
submission, for different reasons.

**MC-116** — The end-to-end stack MUST bring up at least two chains with **distinct chain ids**, each
with its own submission infrastructure, and MUST deploy the canonical contracts to both at the same
addresses (MC-19).

**MC-117** — Both chains in the end-to-end stack MUST be provisioned identically with respect to gas
sponsorship, so a sponsored transaction can be exercised on either without per-chain setup in a test.

**MC-118** — Both chains MUST start as part of the stack's normal start-up, with no separate opt-in
step, so the two-chain stack is what contributors and continuous integration run by default.

**MC-119** — The pre-baked chain state the stack starts from MUST be reproducible for both chains
from a committed generator, and MUST be regenerable with the pinned toolchain.

**MC-120** — The stack backing the **example app** MUST also run two chains, on the same terms, so
the example app can demonstrate cross-chain submission without a bespoke environment.

**MC-121** — The **demo fixture** MUST expose a control that submits a transaction to the second
chain, with a stable element id, alongside its existing single-chain controls.

**MC-122** — That control MUST exercise the real chain-selection path — a provider constructed for
the second chain, negotiating that chain with the wallet origin — and MUST NOT simulate it or bypass
the SDK. A test that passes against a simulated path would assert nothing.

**MC-123** — The fixture MUST report, in its existing output surface, the chain each submitted
transaction went to and the account address used, so a test can assert both directly rather than
inferring them.

**MC-124** — The **example app** MUST offer cross-chain submission as a first-class part of its UI:
the user selects a chain, submits a transaction, and sees which chain it landed on together with the
resulting receipt.

**MC-125** — The example app MUST display the account address alongside the selected chain, so that
the address being identical on both chains (MC-16) is visible rather than asserted. The example app
is where this guarantee should be demonstrable to a person in a few seconds.

**MC-126** — The example app MUST surface the outcome of a cross-chain submission — success and
failure alike — both on screen and in the browser console, consistent with how its existing panels
report outcomes.

**MC-127** — The Playwright suite MUST cover, at minimum: one passkey transacting on both chains with
an identical address (MC-108); a dApp requesting an unserved chain being refused with the served
chains reported (MC-109); an owner added while connected to one chain being usable on the other
(MC-110); a sponsorship authorisation being rejected on the chain it was not issued for (MC-111); and
per-chain sponsorship configuration being independent (MC-67).

**MC-128** — Existing single-chain end-to-end tests MUST continue to pass unmodified against the
two-chain stack. The second chain MUST be additive, and that MUST be demonstrated rather than
assumed.

**MC-129** — The bring-your-own-wallet reference stack MUST be exercised with two chains as well,
because its configuration shape is effectively public API (MC-45).

**MC-130** — No shared test helper MUST depend on a hardcoded single chain id. The two chains' ids
MUST be visibly different, so a test that silently used the wrong one fails rather than passes.

**MC-131** — The stack documentation MUST state which chains it runs and their ids, and how to add or
remove one locally — including how to run the stack with a single chain, since that is the
on-premises profile (MC-88) and must stay easy to reproduce.

### 4.15 Compatibility and migration

Nothing is in production and no tenant has integrated, so this section is deliberately thin. The
clean-state assumption *(Q4)* removes the data-migration and wire-compatibility burden this work
would otherwise carry, and the requirements that encoded it are retained by id and marked removed
rather than deleted, because other documents cite them.

**MC-132** — A deployment serving one chain MUST remain configurable through the existing scalar
configuration, normalised internally into a one-entry chain list. This is not a compatibility
promise to existing deployments — there are none — but a simplicity promise to the on-premises
profile (MC-88, MC-90).

**MC-133** — *(Removed — Q9. Naming the chain is mandatory, so an SDK that does not name one is
refused by design. There are no published integrations to preserve.)*

**MC-134** — *(Removed — Q9. With mandatory naming and no deployed wallet origins predating it, the
unconfirmed-chain case cannot arise.)*

**MC-135** — *(Removed — Q4. No integration exists to break.)*

**MC-148** — Because the wire format, the credential user handle, the canonical contract bytecode and
the policy storage are all being fixed while nothing is in production, each MUST be treated as frozen
once the first tenant integrates. The clean-state latitude this section relies on is available once
*(decided: Q1, Q4, Q9, Q10)*.

### 4.16 Documentation

**MC-136** — The integration documentation MUST state how a dApp names its chain, what happens when it
does not, and what a refusal means.

**MC-137** — The deployment documentation MUST state how to configure several chains, the
address-identity precondition (MC-19) and how to verify it, and the per-chain operational
obligations.

**MC-138** — The transaction-flow documentation MUST show where the chain is decided, where it is
validated, and where it is recorded.

**MC-139** — Tenant-facing documentation MUST state that sponsorship is configured and funded per
chain, and that enabling a chain is an explicit act.

**MC-140** — The address-identity guarantee and its limits MUST be documented for tenants and users:
one address on every served chain, controlled by one passkey, and what follows from that for owner
management and for the security of the account.

---

## 5. Security posture

### 5.1 Why the scheme holds

**The chain is server-authoritative and drawn from a closed set.** A caller may request a chain; only
configuration admits one (D2, D8, MC-96). The set of reachable endpoints is fixed at deployment time,
so no request can direct the system at a chain nobody chose.

**Every operation is bound to exactly one chain.** The operation hash commits to the chain and is
computed from the validated chain, not from the request (MC-57). An operation authorised for one chain
is not valid on another.

**Sponsorship authorisations do not cross chains.** They are separated by chain and by paymaster
instance, so an authorisation obtained on a cheap chain cannot fund an operation on an expensive one
(MC-69).

**Address-based policy is chain-qualified.** An address means different code on different chains, so
allowlists are interpreted per chain (MC-61). Without this, allowlisting a benign contract on one
chain would silently allow whatever occupies that address elsewhere — which an attacker able to
deploy to a chosen address could arrange.

**Identity is bound to the origin, not the chain.** The browser enforces that a passkey is usable only
by its wallet origin. Adding chains does not widen that, because chains are not origins.

**The one deliberate cross-chain signature is contract-bounded.** Owner management is replayable
across chains by design (D5), and the set of operations that may be signed without chain binding is
enforced by the account contract, not by the backend (MC-34).

**Misconfiguration fails closed and fails early.** A chain whose endpoint disagrees about its own
identity, or whose factory is at the wrong address, prevents the deployment from serving it (MC-20,
MC-49). Both of those are failures that would otherwise appear as a user transacting somewhere
unintended.

### 5.2 What an attacker gets

**A caller naming an arbitrary chain** gets a refusal. It cannot cause an endpoint outside the
configured list to be contacted (MC-96).

**A caller naming a served chain it should not use** gets that chain — chain selection is not an
authorisation boundary, and is not intended to be. What bounds it is per-chain policy and per-chain
sponsorship configuration, both of which deny by default (MC-61, MC-67).

**A malicious dApp** gains nothing new. It could already request transactions; it can now request them
on a served chain of its choosing. The user's protection is unchanged and is the consent screen —
which is why the chain must appear there (MC-80). A dApp that requests a chain the user does not
expect is visible rather than silent.

**A compromised endpoint for one chain** can misreport that chain's state, including whether an
account is deployed and what an account's owner set is. It cannot forge a signature, cannot cause
submission to another chain, and cannot affect the other served chains. Detection is via the endpoint
identity check and the divergence alert (MC-49, MC-105).

**An attacker who compromises one owner of an account** compromises that account **on every served
chain**. This is inherent in one address with one owner set across chains, and it is a genuine
widening of blast radius relative to per-chain wallets. It is accepted because the alternative — a
different wallet per chain — is not the product, and because the mitigation is the same as for one
chain: owner management is itself a consented, sponsored, policy-bounded operation. It MUST be stated
plainly to tenants (MC-140).

**An attacker who can influence which chains a deployment serves** — that is, who can edit its
configuration — is already inside the trust boundary. Configuration load is the enforcement point
(MC-20, MC-48), which bounds accident, not a compromised operator.

---

## 6. Accepted limitations and roadmap

### 6.1 Accepted in v1

**No mid-session chain switching.** A dApp changes chain by constructing a new provider and
reconnecting, which costs a popup. Standard wallet-tooling chain pickers do not work and fail
visibly (MC-14).

**One chain at a time per provider.** A dApp cannot address two chains concurrently from one instance.
Two instances work (MC-10) but hold two sessions.

**Owner-set convergence is eventual.** An owner change reaches each chain on that chain's own timing
and any chain can fail, so there is a window in which a new passkey works on some chains and not
others. It is observable and retryable (MC-36), not atomic.

**Tenants fund gas per chain.** Balances, stakes, fees and low-balance monitoring are per chain, so
serving N chains multiplies a tenant's funding and monitoring work by N (D7).

**Infrastructure cost is linear per chain.** Each chain needs its own transaction-submission
infrastructure and its own funded submission account. This is the dominant recurring cost of adding a
chain and it does not amortise.

**A chain with a divergent factory cannot be served.** Address identity is a precondition (MC-19), so
a chain where the canonical factory cannot be placed is excluded — and that may be an external
constraint rather than something Giano can resolve.

**Signature-verification cost differs by chain.** Where the P-256 precompile is unavailable, the
fallback verification is materially more expensive, which changes sponsorship economics. Fees must
be tuned per chain (MC-74), and precompile availability must be checked before a chain is adopted.

**One backend process serves several chains.** A process-level failure affects every chain at once.
Per-chain health and degradation (MC-54) bound the ordinary case; they do not make the process
independent per chain. The alternative is [Q3](#7-open-questions).

**Account deployment is per chain and lazy.** A user's first operation on a newly served chain
includes deployment and therefore costs more. Same address, different deployment state.

**Chains cannot be removed.** Withdrawing a chain from a live deployment, and what becomes of accounts
and balances there, is undefined ([Q11](#7-open-questions)).

### 6.2 Roadmap

1. **Mid-session chain switching**, through the standard mechanism, so ordinary dApp chain pickers
   work. This is the natural v2 and is a delta on this work rather than a redesign; the state-coherence
   problems it raises (D1) are much easier to solve against a working multi-chain backend than
   alongside building one.
2. **A chain argument per operation**, so one session can address several chains concurrently — for
   portfolio views and cross-chain flows. Additive on everything here.
3. **Atomic owner-set convergence**, or at least a guaranteed-eventual mechanism with its own
   durability rather than best-effort replay.
4. **Automatic chain selection** — choosing the chain by where the user's funds or the tenant's
   sponsorship balance actually are, rather than making the dApp decide.
5. **Chain abstraction**: bridging and cross-chain intents, so the user never picks a chain at all.
   This work is a prerequisite either way, since executing on any of N chains is a precondition for
   choosing among them automatically.
6. **Cross-chain gas balances**, so a tenant funds once rather than per chain — dependent on 5.

---

## 7. Open questions

**All thirteen are answered.** The numbering is kept because other documents cite it, and each answer
is recorded in place with the requirements it settled. Three of them reversed a position this
document had previously taken; those are marked.

**Q1 — What happens to the registered chain whose factory address diverges? — ANSWERED: clean slate.**
The divergence had two independent causes, and neither was a compiler drift — settings are
byte-identical across all three registry entries. Chain 381185 was deployed against a
**non-canonical EntryPoint**: the account implementation hardcodes the EntryPoint address, and that
chain used a different one, so the constant differed, the bytecode differed, and every downstream
address differed. Base 8453/84532, separately, predate the v1.1.0 contract changes — their build
compiled 21 sources against 37 for 381185. So the registry held *three generations* and a fresh
build matched none of them; nothing was canonical. Since no production accounts exist, the answer is
to **freeze a canonical build now, deploy it to every fleet chain, and remove all pre-freeze
entries** (MC-19, MC-28). The hardcoded EntryPoint is generalised into MC-141, because it will
otherwise recur on the first private chain.

**Q2 — Where does the chain travel in a backend request? — ANSWERED: the body.** ERC-7677's fixed
JSON-RPC shape already carries the chain in its params, so a path scheme would mean two conventions
in one API. It would also be inconsistent across verbs — the receipt endpoints need no chain at all,
since the operation hash commits to it and the log row records it — and a path segment cannot be
omitted, which the single-chain profile needs (MC-53).

**Q3 — One backend process for all chains, or one per chain? — ANSWERED: one process.** The database
is shared either way, because sessions and credentials are chain-agnostic. The decisive argument is
owner-set convergence: it is inherently cross-chain, and one process gives it one worker with one
view of whether an account has converged, where N processes would need a coordinator — a shared
component again. Safe only with per-chain resource isolation, which is now MC-145. The chain registry
is kept as the seam at which to split if that proves insufficient.

**Q4 — Are policy allowlists per tenant, or per tenant and chain? — ANSWERED: per chain, always, with
no migration.** *(Reverses an earlier position in this document, which proposed inheriting a tenant's
base list to a default chain.)* The precedent was already in the schema: sponsorship configuration is
keyed `(tenant, chain)` with no inheritance. Relay policy protects the same kind of thing and now has
the same shape (MC-61). Because nothing is in production, the compatibility problem the inheritance
rule existed to solve does not arise — which also removes MC-60 and most of §4.15.

**Q5 — Who reconciles owner sets when a chain is added? — ANSWERED: on first use, with a fresh
authorisation — and a prerequisite was found first.** Specifying this surfaced that the chain-free
operation hash covers *everything except the chain id*, including `paymasterAndData`. Since a
sponsorship authorisation is bound to one chain, a sponsored owner-management operation has a
different hash on every chain and one user signature is valid on only one of them — and it cannot go
unsponsored, because Giano accounts hold no native token. The resolution keeps the replay path,
scoped to wallet management exactly as the contract already scopes it, and makes the **sponsorship
authorisation chain-independent for that operation class alone** (MC-142, MC-143). Backfill for a
newly added chain is therefore on first use with a fresh authorisation, because the sponsorship data
is inside the signed hash and a stored operation cannot be re-sponsored later (MC-38).

**Q6 — Is a tenant's relay rate limit shared or per chain? — ANSWERED: shared.** The limit protects
the relay and bounds a runaway tenant, and neither concern becomes more tolerable because the
deployment gained chains. A tenant needing more capacity raises it explicitly (MC-63).

**Q7 — Which chains, concretely? — ANSWERED: no fixed list; chains are adopted on client demand.**
This makes adoption a routine operation rather than a rare event, so the per-chain verification check
becomes a gate (MC-147) and a documented adoption checklist becomes a deliverable (MC-146). It also
raises the stakes on Q11.

**Q8 — May a dApp enumerate the served chains before connecting? — ANSWERED: no.** The refusal already
carries the list at the moment an integrator needs it, and under this design a dApp names its chain
at construction, so there is nothing to discover. An open endpoint would disclose the deployment's
shape to any origin. Additive later if that changes (MC-13).

**Q9 — Default chain per wallet origin or per dApp origin? — ANSWERED: neither; naming the chain is
mandatory.** *(Stricter than this document originally proposed.)* The SDK's chain parameter is already
required, so putting its value on the wire costs integrators nothing and eliminates the
silent-mismatch case outright — including in on-premises deployments, where pointing a dApp at the
wrong environment is the classic failure (MC-11, MC-12). Two consequences: the account is deployed at
registration on the **negotiated** chain rather than a fixed one, and "canonical" becomes an
explicitly frozen constant rather than whatever a reference chain happens to hold (MC-19).

**Q10 — Should the chain be removed from the WebAuthn user handle? — ANSWERED: yes, removed.**
*(Reverses an earlier position, which proposed retaining it as informational.)* The clean-state
assumption removes the two-layouts objection, and the handle then contains nothing chain-specific —
which is exactly right for a credential valid on every chain. A value that is misleading by
construction will eventually be trusted, so it is better absent than deprecated (MC-78).

**Q11 — Can a chain be withdrawn from a deployment? — ANSWERED: design for safe re-adoption now,
defer the exit story.** Withdrawing a chain withdraws nothing real: accounts stay deployed, users may
hold assets, the tenant's paymaster balance remains on that chain, and owner sets freeze. The sharp
edge — and the only part expensive to retrofit — is that a re-adopted chain must not silently
resurrect a stale owner set, which MC-144 prevents. Tenant notice, asset egress and paymaster balance
withdrawal remain out of scope ([§2.3](#23-out-of-scope-for-v1)).

**Q12 — Will any on-premises deployment ever serve more than one chain? — ANSWERED: assume one,
document it as complete, do not forbid more.** The artefacts are identical in both profiles (D13), so
there is no code path to forbid; the decision is one of documentation and support scope (MC-90).
MC-141 applies to on-premises with particular force: a private chain will not have the canonical
EntryPoint unless someone deploys it there.

**Q13 — Which two chains does the test stack run? — ANSWERED: two local networks, `31337` and
`31338`.** Retaining `31337` as the first chain means every existing single-chain test passes
unmodified, demonstrating MC-128 rather than asserting it. Making the second chain lack the P-256
precompile was considered and is not available: the pinned anvil provides RIP-7212 natively and it
cannot be toggled, and the baked state deploys the in-contract fallback verifier regardless.
Precompile availability is covered where it belongs, in the per-chain verification check (MC-100).

---

## 8. Glossary

| Term | Meaning |
|---|---|
| **Chain** | One EVM blockchain, identified by its chain id, on which a Giano deployment can execute transactions |
| **Served chain** | A chain in a deployment's explicit configured list, verified at load time. The only chains a deployment can reach |
| **Default chain** | The served chain used for a dApp that names none. Explicitly declared, never inferred |
| **Granted chain** | The chain the wallet origin actually assigned to a popup session, reported back to the dApp |
| **Chain negotiation** | The exchange in which the dApp names its chain and the wallet origin grants or refuses it |
| **Wallet origin** | The tenant-owned web origin serving the wallet interface. Its host is the WebAuthn relying party, and it is the trust boundary for signing and consent |
| **Tenant** | One customer of a Giano deployment: one wallet origin and one relying party, one-to-one |
| **Address identity** | The property that one passkey resolves to the same account address on every served chain. The central guarantee of this work |
| **Canonical factory address** | The account factory address that must be identical on every served chain for address identity to hold |
| **Deterministic deployment** | Placing a contract at an address computed from the deployer, a fixed salt and the contract's exact bytecode, so the address is the same on every chain |
| **Owner set** | The credentials and addresses authorised to act for an account. Must be identical across served chains for the account to behave as one wallet |
| **Owner management** | Adding or removing an owner, or upgrading the account. The one operation class signed without chain binding, so one authorisation applies to every chain |
| **Chain-independent authorisation** | The account contract's path allowing an owner-management operation to be submitted to any chain from a single signature, restricted by the contract to that operation class |
| **Lazy deployment** | An account existing at a known address on a chain before any contract is deployed there, deployed as part of its first operation on that chain |
| **Operation hash** | The identifier of a submitted operation, which commits to the chain, making the operation valid on one chain only |
| **Paymaster** | The on-chain contract that pays transaction fees on a user's behalf. One deployment per chain, separately staked and funded |
| **Tenant balance** | A tenant's funds held by a chain's paymaster, spendable only by that tenant and only on that chain |
| **Sponsorship authorisation** | The signature that permits a paymaster to pay for one operation. Bound to one chain and one paymaster instance |
| **Submission infrastructure** | The service that submits operations to a chain and fronts their gas. One per chain, each with its own funded account |
| **On-premises deployment** | Giano running inside a client's own infrastructure. Expected to serve exactly one chain |
| **Standalone deployment** | The multi-tenant deployment Giano operates. Where several served chains are actually wanted |
| **Deployment profile** | Which of the two shapes a deployment is. A matter of configuration only: both run the same published artefacts |
| **Demo fixture** | The barebones static page the end-to-end suite drives — stable element ids, no framework. A test target, not a demonstration |
| **Example app** | The real example interface, the thing shown to someone who wants to see Giano working. Where the address-identity guarantee should be visible in seconds |

---

## Related documents

- [`specs/DEVELOPER-GUIDE.md`](./DEVELOPER-GUIDE.md) — deployment and local environments, which must
  gain multi-chain configuration and the per-chain verification step (MC-137)
- [`specs/INTEGRATION.md`](./INTEGRATION.md) — the dApp-facing contract, which must gain chain
  selection, refusal semantics and the address-identity guarantee (MC-136, MC-140)
- [`specs/TRANSACTION-SUBMISSION-FLOW.md`](./TRANSACTION-SUBMISSION-FLOW.md) — the submission path,
  which must show where the chain is decided, validated and recorded (MC-138)
- [`specs/PAYMASTER-REQUIREMENTS.md`](./PAYMASTER-REQUIREMENTS.md) — gas sponsorship requirements.
  Its Q6 already anticipated several chains with per-chain balances; this document holds to that
  (D7) and adds the per-chain routing and deny-by-default requirements
- [`specs/PAYMASTER-SPECS.md`](./PAYMASTER-SPECS.md) — the sponsorship technical specification, whose
  chain-keyed ledger and configuration this work relies on and must not alter
- [`README.md`](../README.md) — distinguishes the example app from the barebones end-to-end fixture,
  and describes the stacks that must gain a second chain ([§4.14](#414-test-demo-and-example-stacks))
- [`MULTICHAIN-SUPPORT-REPORT.md`](../MULTICHAIN-SUPPORT-REPORT.md) — the preceding analysis: the
  current single-chain inventory, the alternatives considered, and why the approach in this document
  was chosen
