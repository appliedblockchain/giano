# Giano — business requirements

Giano gives an application's users a self-custodial blockchain wallet that they open with a
passkey — the same face, fingerprint or device PIN they already use to unlock their phone. There is
no seed phrase to write down, no browser extension to install, and no native token to buy before
the first transaction works.

This document states *what* the product must do and *why*, at the level of the whole system. It is
not an implementation plan, and it does not restate the per-work-stream requirements that already
live in [`MULTICHAIN_REQUIREMENTS.md`](./MULTICHAIN_REQUIREMENTS.md) and
[`PAYMASTER-REQUIREMENTS.md`](./PAYMASTER-REQUIREMENTS.md) — it names the requirements those
documents exist to serve.

Status: **draft, in review.**

> **Numbering.** Requirements are `BR-nn` and are globally unique within this document. They are
> unrelated to the `MC-nn` and `R-nn` series used by the work-stream requirement documents.

---

## Contents

1. [What Giano is for](#1-what-giano-is-for)
2. [Core requirements](#2-core-requirements)
3. [On-premise deployment](#3-on-premise-deployment)
4. [Running Giano as a standalone service](#4-running-giano-as-a-standalone-service)
5. [Planned capabilities, not yet built](#5-planned-capabilities-not-yet-built)
6. [Open questions](#6-open-questions)

---

## 1. What Giano is for

This section is context, not requirement. It exists so the requirements that follow are read
against the problem they were chosen to solve.

### 1.1 The problem

Blockchain applications lose most of their prospective users before those users ever reach the
product. The cause is not the application — it is the wallet in front of it. A new user is asked,
in the first minute, to install a browser extension, to write down and safeguard twelve words that
cannot be reset, and to acquire a native token from somewhere else entirely before their first
action will confirm. Each of those is a point at which a normal person stops.

The industry's usual answer is to take custody: hold the user's keys on their behalf, and hide the
chain completely. That does fix the onboarding cliff, and it replaces it with a different problem —
the operator now holds user assets, with everything that follows from it in risk, in liability and
in regulatory exposure. For many applications that trade is not acceptable, and for some it is not
lawful.

### 1.2 What Giano does instead

Giano belongs to the category the industry calls **embedded wallets**: the wallet is part of the
application, created for the user in place, rather than something the user is expected to bring
with them. That category exists precisely because of the problem above, and most of it buys the fix
with custody — the provider holds the keys, and the user's wallet only works for as long as the
provider is willing and able to operate it.

Giano is an embedded wallet that does not make that trade. It removes the same three obstacles
without taking custody of anything.

The **passkey replaces the seed phrase.** Every modern device can create and hold a hardware-backed
credential and release a signature from it on a biometric prompt. Giano makes that credential the
controller of an on-chain smart account directly, so the thing that authorises a transaction is the
user's device and body — not a secret they were made responsible for.

**Sponsorship replaces the native token.** The application funds gas for the transactions it has
approved, so a user transacts from the first moment, holding nothing.

**An SDK replaces the extension.** The application installs a package and points it at a wallet
origin. The user installs nothing at all.

### 1.3 Who it is for

Giano's customer is the **integrating application** — a team that wants to offer their users a
wallet without becoming a wallet company, and without holding anyone's assets. Giano is delivered
to them as software they deploy and operate themselves, not as a service they depend on us to keep
running.

---

## 2. Core requirements

These are the requirements that define the product. Each one, if withdrawn, would make Giano a
materially different system rather than a lesser version of the same one.

### 2.1 Foundations

**BR-01** — A device passkey MUST be the entire credential controlling a user's wallet. There MUST
be no seed phrase, no mnemonic, and no private key material ever displayed to the user, transmitted
to any server, or made the user's responsibility to store.

**BR-02** — Giano MUST be self-custodial. No component operated by Giano or by the integrating
application — backend, database, relay or administrative interface — MUST be able to authorise a
transaction or move a user's assets. Server-side components MUST be limited to policy decisions and
relaying; the authority to sign MUST exist only in the user's device credential.

**BR-03** — The authority to change what controls a wallet MUST rest solely with the wallet's
existing owners. Adding a credential, removing one, and replacing the account's implementation MUST
each require a signature from a credential the wallet already recognises. No component operated by
Giano or by the integrating application, and no administrative role, key or upgrade mechanism held
by either, MUST be able to add an owner to a user's wallet, remove one, or change the code that
wallet runs.

BR-02 forbids Giano from spending a user's funds. This requirement forbids Giano from acquiring the
ability to, because an authority to upgrade an account or to add an owner to it is an authority to
sign by another name. The upgradeability BR-14 requires exists to serve the user — it is how a
wallet created today gains capabilities it lacked, including BR-33's recovery — and MUST NOT become
an operator's route into it. This constrains a user's wallet and not the shared infrastructure
around it: a paymaster holds no authority over any wallet and no user's assets, and may be
upgradeable by the party that funds and operates it.

**BR-04** — The credential MUST be isolated from the integrating application. All passkey ceremonies,
all signing, and all user consent MUST occur on a wallet origin that is separate from the
application's own origin, and the application MUST NOT be able to observe, script or reach the
credential. A compromised or malicious application MUST NOT be able to obtain a signature the user
did not approve.

**BR-05** — A user MUST be able to transact without ever holding a native token. Transaction fees
MUST be payable by the integrating application on the user's behalf, for the transactions that
application has approved, and the user MUST NOT be required to acquire, hold or manage any asset in
order to use the wallet.

**BR-06** — Integration MUST cost an application no more than installing a published package and
naming a wallet origin. The application MUST NOT be required to implement wallet functionality,
handle key material, or ask its users to install anything. Integration MUST be through the
interfaces the ecosystem's existing tooling already speaks, so that an application's current
wallet-facing code continues to work.

**BR-07** — Giano MUST be deliverable as versioned, self-hosted artifacts that a client deploys and
operates themselves. No part of a client's production system MUST depend on a service that Giano
operates. Every release MUST be reproducible from published, version-pinned artifacts.

**BR-08** — Giano MUST run on Silent Data Rollup as a first-class target rather than as an
adaptation. A user MUST get the same wallet, the same passkey and the same experience on a
privacy-preserving chain as on a public one, and serving it MUST NOT require a forked or variant
build of Giano.

**BR-09** — Giano MUST work against private and permissioned blockchain nodes. It MUST NOT assume
that a chain is publicly reachable, that its endpoint is unauthenticated, that third-party
transaction-submission infrastructure exists for it, or that it provides the same native
capabilities as a public chain.

### 2.2 The parts of the system

Section 2.1 states what Giano promises. This section names the parts that must exist for those
promises to hold. It stays at the level of *what each part is for* — the interfaces, schemas and
protocols are the subject of the work-stream specifications, not of this document.

**BR-10** — Giano MUST publish a client SDK that an integrating application installs as a versioned
dependency. The SDK MUST expose the wallet through the standard interfaces the ecosystem's existing
wallet tooling already speaks, so that an application's current wallet-facing code works unchanged,
and MUST NOT require the application to bundle credential-handling or transaction-construction code
of its own.

**BR-11** — Giano MUST provide a user interface, served from the wallet origin, through which a user
creates a wallet, connects it to an application, reviews and approves transactions, signs messages,
and inspects the wallet's own state. That interface MUST be presented without navigating the user
away from the application they are using.

**BR-12** — Giano MUST provide a backend that runs the passkey registration and authentication
ceremonies, maintains the registry of credentials and their associated wallets, issues and revokes
user sessions, and evaluates every transaction against the owning application's rules before
relaying it onward. Every relay decision — allowed or refused, and on what grounds — MUST be
recorded durably enough to answer an audit.

**BR-13** — A user's wallet MUST NOT be confined to the browser or device where it was created. The
system MUST hold the identity of a user's wallet — its credentials, its address and its history — in
durable storage, so that a user returning on another browser or another device reaches the same
wallet rather than an empty one.

**BR-14** — The wallet itself MUST be an on-chain smart account controlled by the passkey's public
key. It MUST be reachable at an address that is derivable in advance of its first transaction, MUST
be able to hold more than one controlling credential, and MUST be upgradeable without its address
changing.

**BR-15** — A wallet MUST admit controlling credentials of more than one kind. Alongside several
passkeys, a wallet MUST be able to be controlled by an ordinary externally-owned account — a
software wallet or a hardware signing device the user already holds — and the passkeys it holds MUST
be able to be bound to different wallet origins. A user's continued control of their wallet MUST NOT
rest on a single device, a single kind of credential, or a single domain remaining available to
them.

This is the capability BR-32's credential management and BR-33's recovery are expressed in terms of,
and it is the answer to the risk BR-04's origin binding creates: a passkey binds to one hostname, so
a wallet whose only credentials bind to one hostname is a wallet that hostname can take with it.

Where a wallet is served on more than one chain, its owner set MUST be able to be brought into
agreement across them. The set is per-chain state, and a credential that controls the wallet on one
chain but not another is a recovery path that fails at the moment it is needed.

**BR-16** — A signature or transaction MUST NOT leave the wallet without the user having been shown
what they are approving — what it does, which application asked, and on which chain — and having
actively approved it. Refusal MUST be a first-class outcome that the requesting application can
detect and handle, and MUST NOT be indistinguishable from a failure.

**BR-17** — Sponsorship MUST be controllable and accountable by the party paying for it. The operator
MUST be able to state which transactions are eligible, MUST be able to attribute every sponsored
transaction to the budget that paid for it, and MUST be able to bound its exposure so that a funded
budget cannot be drained by abuse of an application's own users or by a third party.

**BR-18** — A client MUST be able to present the wallet as part of their own product. Their users
MUST see the client's domain and the client's branding rather than Giano's, whether the client
points their own domain at a wallet interface Giano serves or runs an interface of their own
against the same backend.

---

## 3. On-premise deployment

Giano's primary delivery model is a deployment the client runs themselves. **On-premise** here means
*the client's own estate* — their cloud account, their cluster, their database — and not an isolated
network: a deployment still reaches a blockchain, and reaching a public chain means reaching the
public internet. Genuinely air-gapped operation is out of scope.

The governing requirement of this section is that the client builds **no wallet software**. A client
adopting Giano is integrating a finished product, not commissioning one, and everything below
follows from that.

**BR-19** — A client MUST be able to adopt Giano without developing wallet functionality of any kind.
No user interface, no credential handling, no passkey ceremony logic and no transaction construction
MUST be left for the client to write. The client's engineering effort MUST be limited to integrating
Giano into their own application.

**BR-20** — Everything a deployment needs MUST be shipped by Giano: the backend, the wallet
interface, the database schema and its migrations, the transaction submission infrastructure, the
smart contracts, and the means to deploy them. No component required for a working deployment MUST
be left for the client to supply or to build.

**BR-21** — Deployment MUST be executed rather than described. Giano MUST ship deployment artifacts —
scripts, container definitions and infrastructure manifests — that stand up a complete environment by
being run, and that produce the same environment each time they are run. A prose runbook MUST NOT be
the only path to a working deployment.

**BR-22** — Adapting a deployment to a client MUST be a matter of configuration. Domains, branding,
the chains served, sponsorship rules and operational limits MUST all be settable without modifying
Giano's source. A client MUST never need to fork Giano in order to go live, because a client who
forks cannot take upgrades.

**BR-23** — A client MUST be able to take a new version of Giano using their own team: a documented
upgrade path, data migrations that run as part of it, and no loss of any user's wallet, credential or
history across it. Upgrading MUST NOT require Giano's involvement, or "on-premise" means an
operating dependency on Giano by another name.

**BR-24** — Everything a deployment holds about its users — credentials, wallet records, sessions and
audit history — MUST reside in infrastructure the client controls, in a jurisdiction of their
choosing. No user data MUST be required to leave the client's estate for the deployment to function.

**BR-25** — A client MUST be able to choose between Giano's canonical, shared contract deployments and
deploying their own instances of the same contracts, and both MUST be supported as a configuration
choice. The consequence of that choice MUST be stated to the client before they make it, because it
is not reversible in practice: on canonical contracts a user reaches the same wallet address they
hold in every other canonical deployment on that chain, while on the client's own contracts the
deployment is a wallet universe of its own, whose addresses exist only within it.

**BR-26** — Transaction submission MUST NOT be tied to a single provider. A client MUST be able to run
the submission infrastructure Giano ships or to point the deployment at a third-party vendor, and
chain access MUST likewise be an endpoint of the client's choosing. No part of the transaction path
MUST depend on a service Giano operates.

**BR-27** — What the client does remain responsible for MUST be stated explicitly: integrating the SDK
into their application, owning the domains their users see, providing chain access, funding gas
sponsorship, and operating the infrastructure the deployment runs on. A commitment that the client
builds nothing is credible only alongside a clear statement of what they do.

---

## 4. Running Giano as a standalone service

[Section 3](#3-on-premise-deployment) describes the primary delivery model: software a client
deploys and runs themselves. The requirements in sections 2 and 3 are complete without this
section.

Giano is *additionally* intended to be runnable as a standalone service — one deployment serving
several unrelated applications, whether commercially or as shared development infrastructure. The
requirements here apply only in that mode. They are not weaker than the core requirements, but they
are conditional on it: a client running Giano for their own single application can satisfy the whole
of sections 2 and 3 while implementing none of this section.

**BR-28** — A single Giano deployment MUST be able to serve several unrelated applications at once,
each with its own configuration, its own rules, its own funds and its own trusted origins. One
application MUST NOT be able to observe, spend, or act on behalf of another, and a
misconfiguration of one MUST NOT degrade the others.

**BR-29** — An application MUST be able to be registered, configured, and made live on a running
deployment without a code change and without redeploying the service. Onboarding a new tenant MUST
NOT require the operator to touch a deployment artifact.

**BR-30** — Each tenant MUST fund its own sponsorship budget, MUST be able to see what that budget
has been spent on, and MUST be able to top it up. The operator MUST be able to charge a fee against
each sponsored transaction and to account for what is owed.

**BR-31** — A tenant MUST NOT be able to degrade another tenant's service. Consumption of shared
capacity MUST be bounded per tenant, so that a traffic spike, a defect or an attack against one
application does not exhaust the capacity or the funds available to the rest.

---

## 5. Planned capabilities, not yet built

Every requirement in this section is **not implemented**. They are stated here, and numbered with
the rest, because they are commitments the product is expected to meet rather than ideas under
consideration — what is undecided is when and how, not whether.

**BR-32** *(not implemented)* — A user MUST be able to see and control the set of credentials that
can act on their wallet: to see which credentials exist, to distinguish them from one another, to
add a further passkey on another device, and to remove one that is lost or no longer trusted.
Today a wallet is created with a single credential and the user can neither see that set nor
change it.

**BR-33** *(not implemented)* — A user who loses the device holding their passkey MUST be able to
regain control of the same wallet, at the same address. No recovery mechanism MUST allow anyone
other than the user to take control of the wallet, and BR-02 MUST continue to hold throughout:
recovery MUST NOT be achieved by any party other than the user holding an authority to sign.

This is the most significant gap in the product today. A user who loses their device loses the
wallet, and that is not an acceptable state for anything holding value. The mechanism is an open
question — see [§6](#6-open-questions).

**BR-34** *(not implemented)* — A user MUST be able to see what their wallet holds and what it has
done — balances and a history of its transactions — from the wallet interface itself, so that the
wallet is somewhere a user can go and check rather than only something that appears to ask for
approval.

**BR-35** *(not implemented)* — An operator running Giano as a standalone service MUST have an
administrative interface through which the requirements of [§4](#4-running-giano-as-a-standalone-service)
are exercised: registering an application, setting its rules and origins, funding and watching its
gas budget, and reviewing its usage. Onboarding a tenant MUST NOT require the involvement of a Giano
engineer.

**BR-36** *(not implemented)* — A wallet MUST be able to be controlled by several credentials
belonging to several people, with a stated rule for how many of them must approve before a
transaction proceeds. The account already admits more than one owner; what is missing is a
threshold rule, the means to approve across people and time, and an interface for both.

---

## 6. Open questions

**Q1 — How is recovery achieved (BR-33)?** The requirement is agreed; the mechanism is not. The
options are materially different in cost, in user experience, and in what each asks a user to trust:

- a **second passkey registered at wallet creation**, on a different device — simplest, and depends
  on the user having a second device and doing it before they need it;
- **recovery mediated by the tenant**, who vouches for the user through whatever identity they
  already hold for them — easiest for the user, and creates an authority the tenant did not have
  before;
- **guardians** — other accounts the user nominates, who together can restore access — strongest
  against a single point of failure, and the hardest to explain to an ordinary user;
- a **delayed recovery with a challenge window**, where a recovery attempt takes effect only after a
  period during which the existing credential can cancel it — defends against a stolen recovery
  path, at the cost of not being immediate.

These are not exclusive; a product answer may combine them. This question must be settled before
BR-33 can be specified.
