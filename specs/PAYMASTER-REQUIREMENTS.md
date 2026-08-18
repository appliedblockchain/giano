# Giano paymaster — requirements

Giano sponsors gas for its tenants, so end users transact without ever holding a native token —
but **only for transactions the tenant has approved**, and **only against funds that tenant has
put up**. Giano takes a fixed fee per sponsored transaction.

The mechanism is a **validating paymaster**, also called signed sponsorship. When a user is about
to transact, the Giano backend checks the transaction against that tenant's rules and available
balance. If both pass, it issues a signature. The on-chain paymaster pays only when it sees a
valid signature, debits that tenant's own balance, and credits Giano's fee. No signature, no
sponsorship.

This document states *what* the system must do and *why* the main decisions were made. It is not
an implementation plan; the technical detail lives in
[`specs/PAYMASTER-SPECS.md`](./PAYMASTER-SPECS.md).

Status: **requirements, agreed.** Section [§7](#7-open-questions) lists what still needs a
decision, and records the answer where one has since been given.

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

**Giano has no production gas sponsorship.** The end-to-end plumbing exists and works — a
transaction can be sponsored, and users never touch a native token — but three things that make
it a product have never been built: the component that decides *whether* to sponsor, the
accounting that says *whose money* paid, and any way for Giano to *earn* from it.

What stands in place of the first is a deliberately permissive paymaster: a test fixture that
approves everything, so local development and automated tests can exercise the sponsored path
without configuring rules. It does that job well and it stays (see
[§2.4](#24-the-permissive-test-paymaster-stays)). It was never intended to run in production, and
this work is not a repair of it — it is building what was always going to be needed alongside it.

Three requirements follow, and each is harder than it first looks.

### 1.1 The decision has to happen before the user signs, and be enforced by the chain

Giano already has a policy engine, applied when a signed transaction is relayed to the network.
It is a good engine and it stays, but it cannot carry sponsorship. By the time it runs, the user
has signed and the sponsorship is already committed; refusing to forward the transaction does not
un-commit the payment. And a client that skips Giano's relay and submits straight to the network
bypasses any backend check entirely — if the paymaster itself cannot tell an approved transaction
from an unapproved one, it pays either way.

So the decision is taken up front by the Giano backend and expressed as a **signature the
paymaster contract verifies on-chain**, regardless of what route the transaction takes.

### 1.2 Tenants must fund their own gas, separately

Giano is sold to multiple tenants. A single pot of operator money spent on everyone's behalf
gives no basis for billing, no protection against one tenant consuming another's gas, and no
answer to "how much do I owe you". Each tenant must **fund its own balance explicitly**, and must
be able to spend **only** that balance.

The hard part is that account abstraction gives the paymaster one deposit, not many. Segregation
has to be built as a ledger over that deposit, and the ledger has to hold under concurrency —
several of a tenant's transactions can be in flight simultaneously, each individually affordable
and collectively not.

### 1.3 Giano needs to earn from it

Sponsorship costs Giano operational work: running the signing service, carrying the deposit,
monitoring, support. A **fixed platform fee per sponsored transaction**, set by Giano, charged to
the tenant on top of the gas their transaction consumed.

Gas itself cannot be marked up — the network charges what it charges, and the EntryPoint debits
exactly that. So the fee is not a gas surcharge; it is a separate debit against the tenant's
balance, made by the same contract in the same operation, and credited to a treasury Giano can
withdraw.

---

## 2. Goal and scope

### 2.1 Goal

A tenant funds gas for **its own application's transactions**, out of **its own balance**, and
pays Giano a fixed fee for each one. Sponsorship becomes an explicit, per-tenant,
per-transaction authorisation decision, taken before the user is asked to approve anything, and
enforced on-chain.

### 2.2 In scope for v1

- A production paymaster contract that verifies an authorisation signature, holds segregated
  per-tenant balances, and charges a platform fee.
- Explicit tenant funding, and withdrawal controlled by the tenant rather than by Giano.
- A sponsorship decision service evaluating each transaction against the tenant's rules **and
  available balance**.
- Three tenant rules: an **allowlist** of contracts and functions, a **maximum cost per
  transaction**, and **sufficient balance** — plus one **platform** rule covering wallet
  management, which is sponsored whatever the tenant's allowlist says (R-05, R-65).
- A reservation ledger, so concurrent transactions cannot collectively overdraw a balance.
- A fixed platform fee, configurable by Giano, with per-tenant overrides.
- Explicitly named roles for every privileged action, with no owner and no superuser.
- An upgradeable contract, behind multi-party control and a published upgrade delay.
- Per-tenant configuration, editable by the tenant without a redeployment.
- A standards-based interface (ERC-7677) so tenants running their own wallet interface need no
  Giano-specific integration work.
- Clear, typed refusals surfaced in the wallet before the user is asked to approve.
- End-to-end coverage of the production paymaster, and a demo stack that stands itself up —
  deployed, staked, funded and configured — with no manual setup.

### 2.3 Out of scope for v1

Deliberately deferred, with reasoning in [§6](#6-accepted-limitations-and-roadmap):

- Rate and spend limits per individual end user.
- Percentage-based or tiered fees.
- Users paying gas in ERC-20 tokens instead of being sponsored.
- Tenants funding in anything other than the chain's native token.

### 2.4 The permissive test paymaster stays

The existing permissive paymaster is a **development and test tool**, and this work does not
remove or replace it. It exists so that local development and automated tests can exercise the
sponsored transaction path without standing up a signing service, funding a balance, or
configuring an allowlist for every fixture — which is exactly what you want when the thing under
test is a token transfer, not the sponsorship rules.

The two coexist, with a clear division:

| | Permissive paymaster | Production paymaster |
|---|---|---|
| Purpose | Test fixture — keeps sponsored-path tests simple | Real sponsorship, rule-enforced, billed |
| Decides anything | No, approves everything | Yes, per tenant, per transaction |
| Whose money | Whoever funded it | The tenant's own segregated balance |
| Charges a fee | No | Yes |
| Where it runs | Local development, test runs | Every real deployment |
| Configuration needed | None | Balance, allowlist, cost cap |

**R-28** — The permissive paymaster MUST remain available for local development and testing, and
MUST NOT require any configuration to use.

**R-29** — The permissive paymaster MUST NOT be deployable to a production environment, and the
separation MUST be structural rather than a matter of operator discipline.

The end-to-end test suite additionally needs to cover the *production* paymaster, because rule
enforcement and billing become the parts most worth having coverage of. That is a gap to close by
**adding** scenarios, not a reason to retire the permissive one — a suite in which every fixture
needs a funded balance and a correctly configured allowlist is a suite that breaks for reasons
unrelated to what it tests. [§4.12](#412-end-to-end-coverage-and-the-demo-stack) states what that
coverage must contain, and what the demo stack must do for itself.

---

## 3. Key decisions

Sixteen decisions shape everything else. Each records what was chosen, what was rejected, and —
where it matters — the consequence that has to be lived with.

### D1 — Segregated per-tenant balances in one shared contract

One paymaster contract per Giano deployment, holding a **per-tenant ledger**. Tenants fund their
own balance explicitly. The money itself joins a single pooled network deposit, because account
abstraction provides only one — but the ledger records whose it is, and the contract enforces
that a tenant can spend only its own.

The accounting invariant, which the contract preserves on every transaction:

```
Σ tenant balances  +  Giano treasury  ≤  the paymaster's network deposit
```

**The relation is "at most", not "equal", and the direction is deliberate.** The network charges
the deposit for slightly more than the contract can observe at the moment it settles — the
accounting step's own gas, and a penalty on over-estimated gas limits, both fall outside the cost
figure handed to the contract. The contract therefore debits a deliberately generous allowance
for that overhead (R-41), so the ledger falls a little faster than the deposit does. The residue
is unattributed slack sitting in the deposit.

Slack is safe: every claim is covered. Equality would not be, because the arithmetic that
produces it drifts the *other* way, leaving the ledger promising money the deposit does not hold.
So the monitored condition is the inequality, plus an alert if the slack grows faster than
expected — which would mean the overhead allowance is mis-calibrated and tenants are being
overcharged.

Giano can withdraw the treasury and nothing else. A tenant's funds are not a claim on Giano; they
are the tenant's, held in a contract, withdrawable by the tenant (D12).

*Rejected:* one operator-funded pot with spend merely attributed to tenants afterwards — no
segregation, no protection between tenants, and a tenant would have to trust Giano's books for
billing. Also rejected: one paymaster contract per tenant — genuine isolation, but N
deployments, N stakes and N addresses to keep funded and monitored.

*Consequence:* the contract must run accounting logic after every transaction, which costs gas on
every sponsored operation (D4). And the balance check reads a value that all of that tenant's
in-flight transactions share, which is why D5 exists.

### D2 — One signing key now, built to become many

The paymaster recognises a *set* of authorised signers, not one fixed key, and keys can be added
and revoked by the holder of a dedicated signer-administration role (D13). v1 operates a single
key; the design does not have to change to add more.

*Rejected:* a single permanently fixed key (rotating it would mean redeploying the paymaster,
migrating every balance, and reconfiguring every tenant); per-tenant keys from day one.

### D3 — A standard interface, not a Giano-specific one

The sponsorship service speaks **ERC-7677**, the established standard for paymaster services.
Standard wallet tooling understands it out of the box.

*Rejected:* a bespoke Giano endpoint. Richer error payloads, at the cost of custom integration
work for every tenant running its own wallet interface.

### D4 — Three rules, and the balance is the budget

v1 enforces:

- **Contract and function allowlist**, denying anything not explicitly permitted.
- **Maximum cost per transaction.**
- **Sufficient balance**, checked on-chain during validation and off-chain before signing.

No separate budget concept is needed: a tenant's balance *is* its budget, and it is enforced by
the chain rather than by a policy setting. Spending caps per period, if ever wanted, become a
convenience on top rather than the mechanism.

Alongside these three sits one rule the tenant does not own: wallet-management transactions are
sponsored under **platform** policy and a platform cap (D15), because a category that must be
sponsored cannot be gated by a list a tenant might leave empty.

*Consequence:* the contract implements post-transaction accounting, so every sponsored
transaction carries that cost and must pre-fund it. This makes sponsored transactions
measurably more expensive than under a paymaster that simply pays and forgets.

### D5 — Reserve on authorisation, settle on receipt — mandatory, not optional

When a signature is issued, the maximum possible cost plus the fee is **reserved** against the
tenant's balance. On receipt it is released and the actual cost settled. Reservations that expire
unused are swept back.

```
available = balance − reserved
```

This is not an accounting nicety. **It is what makes segregation hold under concurrency.** The
on-chain check happens per transaction, but transactions settle in batches:

> A tenant has 0.010 available. Three transactions are authorised, each costing at most 0.005.
> Each one individually passes the on-chain check, because at validation time nothing has been
> debited yet. All three land in the same batch. Together they need 0.015 against a balance of
> 0.010.

The contract cannot resolve this after the fact — refusing to settle would revert transactions
the network has already executed and charged for, so the only safe behaviour is to debit what is
there and record the shortfall. That shortfall comes out of the pooled deposit, which is other
tenants' money. Segregation would leak precisely where it matters.

The reservation ledger prevents the third signature from being issued at all.

*Consequence:* the on-chain balance check is a **backstop**, not the primary gate. Its real value
is bounding a compromised or buggy backend — something no off-chain ledger can do. Day to day, it
should never bind.

### D6 — Refuse before asking, and say why

If the rules deny a transaction, or the balance is insufficient, the wallet shows the reason and
offers no approve button. The user is **never** asked for a fingerprint or face scan for a
transaction that cannot be paid for. The refusal carries a machine-readable reason, so "this app
doesn't support that contract" reads differently from "this app has run out of gas credit".

*Rejected:* falling back to letting the user pay. Giano passkey accounts hold no native token in
practice, so it would present a choice that cannot succeed.

### D7 — Tenants configure their own rules, through the existing admin API

Sponsorship rules join the per-tenant configuration that already exists, written through the
tenant's existing authenticated admin API. A tenant can add a newly deployed contract to its own
allowlist without an operator, a redeployment, or a support ticket.

Balance and fee are **not** tenant-writable: balance changes only through on-chain funding and
spending, and the fee is Giano's to set (D11).

### D8 — Per-tenant on/off switch, and per-tenant balance monitoring

Any tenant can run with sponsorship switched off, in which case its wallet behaves exactly as the
unsponsored path does today.

Because balances are now per tenant, so is running out. Each tenant's available balance is
monitored with a configurable low-balance alert, and exhaustion produces a clear refusal rather
than a transaction that fails after the user has already authenticated. Separately, the
deployment-wide accounting invariant (D1) is monitored, because a divergence there means
something is wrong with the ledger itself.

### D9 — An authenticated session is required, bound to the user's own wallet

A sponsorship request must carry the wallet session token; the tenant is derived from the
requesting origin; the session's tenant must match; and the transaction's sender must be that
session's own wallet.

*Rejected:* identifying the tenant by origin alone. The origin header is not enforced outside a
browser, so it is trivially forgeable server-to-server. This matters more now than it did before
sponsorship cost the tenant real money.

### D10 — Deployed like the rest of the stack, and address-stable

The paymaster follows Giano's existing deterministic deployment pattern and is published in the
address registry.

Because it is upgradeable (D14), its configuration — roles, fee, overhead allowance — lives in
storage set by an initialiser, not in constructor arguments baked into bytecode. That makes its
deployed address **identical across deployments**, exactly like the account factory, and the
continuous-integration check that asserts address equality applies to it unchanged.

This reverses the earlier position, which assumed a non-upgradeable contract configured at
construction and therefore required a carve-out from that check. Upgradeability removed the
reason for the carve-out; the address is stable because nothing operator-specific is in the
bytecode.

The address must stay stable for a second reason now: it is the address tenants send money to.
Changing it means every tenant re-learns where to fund, and any payment already in flight to the
old address is lost.

### D11 — A fixed platform fee, set by Giano

Each sponsored transaction debits the tenant's balance for the gas it consumed **plus a fixed
fee**, and credits that fee to a treasury withdrawable only by the fee-collector role (D13).
Giano sets a deployment-wide default; individual tenants may be given a different rate, so volume
discounts, pilots and enterprise pricing are possible without a contract change.

Setting the rate and collecting the money are **separate roles**, so the party that decides what
tenants are charged is not automatically the party that can move the proceeds.

The rate in force is **pinned into each authorisation**, so a rate change cannot alter what an
already-authorised transaction charges, and a tenant can verify from the chain exactly what it
was charged and why.

The fee is charged whether the user's transaction succeeds or reverts. A reverted transaction
still consumed real gas that Giano's deposit paid for, and still consumed the service.

*Rejected:* a percentage markup on gas (self-tuning across chains and the industry norm, but
revenue becomes unpredictable and near zero on cheap networks); a margin taken at funding time
instead (no contract changes at all, but no per-transaction granularity and nothing a tenant can
audit).

*Consequence:* a fixed fee does not adapt across chains. On an expensive network it is a small
percentage of gas; on a cheap one it can be several times the gas cost. It needs deliberate
per-chain configuration, and that is an operational responsibility, not a one-time setting.

### D12 — Tenants own their balance and can withdraw it

Each tenant registers a withdrawal address on-chain. Only that address can withdraw that tenant's
unspent balance. **Giano cannot move tenant funds**, only its own accrued fees.

*Rejected:* operator-only withdrawal with refunds handled commercially (simpler, but a tenant's
prepaid balance would be a claim against Giano rather than their own money); tenant control with
an operator override (pragmatic, but the override would have to be disclosed and undermines the
guarantee that makes prepayment safe).

*Consequence:* tenants hold a key that matters. Losing it strands that balance permanently, since
by design nobody else can move it. This must be stated to tenants at onboarding, and key rotation
must be supported — see [Q2](#7-open-questions).

*Qualification, which must be stated to tenants rather than implied:* this guarantee holds against
every role in D13, but **not** against the upgrade authority, which can replace the logic that
enforces it. "Giano cannot take your funds" is therefore true of Giano's day-to-day operation and
conditional on the upgrade controls in D14. Anything stronger would be a claim the architecture
does not support.

### D13 — Every privileged action has its own named role. There is no owner.

The contract has **no owner and no superuser**. Each privileged action is gated by a distinct,
explicitly named role, granted independently:

| Role | May do | Notably may **not** |
|---|---|---|
| Signer admin | Add and revoke sponsorship signing keys | Move any funds |
| Fee admin | Set the fee rate and per-tenant overrides | Collect the fees it sets |
| **Fee collector** | Withdraw accrued treasury, up to the accrued amount | Change the rate; touch tenant balances |
| Stake admin | Add, unlock and withdraw the network stake | Touch the deposit or any balance |
| Tenant admin | Register tenants and their withdrawal addresses | Move a registered tenant's funds |
| Parameter admin | Set the overhead allowance and operational limits | Move funds |
| Pauser | Halt acceptance of new sponsorships | Move funds; alter configuration |
| Upgrader | Replace the implementation, subject to D14 | — (see the qualification above) |

Separating *fee admin* from *fee collector* is the point of the exercise generalised: deciding
what is charged and taking the proceeds are different powers and should be held separately, and
the same reasoning applies to every other pair in the table.

*Consequence, and it must not be glossed:* role separation is only real if whoever administers
roles cannot simply grant themselves the role they are separated from. A conventional
role-administration setup makes the administrator a superuser by another name and returns the
design to exactly what this decision rejects. The role-granting authority must therefore be
constrained — held by a multi-party account, subject to a delay, or both — and that constraint is
part of the requirement, not a deployment detail (R-46).

### D14 — The paymaster is upgradeable

The paymaster is deployed behind a proxy and its implementation can be replaced. It has to be:
it holds customer funds, it encodes a fee model that will change commercially, and it is coupled
to an EntryPoint version that will eventually move. A contract in that position cannot be
immutable — a defect found after tenants have funded balances would otherwise be unfixable, and
migration would mean moving everyone's money to a new address.

Upgradeability is consistent with the rest of the stack: Giano's smart wallet is already an
upgradeable proxy with namespaced storage, so the pattern and its discipline are established.

*Consequence, stated plainly:* **an upgrade can do anything, including taking tenant funds.** This
is the one power that overrides D12's guarantee, and no amount of role separation changes it. It
is a trust position, not a technical safeguard, so it must be constrained by process:

- The upgrade authority is its own role, held by a multi-party account, never by an individual
  operational key.
- Upgrades are subject to a **published delay**, long enough for a tenant that objects to
  withdraw its balance first. An upgrade a tenant cannot exit before is an upgrade they must
  simply trust.
- Every upgrade is announced and independently verifiable on-chain.

Storage layout discipline follows from holding balances: an upgrade that corrupts the ledger
destroys the accounting, and there is no recovery from a mis-ordered storage slot once real
funds are attributed by it.

### D15 — Wallet-management transactions are sponsored, and the platform decides that, not the tenant

Adding or removing a passkey, and account recovery, **are sponsored**. This reverses the earlier
position, which denied them unless a tenant opted in.

The reason is that these are the transactions a user is least able to pay for. A passkey is bound to
a device; the moment a user needs a second one is the moment they are holding a device with no
native token on it and no way to acquire any. An unsponsored recovery path is a recovery path that
does not work for the users who need it, and the sensitivity that argued for denying it by default
argues the other way once you notice that whoever holds the passkey already controls the wallet —
sponsoring the transaction grants no authority, it only pays for it.

Because it must be sponsored, it **cannot** be an entry in the tenant's allowlist. A tenant that
forgot to list its own wallet contract would silently break recovery for its users, which is exactly
the failure mode R-02's deny-by-default is right about everywhere else and wrong about here. So
wallet management is detected **structurally** — a call from the wallet to itself — and governed by
platform policy with its own platform-set cost cap. Structural detection cuts both ways and that is
the point: a self-administration function added later cannot become sponsorable by omission, and
cannot become *un*sponsorable by omission either.

*Still open ([Q1](#7-open-questions)):* whether the tenant or the platform bears the cost, and
whether a tenant may switch it off at all.

*Consequence:* every tenant now has a spend path it cannot remove from its own allowlist. The
platform cap and per-user limits (roadmap item 1) are what bound it; a tenant cannot.

### D16 — The signing key lives in an HSM in production, and in an environment variable only where nothing is at stake

Production signs with a key held in an **AWS HSM**, driven through Applied Blockchain's
[`evm-hsm-signer`](https://github.com/appliedblockchain/evm-hsm-signer), so the key that authorises
spending against customer funds never enters the service process. Local development and testnet sign
with a private key in an environment variable, because there the balances are worthless and the
convenience is what lets the demo stack provision itself without a credential (R-61).

*Rejected:* an environment variable everywhere (the worst blast radius of any option, for the
highest-value secret in the system); a self-managed HSM appliance (the same custody property, more
operational surface).

*Consequence, and it is a trap worth naming:* the two paths cannot be separated by `NODE_ENV`. A
testnet deployment legitimately runs as a production build, so the switch has to be an explicit
statement about the deployment's class, and the refusal has to be at configuration load rather than
at first signature.

---

## 4. Requirements

Numbered for traceability; [`specs/PAYMASTER-SPECS.md` §16](./PAYMASTER-SPECS.md#16-traceability)
maps each to its implementation.

### 4.1 The sponsorship decision

**R-01** — Sponsorship MUST be an explicit authorisation decision, taken per transaction, before
the user is asked to approve, and enforced on-chain. A client that bypasses the Giano backend
MUST NOT be able to obtain sponsorship.

**R-02** — The rules engine MUST **deny by default**. A tenant with no sponsorship configuration,
an empty one, or one that fails validation gets *no sponsorship* — never unrestricted
sponsorship.

**R-03** — A tenant MUST be able to specify exactly which contracts, and which functions on those
contracts, it will sponsor. A tenant MUST be able to allow an entire contract without listing
every function, but MUST NOT be able to express "any contract".

**R-04** — A tenant MUST be able to set a maximum cost for any single sponsored transaction.
Transactions above it are refused.

**R-05** — Transactions that manage the wallet itself — adding or removing a passkey, account
recovery — MUST be sponsored wherever sponsorship is enabled for the tenant, and MUST NOT depend on
the tenant having listed anything. A user acquiring a second device holds no native token and has no
way to obtain one, so an unsponsored recovery path does not work for the users who need it (D15).

**R-65** — Wallet management MUST be governed by **platform policy rather than by a tenant's
allowlist**. It MUST be detected structurally — a call from the wallet to itself — rather than by a
list of function names, so that a self-administration function added later can neither become
sponsorable nor become unsponsorable by omission. It MUST carry its own platform-set cost cap,
separate from the tenant's per-transaction cap. A tenant MAY be permitted to switch it off
explicitly, but MUST NOT be able to switch it off by leaving something out of a list. Whether that
opt-out is offered, and whether the tenant or the platform bears the cost, is
[Q1](#7-open-questions).

**R-06** — Every decision, whether allowed or refused, MUST be recorded with enough detail to
answer "why was this sponsored?", "why was this refused?" and "what was it charged?" — including
which individual rules passed and which failed.

**R-07** — An issued sponsorship MUST be usable exactly once, on one blockchain, for one
transaction, and MUST expire within minutes if unused.

### 4.2 Funding and segregation

**R-30** — Tenants MUST fund their gas balance explicitly, and every funding payment MUST be
attributable to exactly one tenant. Funds MUST NOT arrive un-attributed.

**R-31** — A tenant MUST NOT be able to spend another tenant's balance. This MUST be enforced
on-chain, not only by the Giano backend, so that a compromised or defective backend cannot cause
one tenant to consume another's funds.

**R-32** — Transactions authorised concurrently MUST NOT be able to collectively overdraw a
tenant's balance. Authorisation MUST account for transactions already in flight, not merely for
the balance at that instant (D5).

> **How this holds when the service runs several instances.** The concern is the right one to have:
> if each replica kept its own view of what was in flight, both would authorise against the same
> balance and R-32 would be satisfied nowhere. They do not keep one. There is exactly **one**
> reservation ledger, in the shared database, and no replica holds an in-process view of
> availability that could disagree with another's — `available = balance − reserved` is a query, not
> a cached number. The affordability test and the write happen inside a transaction holding a
> database **row lock on that tenant**, so the second request to arrive waits for the first to
> commit and then reads its reservation, whichever replica each arrived at. Balances are written by
> a single elected watcher and read by everyone, so a lag makes the cached balance *uniformly*
> stale rather than differently stale per instance — and the reservation ledger, which is what
> actually bounds authorisation, is not derived from the chain at all. Two places would reintroduce
> the problem if got wrong: signing before the reservation commits, and computing reservation expiry
> from the replica's own clock instead of the database's.
> [`PAYMASTER-SPECS.md` §7.6](./PAYMASTER-SPECS.md#76-why-this-holds-across-replicas) sets out the
> mechanism and both traps in full.

**R-33** — A tenant's unspent balance MUST be withdrawable by an address that tenant controls. No
role defined in D13 MUST be able to move a tenant's funds, individually or in combination. The
sole exception is the upgrade authority, which can replace the enforcing logic — constrained by
R-50 and R-51, and disclosed under R-54 rather than claimed away.

**R-34** — The accounting invariant — tenant balances plus Giano's treasury being **at most** the
paymaster's deposit — MUST hold at all times, MUST be independently verifiable from the chain,
and MUST be monitored. Any breach, meaning claims exceeding the deposit, is an insolvency and
MUST alert immediately. Slack in the safe direction is expected (D1), but MUST also be monitored:
slack growing faster than the overhead allowance predicts means tenants are being overcharged.

**R-35** — If a transaction settles for more than the balance remaining (possible only under the
concurrency case D5 describes), the shortfall MUST be recorded as an explicit deficit and
alerted. It MUST NOT be silently absorbed.

**R-36** — A tenant MUST be able to see its own balance, its outstanding reservations, its spend
history and the fees it has been charged, and reconcile them against the chain.

### 4.3 The platform fee

**R-37** — Each sponsored transaction MUST charge the tenant a fixed platform fee in addition to
the gas consumed, credited to a treasury separate from every tenant balance.

**R-38** — The fee MUST be configurable by the Giano administrator as a deployment-wide default,
with per-tenant overrides. It MUST NOT be configurable by tenants.

**R-39** — The fee in force MUST be pinned into each authorisation, so that changing the rate
cannot alter the charge for an already-authorised transaction, and so a tenant can verify each
charge from the chain.

**R-40** — The fee MUST be charged whether the user's transaction succeeds or reverts on-chain.

**R-41** — Settlement MUST debit the tenant for the network overhead that falls outside the cost
figure the contract is given — the accounting step's own gas, and the network's penalty on
over-estimated gas limits — **as a charge distinct from the fee, and not credited to the
treasury**. The allowance MUST be deliberately generous, so the ledger falls at least as fast as
the deposit (D1), and MUST be configurable per chain rather than fixed in code.

> This cannot be solved by making the fee larger. A fee moves value from a tenant balance to the
> treasury, and both sit inside the ledger, so it cancels out of the ledger total entirely and
> offsets none of the shortfall. Only a charge that *leaves* the ledger, mirroring the money that
> left the deposit, keeps the invariant intact. Getting this wrong is not lost margin; it is a
> ledger that slowly comes to promise more than the deposit holds.

**R-42** — Fees MUST be withdrawable, and it MUST be impossible to withdraw more than has
accrued. The cap is what makes R-33 true: without it, the withdrawal path reaches tenant funds.

**R-43** — The fee actually charged MUST equal gas consumed plus the pinned fee plus the overhead
allowance, and each component MUST be separately visible in the record, so a tenant can see what
was gas, what was Giano's margin, and what was overhead.

### 4.4 Roles and authority

**R-44** — Every privileged on-chain action MUST be gated by a distinct, explicitly named role.
The contract MUST NOT have an owner, a superuser, or any single account able to perform every
privileged action.

**R-45** — Collecting fees MUST be a role of its own, separate from setting the fee rate and from
every other role. Holding it MUST NOT confer any other capability.

**R-46** — The authority that grants and revokes roles MUST NOT be able to grant itself a role it
does not already hold without the same constraints that protect that role. It MUST be held by a
multi-party account, subject to a delay, or both — otherwise the separation in R-44 is nominal.

**R-47** — Every role assignment, revocation and privileged action MUST emit an on-chain event, so
who did what is reconstructible from the chain alone rather than from Giano's records.

**R-48** — No role MUST be able to move a tenant's balance. This MUST hold for every role
individually and for any combination of them, subject only to R-51.

### 4.5 Upgradeability

**R-49** — The paymaster MUST be upgradeable, deployed behind a proxy, at an address that does not
change across upgrades. Tenants fund that address; it MUST remain stable.

**R-50** — Upgrade authority MUST be its own role, MUST be held by a multi-party account, and MUST
NOT be held by any key used in day-to-day operation.

**R-51** — Upgrades MUST be subject to a published delay long enough for a tenant that objects to
withdraw its balance before the upgrade takes effect, and MUST be announced in advance. This
delay is the only meaningful protection tenants have against the upgrade power, and it MUST NOT
be bypassable — including for changes presented as urgent.

**R-52** — Upgrades MUST preserve tenant balances, treasury and every reservation exactly.
Storage layout compatibility MUST be verified mechanically before any upgrade is proposed, not
reviewed by eye.

**R-53** — Tenant withdrawal MUST remain available while the contract is paused. A pause is for
halting new sponsorship, and MUST NOT trap funds.

**R-54** — The limits of the custody guarantee MUST be documented for tenants: that no role can
take their funds, that the upgrade authority can, and what constrains it. This MUST be in the
tenant-facing documentation, not only here.

### 4.6 Tenant configuration

**R-08** — Tenants MUST be able to change their own sponsorship rules through the existing
authenticated admin API, taking effect without a redeployment or operator involvement.

**R-09** — Sponsorship MUST be switchable off per tenant. A tenant with it off MUST fall back
cleanly to the existing unsponsored behaviour, not to an error.

**R-10** — Configuration MUST be validated when written, and rejected if malformed, so that an
invalid rule set is never silently interpreted as permissive.

### 4.7 Authentication and tenant isolation

**R-11** — A sponsorship request MUST carry a valid wallet session. Unauthenticated requests get
nothing.

**R-12** — A session belonging to one tenant MUST NOT be usable to obtain sponsorship from
another tenant. Cross-tenant attempts MUST be counted and alertable, and the response MUST NOT
reveal whether the other tenant exists.

**R-13** — A sponsorship MUST only be issued for the requesting session's **own** wallet.

**R-14** — The blockchain and the EntryPoint contract MUST be taken from server configuration and
never from the request, matching the convention already used on the relay path.

### 4.8 User experience

**R-15** — A refusal MUST be surfaced **before** the approval screen. No approve button, and no
passkey prompt, for a transaction that will not be sponsored.

**R-16** — Refusals MUST carry a stable, machine-readable reason. At minimum the wallet must be
able to distinguish: the contract or function is not allowed; the transaction is too expensive;
**the tenant has insufficient balance**; sponsorship is temporarily unavailable; sponsorship is
switched off for this tenant; and, where the opt-out of R-65 exists, wallet management is switched
off for this tenant.

**R-17** — The reason MUST be both displayed to the user and written to the browser console. A
transient notification is not sufficient.

**R-67** — Refusal copy MUST name the party who can act. A user meeting a refusal can do nothing
about it themselves — they cannot fund a tenant's balance or edit its allowlist — so the text MUST
make clear that the application's operator is who resolves it, rather than implying a user action
that does not exist. This is [Q7](#7-open-questions)'s answer, and it is why no dApp-facing
pre-flight check is required in v1: the refusal is shown where the user already is, in words that
tell them what it means.

### 4.9 Availability and resilience

**R-18** — Each tenant's available balance MUST be monitored, with a configurable low-balance
alert to that tenant and to the operator, and a clear refusal on exhaustion rather than a
transaction that fails after the user has authenticated.

**R-19** — There MUST be a fast, deployment-wide way to stop issuing sponsorships immediately,
without a redeployment. This is the primary response to a suspected key compromise.

**R-20** — It MUST be possible to rotate the signing key with no downtime and no redeployment.

**R-66** — In production the signing key MUST be held in an HSM and MUST NOT be readable by the
service process. An environment-variable key MAY be used for local development and testnet only,
and configuration MUST refuse it for a production deployment at load time. The refusal MUST be
keyed on an explicit statement of the deployment's class, **not** on `NODE_ENV`, because a testnet
deployment legitimately runs as a production build (D16).

**R-21** — The sponsorship service is on the **critical path for transacting**: if it is
unreachable, sponsored tenants cannot transact at all, where today they would merely lose the
audit gate. This MUST be reflected in health checks and monitoring, and the wallet MUST
distinguish "refused by the rules" from "service unreachable" so an outage is not mistaken for a
misconfiguration.

### 4.10 Interoperability

**R-22** — The sponsorship interface MUST follow ERC-7677, so that a tenant running its own
wallet interface can use it with standard tooling.

**R-23** — The interface MUST be documented in the tenant-facing integration guide, including
funding, withdrawal and fees. A tenant that cannot obtain sponsorship is not a working tenant.

### 4.11 Operations

**R-24** — A deployment MUST NOT be considered complete until the paymaster is staked and at least
one tenant balance is funded. A paymaster that is deployed but not staked fails in a way that
looks like a client bug.

**R-25** — Decisions, refusals, per-tenant balances and spend, fee accrual and signing activity
MUST be observable, with alerts for: low tenant balance, invariant divergence, deficits, signing
stopped, an unusual spike in refusals for one tenant, and any signature issued by an unexpected
key.

**R-26** — Attributed spend MUST be periodically reconciled against actual on-chain deposit
drawdown, and divergence alerted. An unexplained drawdown means sponsorships are being issued
that the backend did not record.

**R-27** — An operational runbook MUST cover: onboarding and funding a tenant, rotating the
signing key, using the emergency stop, changing the fee, withdrawing the treasury, the unstaking
delay, the clock-synchronisation requirement on the signing service, who holds each role in D13,
and the upgrade procedure including the announcement and delay (R-51).

**R-55** — Role holders MUST be documented and periodically reviewed, and the review MUST verify
that R-46's constraint on the granting authority actually holds in the deployment rather than
only in this document. A role separation that exists on paper and not on-chain is worse than
none, because it is relied upon.

### 4.12 End-to-end coverage and the demo stack

**R-56** — The end-to-end suite MUST exercise the **production** paymaster, and MUST assert the
accounting rather than merely that the transaction succeeded: the tenant's balance debited by gas
plus fee plus overhead, the fee credited to the treasury, and the invariant (R-34) intact at the end
of every scenario. A sponsored transaction that lands is not evidence that the ledger is right.

**R-57** — The suite MUST cover at least the following, each as an observed outcome rather than a
mocked one:

| Scenario | MUST assert |
|---|---|
| Sponsored transaction, stock wallet UI | Receipt; balance debited by gas + fee + overhead; treasury credited the pinned fee; invariant intact |
| Sponsored transaction, bring-your-own wallet UI | The same, through a tenant's own interface (R-63) |
| Contract not on the allowlist | Refused before approval; distinct reason; nothing charged |
| Function not allowed on an allowed contract | Refused; a reason distinguishable from the above (R-16) |
| Cost above the tenant's per-transaction cap | Refused; distinct reason (R-04) |
| Insufficient balance | Refused naming exhaustion, not a generic failure (R-16, R-18) |
| Wallet management — adding a passkey | Sponsored with no allowlist entry for it, under the platform cap; refused only where the tenant has explicitly opted out (R-05, R-65) |
| Concurrent authorisations that would collectively overdraw | The overdrawing one is refused **before** a signature is issued, and no deficit is recorded (R-32) — asserted with the requests arriving at more than one service instance, since a single-process run cannot demonstrate the property |
| An authorisation used twice, and one used after expiry | Both rejected on-chain; nothing debited (R-07) |
| Tenant funding and withdrawal | Balance moves; only the registered withdrawal address can withdraw (R-33) |
| Withdrawal while the paymaster is paused | Withdrawal succeeds; new sponsorship is refused (R-19, R-53) |
| Signing-key rotation during the run | Sponsorship continues with no downtime and no redeployment (R-20) |
| Sponsorship switched off for a tenant | Falls back cleanly to the unsponsored path, not to an error (R-09) |
| A session from one tenant used against another | Refused as a plain authentication failure, and counted (R-12) |
| Sponsorship service unreachable | The wallet reports an outage, distinguishably from a refusal (R-21) |

**R-58** — Refusals MUST be asserted where the user meets them, not only at the API: the test MUST
verify that no approve button and no passkey prompt were presented (R-15), and that the typed reason
was both displayed and written to the browser console (R-16, R-17).

**R-59** — The demo dApp MUST transact through the production paymaster by default, so that what is
demonstrated is the path real tenants use — rules enforced, balance debited, fee charged — rather
than a permissive fixture that cannot fail.

**R-60** — The demo and end-to-end stack MUST provision itself. Bringing it up with a **single
command** MUST deploy, stake and fund the paymaster, register the demo tenants and their withdrawal
addresses, and install a working sponsorship configuration, with no manual step, no interactive
prompt and no operator-supplied secret. If provisioning cannot complete, bring-up MUST fail loudly
rather than start in a state where sponsorship silently does not work.

**R-61** — Provisioning MUST be deterministic and self-contained: fixed addresses, no faucet, no
external funding, no dependency on anything beyond the local devnet — so the stack behaves
identically on a developer machine and in continuous integration, and a first run needs no
credentials.

**R-62** — Convenience MUST NOT leak into production. Whatever mechanism pre-configures a demo
tenant's sponsorship MUST be unavailable in a production deployment, and a real tenant with no
configuration MUST still get no sponsorship (R-02). See [Q5](#7-open-questions).

**R-63** — Both the stock wallet interface and the bring-your-own-UI tenant MUST be covered by
sponsored-path and refusal tests, because the pre-approval refusal (R-15) is wallet-side behaviour
that each implementation has to get right separately.

**R-64** — Sponsorship coverage MUST NOT be paid for by the rest of the suite: fixtures whose
subject is not sponsorship MUST keep passing without a funded balance or a configured allowlist
(R-28), so a change to a sponsorship rule cannot break tests that have nothing to do with it.

---

## 5. Security posture

### 5.1 Why the scheme holds

Two signatures are involved, each covering what the other cannot. The Giano backend signs the
parts of the transaction that determine its cost and its intent — who is sending it, what it
calls, how much gas it may consume, **which tenant pays, and what fee applies**. The user's
passkey then signs the whole transaction, *including* the sponsorship. Neither can be altered
afterwards without invalidating one of them.

Binding the tenant into the backend's signature is what stops an end user from redirecting the
charge to a different tenant's balance — the user controls their own passkey, so anything the
backend does not sign is something the user could otherwise choose freely.

A sponsorship cannot be reused: it is tied to a single wallet, a single transaction sequence
number and a single blockchain, and it expires within minutes.

### 5.2 What an attacker gets

| Attacker capability | Consequence | Bounded by |
|---|---|---|
| A passkey on tenant T | Can spend T's balance on T's allow-listed contracts | Allowlist, per-transaction cap, **T's balance** |
| The same passkey, on wallet management | Can have its own wallet's passkey changes sponsored, which T cannot deny by allowlist (R-65) | Platform wallet-management cap, **T's balance**. It confers no authority: whoever holds the passkey already controls that wallet |
| A stolen session token | The same, for that one user's wallet | Session lifetime, sender binding (R-13) |
| Ability to forge the origin header | Nothing — an authenticated session is still required | D9 / R-11 |
| **The signing key** | Can drain **every tenant's balance**, up to each tenant's own funds | Per-tenant balances, emergency stop (R-19), key revocation. **Not** the treasury |
| Compromise of the Giano backend | As above, plus forged reservations | As above, plus invariant monitoring (R-34) |
| A tenant's own withdrawal key | Can withdraw that tenant's unspent balance | That tenant's balance only |
| The fee-collector role | Withdraw accrued fees only | The accrued amount; cannot reach tenant balances (R-42) |
| The fee-admin role | Change what tenants are charged going forward | Cannot collect it, and cannot alter already-authorised charges (R-39) |
| Any single other role | Its own narrow capability | R-48 — no role, and no combination of roles, moves a tenant balance |
| **The upgrade authority** | **Everything, including taking tenant funds** | Multi-party control and a published exit delay (R-50, R-51). Process, not code |

The last row is the honest ceiling on the custody guarantee. Every other row is bounded by
something the contract enforces; that one is bounded by who holds the keys and how long tenants
have to leave. It is why R-54 requires saying so to tenants rather than letting "Giano cannot
take your funds" stand unqualified.

Segregation improves the picture but does not transform it: a compromised signer still reaches
every tenant, because one key authorises for all of them. What it can no longer do is overdraw
any single tenant, or touch Giano's accrued fees. Per-tenant signing keys would fix the rest, and
are on the roadmap.

---

## 6. Accepted limitations and roadmap

### 6.1 Accepted in v1

**Sponsored transactions cost more gas.** Per-tenant accounting means the contract does work after
every transaction. That cost is charged to the tenant and must be pre-funded, which also raises
the effective minimum for the per-transaction cost cap.

**One tenant running dry can affect others.** When a tenant exhausts its balance, its transactions
start failing validation on the network. Those failures accrue against the *shared* paymaster's
standing with transaction bundlers, which affects every tenant. The reservation ledger (D5) is
what keeps deployments away from that edge; the coupling itself is structural to a shared
contract.

**Concurrency deficits are possible, not impossible.** The reservation ledger prevents them in
normal operation, but a backend defect could still authorise beyond a balance. The contract
clamps and alerts (R-35) rather than reverting, so the failure is visible and bounded rather than
silent — but it is absorbed from the pooled deposit when it happens.

**A fixed fee does not adapt across chains.** It must be tuned per deployment, and revisited when
gas conditions change materially.

**No per-user limits.** A single compromised or abusive passkey inside a tenant can consume as
much of that tenant's balance as the allowlist and per-transaction cap permit. Wallet management
(D15) makes this slightly sharper: it is a spend path a tenant cannot remove from its own
allowlist, bounded only by the platform cap until per-user limits exist.

**Tenants hold a balance per chain.** Each blockchain is a separate paymaster deployment, separately
staked, separately funded and separately fee-tuned, so a tenant operating on two chains funds and
monitors two balances. This is accepted rather than solved ([Q6](#7-open-questions)).

**Custody rests on process, not only on code.** The upgrade authority can replace the logic that
protects tenant balances (D14). Multi-party control and a published exit delay are real
mitigations, but they are governance rather than a guarantee the contract can enforce against
itself. Tenants are trusting Giano's upgrade process, and must be told so plainly (R-54).

**Roles are only as separate as the granting authority allows.** R-46 constrains whoever grants
roles, but a deployment that ignores it collapses every distinction in D13 back into a single
superuser while still looking role-separated on-chain. This is a deployment-time property that
review must actually check.

### 6.2 Roadmap

1. **Per-user rate and spend limits**, so one wallet cannot exhaust its tenant's balance — and so
   the wallet-management path a tenant cannot switch out of its allowlist (D15) is bounded per user
   rather than only per transaction.
2. **Percentage or tiered fees**, removing the per-chain tuning burden of a fixed fee.
3. **Per-tenant signing keys**, so a compromised key reaches one tenant rather than all of them.
   Now genuinely achievable, because the contract already knows which tenant a transaction bills.
4. **A dedicated rules subsystem** with a full "who allowed this contract, and when" audit trail.
5. **ERC-20 gas payment** — users paying in tokens rather than being sponsored. Orthogonal to this
   work, but shares the same contract foundation.
6. **Automated tenant top-up**, so a tenant can authorise replenishment rather than monitoring a
   balance manually.

---

## 7. Open questions

Q3, Q5, Q6 and Q7 have since been answered; their numbering is kept because other documents cite
it, and the answer is recorded in place. Q1 has been narrowed rather than closed. Q2 and Q4 are
open as written.

**Q1 — For wallet management, who pays, and may a tenant switch it off?** The question of *whether*
these transactions are sponsorable is settled: they are (R-05, D15), and the policy is the
platform's rather than an allowlist entry (R-65), because a category that must be sponsored cannot
be gated by a list a tenant might leave empty. Two parts remain.

*Who pays.* Charging the tenant needs no new mechanism and is what the specification implements.
Having the platform pay is arguably fairer — a recovery delivers the tenant no application value —
but it needs a platform-funded balance alongside the tenant balances, an extension of the accounting
invariant to include it, a payer flag signed into each authorisation so the chain charges whoever the
service decided, and a decision that no platform fee applies. It also reintroduces a shared pot at
small scale: one tenant's users' recoveries would draw on a balance every tenant depends on, which is
the coupling D1 rejected, and it would need per-user rate limits to bound.

*Opt-out.* A tenant paying for recovery it did not ask for has a reasonable case for switching it
off; a tenant that switches it off has users who cannot recover. Whichever way this goes, R-65
forbids it happening by omission.

**Needs a product decision.**
[`PAYMASTER-SPECS.md` §6.6](./PAYMASTER-SPECS.md#66-if-the-platform-pays-for-wallet-management)
implements tenant-paid with an explicit opt-out and sets out exactly what changes if the platform
pays instead.

**Q2 — What happens when a tenant loses its withdrawal key?** D12 deliberately makes Giano unable
to move tenant funds, which is the property that makes prepayment safe — and it means a lost key
strands that balance permanently. Options are supporting key rotation while the current key still
works (necessary regardless), accepting permanent loss as the price of the guarantee, or a
disclosed time-locked recovery path. **Needs a product and legal decision**, and it must be
settled before tenants are onboarded rather than after.

**Q3 — Where does the signing key live? — ANSWERED.** Production holds it in an **AWS HSM**, driven
through Applied Blockchain's
[`evm-hsm-signer`](https://github.com/appliedblockchain/evm-hsm-signer), so the key never enters the
service process. Local development and testnet use a private key in an environment variable, where
the balances at risk are worthless and the convenience is what lets the demo stack provision itself
without a credential (R-61). Recorded as D16 and required by R-66. One consequence has to be
carried into the implementation: the gate between the two paths cannot be `NODE_ENV`, because a
testnet deployment runs as a production build —
[`PAYMASTER-SPECS.md` §9.1](./PAYMASTER-SPECS.md#91-interface) says what it is instead.

**Q4 — How does a tenant top up, in practice?** The contract accepts native-token funding from any
address. Whether tenants are expected to hold and send the native token themselves, or Giano
offers to fund on their behalf against a fiat invoice, is a commercial and compliance question
rather than a technical one — but it determines what onboarding looks like.

**Q5 — Should new tenants ship with an example configuration? — ANSWERED: no.** A new tenant gets
no sponsorship configuration and therefore no sponsorship, which is R-02 working as intended. The
"sponsorship is broken" misreading is a documentation problem and is fixed in the onboarding
documentation (R-23) rather than by seeding a row nobody asked for — a seeded example is one more
thing to keep out of production (R-62) and one more state a tenant can be surprised by. The demo
stack's own working configuration is unaffected: it is written through the real admin API like any
tenant's (R-60, R-62).

**Q6 — How many blockchains? — ANSWERED: as many as needed, and per-chain balances are expected.**
Each blockchain is its own paymaster deployment, separately staked, with its own per-tenant balances
and its own fee tuning, and a tenant operating on two chains funds and monitors two balances. That
is accepted as the shape of the product rather than treated as a problem to design away; it is
recorded as an accepted limitation in [§6.1](#61-accepted-in-v1). The ledger and configuration are
chain-keyed from the start so nothing has to be retrofitted.

**Q7 — Is a dApp-facing pre-flight check needed? — ANSWERED: no.** The popup is the right place for
the refusal, and its job is to show the user the **specific** reason rather than a generic failure.
The user cannot resolve any of these conditions — they cannot fund a tenant's balance or edit its
allowlist — so the copy has to say what is wrong and make clear that the application's operator is
who fixes it. That is R-67. The wallet's own review screen still evaluates the rules before it
renders an approve button, which is R-15 and unchanged; what is not being built is a second,
dApp-facing "would this be sponsored?" surface, and with it the risk of a second rules
implementation that drifts.

---

## 8. Glossary

| Term | Meaning |
|---|---|
| **Tenant** | One customer of a Giano deployment. In Giano a tenant is one wallet origin and one passkey relying party, one-to-one |
| **Paymaster** | An on-chain contract that pays transaction fees on a user's behalf |
| **Validating paymaster** | A paymaster that pays only when presented with an authorisation signature from a designated signer — also called signed sponsorship |
| **Deposit** | The funds the paymaster holds with the network's EntryPoint contract, from which sponsored fees are drawn. Shared by all tenants, apportioned by the ledger |
| **Tenant balance** | A tenant's share of the deposit, recorded by the contract. Spendable only by that tenant, withdrawable only by that tenant |
| **Treasury** | Accrued platform fees. Withdrawable only by the fee-collector role, capped at what has accrued, and never at the expense of a tenant balance |
| **Overhead allowance** | A charge covering network costs the contract cannot observe at settlement — its own accounting gas, and the network's penalty on over-estimated gas limits. Debited from the tenant but *not* credited to the treasury, so it leaves the ledger the way the money left the deposit |
| **Role** | A named, independently granted permission to perform one class of privileged action. The contract has no owner: every privileged action belongs to a role |
| **Upgrade authority** | The role able to replace the contract's logic. The one power that can override the custody guarantee, constrained by multi-party control and a published delay rather than by the contract itself |
| **Reservation** | Funds set aside when a sponsorship is authorised, released when the transaction settles or the authorisation expires. What prevents concurrent transactions from overdrawing |
| **Available balance** | Balance minus outstanding reservations — what a new transaction may actually draw on |
| **Stake** | Funds the paymaster locks as a good-behaviour bond, required by the network before a paymaster may make certain kinds of decision. Distinct from the deposit |
| **UserOperation** | The account-abstraction equivalent of a transaction: which wallet, calling what, with what gas limits |
| **EntryPoint** | The standard on-chain contract that executes UserOperations and settles payment |
| **ERC-7677** | The standard interface between a wallet and a paymaster service |
| **Passkey** | The user's device-held credential. In Giano it is the wallet's identity and its signing key |
| **Wallet management** | A transaction the wallet sends to itself — adding or removing a passkey, recovery, upgrading itself. Sponsored under platform policy rather than a tenant allowlist, and detected structurally rather than by function name |
| **HSM** | The hardware-backed key store holding the sponsorship signing key in production. The service asks it for a signature and never sees the key |

---

## Related documents

- [`specs/PAYMASTER-SPECS.md`](./PAYMASTER-SPECS.md) — the technical specification implementing
  these requirements
- [`specs/INTEGRATION.md`](./INTEGRATION.md) — the tenant-facing integration contract, which must
  gain the sponsorship interface, funding and fees (R-23)
- [`specs/TRANSACTION-SUBMISSION-FLOW.md`](./TRANSACTION-SUBMISSION-FLOW.md) — the multi-tenant
  transaction path this modifies. Its "Sponsorship" section describes the current permissive
  behaviour and will need updating
- [`specs/DEVELOPER-GUIDE.md`](./DEVELOPER-GUIDE.md) — local environments, which must deploy,
  stake and fund the paymaster
