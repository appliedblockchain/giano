# Giano — Gaps to Production Readiness

**Audience:** management / decision-makers
**Date:** 2026-07-23
**Purpose:** A plain-language inventory of what still stands between Giano and a production
deployment holding real user value. Each gap notes *what it is*, *why it matters*, and — where it
only applies to certain deployments — *which use case it is relevant for*.

---

## Where Giano stands today

Giano has moved a long way from a proof-of-concept. The heavy engineering is largely done:

- **The architecture is sound and complete.** Giano is a passkey (Face ID / fingerprint) smart
  wallet where the user's dApp never touches wallet secrets — all sensitive logic lives on a
  separate, isolated "wallet origin." This is the same trust model as Coinbase's wallet, and it is
  fully built.
- **All the moving parts exist:** the smart contracts, the wallet backend service, the wallet UI,
  the thin integration kit for customer apps, and the transaction bundler are all implemented and
  wired together.
- **It is packaged to be self-hosted.** Everything ships as Docker images and a Helm chart, so a
  customer runs Giano inside their own infrastructure. Deployment guides, a verification tool
  (`giano-doctor`), secrets inventory, and an upgrade policy all exist and are well-documented.
- **Quality gates are in place:** automated testing, continuous integration, an end-to-end test
  suite, and a check that guarantees wallet addresses stay consistent across chains.
- **The security defaults are conservative.** User registration is locked down by default, sessions
  are short-lived and revocable, and no private keys are ever exposed to the browser or the
  customer's app.

The remaining gaps are **not** about missing features — they are about the last steps that turn a
technically-complete system into one safe to run with real money and real customers. They fall into
three buckets: **blockers for handling real value**, **blockers for shipping to customers**, and
**operational maturity**.

---

## Tier 1 — Blockers before real value / mainnet

These must be resolved before Giano guards anything of value on a public network.

### 1. No independent security audit of the contracts
**What:** The smart contracts (which hold and move user funds) have never been reviewed by a
third-party security firm. They are based on Coinbase's audited wallet, but Giano's own additions —
the multi-owner logic, the passkey verification path, and custom modules — have not been audited.

**Why it matters:** Smart-contract bugs are irreversible and can drain every wallet at once. No
serious project puts an unaudited wallet contract in front of real value. This is the single highest
risk item.

**Relevant to:** any deployment on a live network holding real assets. Not required for internal
demos or testnets.

### 2. No production gas-sponsorship (paymaster)
**What:** "Gas sponsorship" lets users transact without holding crypto to pay fees — a core selling
point of the passkey UX. Today only a **testing** sponsor ships, and it pays for *anything from
anyone* with no limits. A real, policy-controlled sponsor does not exist yet and must be built and
funded per deployment.

**Why it matters:** Deploying the testing sponsor to production is an open invitation for attackers
to drain the fee budget. Any customer who wants the "gasless" experience needs a production sponsor
with spending rules first.

**Relevant to:** every use case that offers gasless / sponsored transactions (i.e. the main
consumer-friendly experience). Deployments where users pay their own gas can skip it.

### 3. Self-hosted transaction bundler is unproven on public networks
**What:** The "bundler" is the piece that actually submits transactions to the blockchain. In
production, transactions have historically only cleared through **Coinbase's managed bundler**.
Giano ships its own self-hosted bundler, but it has only been validated in a relaxed mode that skips
some of the strict validation a production network enforces — and the root cause of past failures
with non-Coinbase bundlers was never documented.

**Why it matters:** If the self-hosted bundler doesn't work reliably in strict mode, every customer
either silently depends on Coinbase (undermining the whole "self-hosted, no third-party dependency"
promise) or can't operate on chains Coinbase doesn't support.

**Relevant to:** any deployment that wants true independence, or that targets a chain Coinbase's
bundler doesn't cover. Deployments content to rely on a managed bundler (Coinbase/Pimlico) are less
affected — but that dependency should be a conscious decision, not a surprise.

### 4. No account recovery story
**What:** If a user loses their device or passkey, there is no built-in way to recover their wallet.
The underlying contracts support multiple owners (a backup could be added), but no recovery *flow* or
UX has been productized.

**Why it matters:** For consumer products, lost-device recovery is table stakes — without it, a lost
phone can mean permanently lost funds, which is both a support nightmare and a reputational risk.

**Relevant to:** consumer-facing use cases. Less critical where wallets are managed/custodied by the
customer's backend or are disposable.

---

## Tier 2 — Blockers before shipping to external customers

These block Giano being consumed cleanly by a third party as a product.

### 5. The developer packages have not been published
**What:** The integration kit a customer app installs (and its supporting packages) are still
pre-release (version 0.x) and have never actually been published to a registry. Only the contracts
package has ever been released. A batch of version bumps is staged but not shipped.

**Why it matters:** Until these are published and versioned, a customer cannot simply "install
Giano" — they'd have to build from source, which contradicts the whole distribution model. The
release pipeline is built; it just hasn't been run.

**Relevant to:** every external integration. Internal use from the monorepo is unaffected.

### 6. Packages are published privately, not to public npm
**What:** The packages are configured to publish to a private GitHub registry, requiring customers to
authenticate with a token — and routing the entire `@appliedblockchain` scope there, which can
conflict with pulling other public packages.

**Why it matters:** This adds friction for external adopters and needs a deliberate decision: keep it
private (fine for controlled clients) or publish publicly (needed for open distribution).

**Relevant to:** open or self-service distribution. Fine as-is for a small set of managed clients.

### 7. Legacy "embedded" mode still ships and is only deprecated — **RESOLVED**
**What:** The older model — where the customer's app *was* the wallet — used to ship alongside the
new one behind the deprecated `./embedded`, `./web` and `./node` connector subpaths.

**Resolution:** Those subpaths were removed before 1.0.0 and the connector no longer depends on
`giano-wallet-core`, so a dApp bundle cannot reach WebAuthn, credential-storage or bundler code at
all. Only the thin SDK ships. Migration notes for 0.x integrations remain in
`packages/connector/README.md`.

---

## Tier 3 — Operational maturity

Not strictly blockers, but expected before running a serious production service.

### 8. Cross-browser and mobile coverage is thin
**What:** Automated end-to-end testing only covers Chrome. Safari and Firefox get a partial smoke
test, and there is no native mobile (iOS/Android app) story — only mobile web.

**Why it matters:** Passkeys behave differently across browsers and platforms; Safari in particular
has strict popup rules. Untested paths are where real users hit failures.

**Relevant to:** any consumer product with a broad user base; especially mobile-heavy audiences.

### 9. Backup / disaster-recovery guidance is missing
**What:** The wallet backend stores critical data (credential records, sessions). There is no
documented backup, restore, or disaster-recovery runbook.

**Why it matters:** Losing that database could lock users out of their wallets. Customers running the
stack need clear guidance on protecting it.

**Relevant to:** every production deployment.

### 10. Monitoring exists, but deeper observability is limited
**What:** Basic health checks and metrics are in place (good), but there is no distributed tracing to
diagnose slow or failing transactions end-to-end.

**Why it matters:** When a sponsored transaction silently fails, tracing is what lets operators find
out why quickly. Nice-to-have, not a blocker.

**Relevant to:** higher-scale or SLA-bound deployments.

### 11. Configuration "fails open" if misconfigured
**What:** A few security controls (which app origins may connect, cross-origin rules) default to
permissive when left blank, intended for local development. Rate limiting is applied only to
specific endpoints rather than globally.

**Why it matters:** The whole security model depends on these being configured correctly. A rushed or
incomplete deployment could unknowingly leave the door open. Documentation flags this, but it relies
on operators reading carefully — safer defaults or a startup check would reduce risk.

**Relevant to:** every production deployment; a checklist/guardrail issue more than a missing feature.

### 12. Minor loose ends
**What:** A handful of small items: one wallet capability (programmatic chain-switching) is a
placeholder; one signature-expiry value is hardcoded rather than configurable; and demo bundler API
keys that leaked into git history still need rotating.

**Why it matters:** Individually minor, but the key rotation is a genuine security hygiene task, and
the others may surface for specific integrations.

**Relevant to:** varies; the key rotation applies to everyone (it's a one-time housekeeping task).

---

## Suggested order of attack

| Priority | Gap | Rationale |
| --- | --- | --- |
| **1** | Security audit (#1) | Long lead time; blocks all real-value use. Start now. |
| **1** | Production paymaster (#2) | Blocks the flagship gasless experience. |
| **1** | Bundler validation (#3) | Determines whether "self-hosted" is real or a Coinbase dependency. |
| **2** | Account recovery (#4) | Needed for any consumer product; design work should start early. |
| **2** | Publish packages (#5, #6) | Unblocks external adoption; pipeline already exists. |
| **3** | Operational maturity (#8–#12) | Harden and polish once the above are underway. (#7 is done.) |

---

## Bottom line for management

Giano is **architecturally complete and well-documented** — the hard engineering is done, and the
team has been transparent about its own gaps (much of this is already flagged in the repo's own
docs). What remains is the maturity work that separates a working system from a production one:

- **Two items gate any real-money launch and have external dependencies (time and cost):** a
  **security audit** and a **production gas sponsor**. These should start immediately.
- **One item is a strategic question to resolve:** whether the self-hosted bundler is proven, or
  whether Giano knowingly leans on a managed bundler provider.
- **One item is a product decision:** how users recover a lost device.
- **The rest is packaging and operational polish** — mostly quick wins, since the pipelines and
  patterns already exist.

None of the remaining gaps require re-architecting. They are finishing work — but the audit and
paymaster items in particular carry real lead time and should be scheduled now rather than treated as
last-mile tasks.
