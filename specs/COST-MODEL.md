# Giano Cost Model & Breakeven

**What it costs to run Giano as an internal standalone service, and how many paying clients it takes
to break even.**

Status: draft · Last updated 2026-07-27 · Owner: Giano team
Companion document: [`docs/PRODUCT-STRATEGY.md`](./PRODUCT-STRATEGY.md)

> **All figures are AWS `eu-west-1` on-demand list prices as of 2026-07-27, and are illustrative.**
> Every line shows its unit price so it can be re-derived. Nothing here is a quote. See
> [§8](#8-assumptions-and-how-to-refresh) for how to refresh.

---

## Contents

- [1. The three cost pools](#1-the-three-cost-pools)
- [2. Reference architecture](#2-reference-architecture)
- [3. Why a shared substrate is the whole ballgame](#3-why-a-shared-substrate-is-the-whole-ballgame)
- [4. Itemised infrastructure cost](#4-itemised-infrastructure-cost)
- [5. Gas and sponsorship (Pool C)](#5-gas-and-sponsorship-pool-c)
- [6. Breakeven](#6-breakeven)
- [7. Cost levers](#7-cost-levers)
- [8. Assumptions and how to refresh](#8-assumptions-and-how-to-refresh)

---

## 1. The three cost pools

The single most important thing in this document is that these three pools must never be mixed.

| Pool | Nature | Scales with | Who pays |
|---|---|---|---|
| **A — Platform infrastructure** | Fixed monthly, shared across all clients | Nothing | Us, recovered via subscription |
| **B — Per-client infrastructure** | Fixed monthly, per client | Client count | Us, recovered via subscription |
| **C — Gas & sponsorship** | Variable, effectively unbounded | Transaction volume × gas price | **Pass-through. Prepaid client deposit. Never bundled.** |

**Breakeven is computed on A + B only.**

Pool C is not a cost of running the service; it is a cost of the client's users transacting. On
Ethereum Mainnet a single sponsored transaction can cost more than a full day of platform
infrastructure ([§5](#5-gas-and-sponsorship-pool-c)). Folding it into a subscription is the
straightforward way to lose money on this: one client with an active user base would consume the
entire margin from the other two.

The mechanism for keeping them separate already exists in the codebase — see
[§5.4](#54-controlling-pool-c).

---

## 2. Reference architecture

Constraints: cheap but reliable, no Kubernetes, all stateful services managed, minimal maintenance.

```
   NOT OUR INFRASTRUCTURE                 │  OURS
                                          │
   wallet.keo.com  (Tier B)               │   Route53 ─ ACM ─ ALB (one, host-based routing)
   KEO hosts its own wallet origin ───────┼──────────────┐
   → no wallet-web cost for us            │              │
                                          │   ┌──────────┴──────────┐
   wallet.acme.example.com (Tier A) ──────┼──►│ wallet-web  (S3+CF) │  ← per Tier A client
                                          │   │ wallet-api  (ECS)   │  ← per client, always
                                          │   └──────────┬──────────┘
                                          │              │
                                          │   ┌──────────┴────────────────────┐
                                          │   │  SHARED (Pool A)              │
                                          │   │  · RDS Postgres — 1 DB/client │
                                          │   │  · Alto bundler — 1 per CHAIN │
                                          │   │  · Secrets Manager, CloudWatch│
                                          │   │  · Trace-capable RPC provider │
                                          │   └───────────────────────────────┘
```

Each client gets its own `wallet-api` task set and its own database — topology **T1** in
[`PRODUCT-STRATEGY.md`](./PRODUCT-STRATEGY.md) §5.2, which works with today's code because
`wallet-api` supports exactly one RP ID.

A single shared `wallet-api` and database across all clients (**T2**) would remove the per-client
Fargate and database lines entirely — roughly $20/month/client — but the trade is not just
engineering: it replaces per-client isolation with **one shared failure domain and one shared blast
radius**, and it requires multi-RP support plus tenant-scoped credentials. The full requirement list
is specified in [`MULTI-TENANCY-GAPS.md`](./MULTI-TENANCY-GAPS.md). T2 is not priced here; at 3–10
clients the saving is small relative to the risk.

### Component notes

- **ECS Fargate.** One cluster. Per client: a `wallet-api` service. Managed, no nodes to patch,
  which is the stated requirement.
- **`wallet-web` on S3 + CloudFront.** The wallet origin is a static SPA whose runtime config comes
  from `/config.json`. Serving it from Fargate costs ~$10/task-month for something a CDN does for
  ~$2. **Caveat:** the nginx image does real work — it proxies `/api` and `/.well-known/webauthn`
  same-origin and sets the CSP and `X-Frame-Options: DENY` headers
  (`services/wallet-web/docker/nginx.conf.template`). Moving to CloudFront means reproducing that as
  origin behaviours plus a response-headers policy. **Budget one engineering day and treat the
  header parity as a security-review item** — the same-origin proxy and `frame-ancestors 'none'` are
  load-bearing, not cosmetic. Both options are priced below.
- **RDS Postgres, single instance, one database per client.** Managed backups and patching.
  `deploy/helm/giano/values.yaml` already defaults to `postgres.external: true`, and
  `docker-compose.reference.yml` expects an external DSN, so nothing in the app assumes a co-located
  database.
- **One ALB with host-based routing.** One hostname per client; `RP_ID` isolation is preserved
  because it is a DNS-level property.
- **One bundler per *chain*, not per client.** This is the key economic insight and it is easy to
  miss. Alto is a plain ERC-4337 bundler with no notion of tenancy — it accepts signed UserOps for
  an EntryPoint. If every client is on Ethereum Mainnet, **one Alto instance serves all of them**,
  and it moves from Pool B to Pool A. Per-client gas attribution then happens at the *paymaster*
  layer, not the bundler: each client gets its own `VerifyingPaymaster` with its own EntryPoint
  deposit, scoped via `USEROP_ALLOWED_PAYMASTERS`. See [§5.4](#54-controlling-pool-c).
- **No NAT Gateway.** Run tasks in public subnets with `assignPublicIp: ENABLED` and tight security
  groups. A NAT Gateway is $35/month before a byte of traffic — the classic silent line item that
  would be a third of the lean bill.
- **Images from GHCR.** `.github/workflows/docker.yml` already publishes there, multi-arch
  (`linux/amd64,linux/arm64`). No ECR cost, and the arm64 images mean Graviton is available for free
  ([§7](#7-cost-levers)).

### Gap to close

The repo ships a Helm chart (`deploy/helm/giano/`) — Kubernetes only. **ECS needs a new IaC module.**
`deploy/docker-compose.reference.yml` is the closest existing analogue and maps almost one-to-one
onto ECS task definitions: same images, same environment variables, same external-Postgres
assumption. Budget this as part of P2; it is configuration translation, not new design.

---

## 3. Why a shared substrate is the whole ballgame

Giano has **no application-level tenancy**. `services/wallet-api/src/db/schema.ts` has no `tenants`
or `api_keys` table, and every setting in `src/config.ts` is single-valued. One deployment serves one
client, permanently.

Read naively, this is fatal to the economics: each client needs a full stack, so cost scales
linearly, nothing amortises, and breakeven never improves no matter how many clients sign up.

The resolution is to separate the *logical* stack from the *physical* substrate:

| | Naive (stack per client) | Shared substrate |
|---|---|---|
| ALB | 1 per client | **1 total** |
| RDS instance | 1 per client | **1 total**, one database per client |
| Bundler | 1 per client | **1 per chain** |
| RPC subscription | 1 per client | **1 per chain** |
| Observability | 1 per client | **1 total** |
| `wallet-api` tasks | per client | per client |
| `wallet-web` | per client | per Tier A client; **none for Tier B** |
| Hostname / `RP_ID` | per client | per client |

Each client still gets full logical isolation — its own database, its own `RP_ID`, its own origin
allowlist, its own policy caps, its own paymaster — because all of those are per-deployment
configuration. What is shared is only the infrastructure they run on.

**Result: the marginal cost of client number four is ~$29/month, not ~$180/month.** That is what
makes a three-client breakeven achievable, and it is achievable *without* building multi-tenancy
(P4b/P6). Infrastructure sharing buys us the economics; application tenancy only buys us self-serve
onboarding, which nobody is asking for yet.

---

## 4. Itemised infrastructure cost

Two tiers. **Lean** = pilot-grade (single-AZ database, one replica per service, no WAF). **Reliable**
= what we would actually charge for (multi-AZ database, redundant API tasks, WAF, real log
retention).

Unit prices are `eu-west-1` on-demand, 730 hours/month.

### Pool A — fixed substrate

| Item | Unit price | Lean | Reliable |
|---|---|---|---|
| Application Load Balancer | $0.0270/hr + $0.008/LCU-hr | $25 | $32 |
| RDS Postgres | `db.t4g.micro` $0.018/hr (lean) · `db.t4g.small` multi-AZ $0.072/hr (reliable) | $13 | $53 |
| RDS storage (gp3) | $0.1265/GB-month | $3 (20 GB) | $6 (50 GB) |
| Bundler — Alto on Fargate, 0.5 vCPU / 1 GB | $0.04456/vCPU-hr + $0.004889/GB-hr | $20 | $20 |
| Secrets Manager (shared) | $0.40/secret-month | $2 | $2 |
| CloudWatch Logs | $0.57/GB ingest + $0.03/GB-month | $5 | $12 |
| Route53 | $0.50/zone + $0.40/M queries | $1 | $1 |
| AWS WAF | $5/ACL + $1/rule + $0.60/M req | — | $10 |
| Data transfer out | first 100 GB free, then $0.09/GB | $3 | $5 |
| ACM certificates | free with ALB | $0 | $0 |
| **Subtotal (excl. RPC)** | | **$72** | **$141** |
| **Trace-capable RPC provider** | see below | **$50** | **$200** |
| **Pool A total** | | **$122** | **$341** |

**On the RPC line.** This is the largest and least obvious cost. Running Alto with
`--safe-mode true` — which P3 requires — needs `debug_traceCall`, and the keyless public endpoints
currently used throughout the repo (`ethereum-sepolia-rpc.publicnode.com`,
`base-rpc.publicnode.com`) do not serve it. A trace-capable Ethereum Mainnet endpoint from Alchemy,
QuickNode or similar runs roughly $50–250/month depending on tier and request volume. **This single
line can exceed all compute combined**, and it is also a vendor-availability risk — worth a
documented fallback provider.

### Pool B — per client

| Item | Unit price | Lean | Reliable |
|---|---|---|---|
| `wallet-api` on Fargate, 0.25 vCPU / 0.5 GB | $9.91/task-month | $10 (×1) | $20 (×2) |
| `wallet-web` — S3 + CloudFront *(Tier A only)* | $0.023/GB storage, $0.085/GB out | $2 | $3 |
| *(alternative: `wallet-web` on Fargate ×2)* | *$9.91/task-month* | *$10* | *$20* |
| Client secrets | $0.40/secret-month × ~5 | $2 | $2 |
| Incremental logs | $0.57/GB | $2 | $4 |
| **Pool B per client — Tier A (we host the wallet UI)** | | **$16** | **$29** |
| **Pool B per client — Tier B (client hosts its own wallet origin)** | | **$14** | **$26** |

**Tier B clients are cheaper for us to host** — they serve their own wallet origin, so the
`wallet-web` line disappears from Pool B. The saving is small in absolute terms (~$3/month), but the
direction matters: bring-your-own-UI shifts hosting cost *and* frontend maintenance to the client. It
also shifts **security responsibility**, which is why
[`PRODUCT-STRATEGY.md`](./PRODUCT-STRATEGY.md) §7 makes conformance testing a gate rather than
documentation — and that testing is an ops cost, not an infrastructure one. Budget it in the ops line
of [§6](#6-breakeven), roughly half a day per client per release.

The tables below use the Tier A figure, so they are the conservative case.

### Totals

| Clients | Lean | Reliable |
|---|---|---|
| 1 | $138 | $370 |
| 2 | $154 | $399 |
| 3 | **$170** | **$428** |
| 5 | $202 | $486 |
| 10 | $282 | $631 |

The shape is what matters: going from one client to ten increases infrastructure cost by only **~70%**
while increasing revenue tenfold. The fixed substrate is ~92% of the bill at one client and ~54% at
ten — which is exactly why the shared substrate in [§3](#3-why-a-shared-substrate-is-the-whole-ballgame)
is the difference between a viable service and a treadmill.

---

## 5. Gas and sponsorship (Pool C)

### 5.1 The formula

```
cost_usd  =  gas_units × gas_price_gwei × 1e-9 × eth_price_usd
```

### 5.2 Gas units per sponsored UserOperation

The decisive variable is whether the chain exposes the RIP-7212 P-256 precompile. Giano verifies
passkey signatures through the precompile when present, and falls back to an in-contract
FreshCryptoLib implementation when absent.

> **Verify, do not assume.** Whether Ethereum Mainnet exposes the precompile changes the answer by
> roughly 2.5×. Settle it before quoting anything:
>
> ```sh
> pnpm run doctor chain --rpc <mainnet-rpc-url> --chain-id 1
> ```
>
> The relevant output line is either `P-256 via RIP-7212 precompile` or
> `P-256 via FreshCryptoLib verifier`. Stale comments in this repo about Sepolia's precompile
> support were already found to be wrong — this check is the only reliable source.

| Component | With precompile | FCL fallback |
|---|---|---|
| P-256 signature verification | ~5k | ~330k |
| `preVerificationGas` (L1 calldata) | ~50k | ~50k |
| Account validation (non-P256) | ~20k | ~20k |
| Paymaster validation + `postOp` | ~40k | ~40k |
| EntryPoint overhead | ~40k | ~40k |
| Call (e.g. ERC-20 transfer) | ~50k | ~50k |
| **Total per transaction** | **~205k** | **~530k** |
| *First transaction — add wallet deployment* | *+~200k* | *+~200k* |

Note separately that WebAuthn requires `verificationGasLimit ≥ 800k`
(`docs/TRANSACTION-SUBMISSION-FLOW.md`). That is a *limit*, not consumption — but it is what the
paymaster must prefund, so it drives the deposit balance even when actual usage is lower.

### 5.3 Cost per transaction on Ethereum Mainnet

At ETH = $3,500:

| Gas price | 205k (precompile) | 530k (FCL fallback) |
|---|---|---|
| 5 gwei | **$3.59** | **$9.28** |
| 15 gwei | **$10.76** | **$27.83** |
| 40 gwei | **$28.70** | **$74.20** |

First transaction per user adds a wallet deployment: **+$3.50 / $10.50 / $28.00** at those
gas prices.

For scale, the same 205k-gas transaction on Base at 0.01 gwei plus L1 data costs is roughly
**$0.01–0.10** — two to three orders of magnitude cheaper. This is the single largest cost lever in
the entire model.

**Worked example.** A client with 1,000 users each doing 5 transactions per month, on Mainnet at
15 gwei with the precompile present: 5,000 × $10.76 + 1,000 × $10.50 (deployments) ≈ **$64,300 in the
first month**, versus a $428 infrastructure bill. Without the precompile it is roughly $150,000. The
arithmetic makes the point better than any argument: **sponsorship cannot be bundled.**

### 5.4 Controlling Pool C

The controls already exist and need configuring, not building:

- **Per-client paymaster.** Each client gets its own `VerifyingPaymaster` (P3) with its own
  EntryPoint deposit, funded by that client. The deposit **is** the budget: when it is empty,
  sponsorship stops, and no other client is affected. Scope it with `USEROP_ALLOWED_PAYMASTERS`.
- **Policy caps**, enforced in `services/wallet-api/src/services/userop-policy.ts`:
  `USEROP_MAX_CALL_GAS`, `USEROP_MAX_VERIFICATION_GAS`, `USEROP_MAX_FEE_PER_GAS`,
  `USEROP_MAX_PRIORITY_FEE_PER_GAS`, `USEROP_ALLOWED_TARGETS`. The reference compose defaults to 5M
  gas and 500 gwei caps — **500 gwei is far too permissive for Mainnet** and should be tightened per
  client.
- **Never deploy `PermissivePaymaster` to a live chain.** It sponsors anything from anyone; it is a
  testing contract and `GAPS-TO-COMPLETION.md` describes deploying it as an open invitation to drain
  the fee budget.
- **Alerting on two balances:** the Alto executor EOA (which fronts gas for every bundle) and each
  client's paymaster EntryPoint deposit. Both are already surfaced by
  `pnpm run doctor chain --paymaster 0x.. --executor 0x..`, which warns on low balances — wire it
  into a scheduled job.
- **Bill it as a prepaid deposit with a top-up threshold**, mirroring how the on-chain deposit
  actually behaves. This keeps the commercial model and the technical mechanism aligned.

---

## 6. Breakeven

"Breakeven" means three different things depending on what you count. All three are legitimate; they
answer different questions.

Assumes the **Reliable** tier and **3 clients** → $428/month infrastructure (≈ £340 at $1.26/£).

| # | Definition | What it covers | Monthly cost | **Price per client** |
|---|---|---|---|---|
| **1** | **Infrastructure only** | AWS + RPC. Nothing else. | £340 | **£115** |
| **2** | **Infrastructure + operations** | Above, plus ~0.25 FTE for on-call, patching, key rotation, upgrades, DR drills, client support | £340 + £2,100 = **£2,440** | **£815** |
| **3** | **Infrastructure + operations + roadmap** | Above, plus the security audit amortised (£40k over 24 months) and ~0.25 FTE of continued development | £2,440 + £1,670 + £2,100 = **£6,210** | **£2,070** |

*0.25 FTE ≈ £2,100/month assuming a fully-loaded senior engineer at ~£100k/year.*

### Recommendation

**Price the pilot at definition 2 (~£800–1,100 per client per month).**

- Definition 1 is not breakeven in any meaningful sense — it means every hour an engineer spends on
  Giano is an unfunded loss. It is only defensible for a genuinely free pilot.
- Definition 3 is the honest full-cost number, but £2,000+/month is a hard sell for client number one
  and the audit is a one-off capability investment that benefits every future client. **Treat the
  audit as business investment, recovered across clients 4+ rather than loaded onto the first
  three.**
- Definition 2 covers running the thing properly and keeps the service self-sustaining, which is the
  stated goal.

At £815/client, **three clients break even.** That matches the target.

### Breakeven vs client count

Monthly contribution at £815/client against actual cost, Reliable tier:

| Clients | Infra cost | Ops (0.25 FTE) | Total cost | Revenue @ £815 | Margin |
|---|---|---|---|---|---|
| 1 | £294 | £2,100 | £2,394 | £815 | **−£1,579** |
| 2 | £317 | £2,100 | £2,417 | £1,630 | **−£787** |
| 3 | £340 | £2,100 | £2,440 | £2,445 | **+£5** ✅ |
| 5 | £386 | £2,625 | £3,011 | £4,075 | **+£1,064** |
| 10 | £501 | £3,150 | £3,651 | £8,150 | **+£4,499** |

Ops scales sub-linearly (0.25 FTE to 3 clients, 0.3 to 5, 0.375 to 10) because the substrate is
shared and onboarding is templatised at P4a — which is precisely why P4a exists.

Beyond breakeven the margin funds the roadmap: at 10 clients the surplus covers the audit
amortisation and a further 0.5 FTE of development, which is what makes P4–P6 self-financing rather
than a bet.

---

## 7. Cost levers

Ordered by effort-to-saving ratio.

| Lever | Saving | Effort | Notes |
|---|---|---|---|
| **Launch on an L2 instead of Mainnet** | **100–1000× on Pool C** | None (config) | By far the largest lever in this document. Base is already in the address registry with identical CREATE2 addresses. |
| Avoid NAT Gateway | $35/month | None | Public subnets + tight security groups |
| `wallet-web` on S3 + CloudFront | ~$17/client/month | ~1 day | Must reproduce the nginx proxy rules and security headers — treat as a security-review item |
| Graviton (`ARM64`) Fargate | ~20% of compute | None | Multi-arch images already built by `docker.yml` |
| Single-AZ RDS during pilot | $40/month | None | Accept the RTO; revisit before the first paying client |
| Fargate Spot for `wallet-web` tasks | ~70% of that task's compute | Low | Never for `wallet-api` or the bundler |
| Right-size the RPC tier | up to $200/month | Low | Only pay for trace capability once safe mode is actually enabled |
| Reserved capacity / Savings Plans | ~20–40% | None | Only once the footprint is stable — not during the pilot |

**Do not** economise on: multi-AZ RDS once clients are paying (the credential database is
unrecoverable if lost — there is no backup/DR runbook today, listed as Tier 3 gap #9), the security
audit, or paymaster balance alerting.

---

## 8. Assumptions and how to refresh

### Assumptions

| Assumption | Value | Source / how to check |
|---|---|---|
| AWS region | `eu-west-1` | Decision |
| AWS pricing date | 2026-07-27, on-demand list | AWS Pricing Calculator |
| Hours per month | 730 | Standard |
| ETH price | $3,500 | Set at model time — re-run §5.3 with the current price |
| USD/GBP | 1.26 | Set at model time |
| Fully-loaded senior engineer | £100k/year | Internal |
| Security audit | £40k, amortised over 24 months | **Unquoted — get real quotes during P1/P2** |
| P-256 precompile on Mainnet | **Unverified** | `pnpm run doctor chain --rpc <url> --chain-id 1` |
| Alto safe mode requires paid RPC | Yes (`debug_traceCall`) | `GAPS-TO-COMPLETION.md` §3 |

### Refresh procedure

1. **Precompile status** — `pnpm run doctor chain --rpc <url> --chain-id <id>`; update the §5.2
   column that applies and re-derive §5.3.
2. **Gas and ETH price** — re-run the §5.1 formula; the tables are pure arithmetic.
3. **AWS prices** — rebuild from the unit-price column in §4 against the AWS Pricing Calculator.
   Every line shows its unit so no total is unsourced.
4. **RPC provider** — get current quotes for a trace-capable Mainnet endpoint at expected request
   volume. This is the widest range in the model.
5. **Audit** — replace the £40k placeholder with real quotes as soon as procurement starts (P1).

### Open questions

- Does Ethereum Mainnet expose the P-256 precompile? *(2.5× on all Mainnet gas costs.)*
- What transaction volume should we model for KEO? *(Determines whether Pool C is a rounding error
  or the dominant cost.)*
- Is sponsorship a requirement at all, or can users pay their own gas? *(If users pay, Pool C
  disappears from our books entirely and the model becomes purely infrastructural.)*
- Multi-AZ from day one, or accept single-AZ through the pilot?
- Is the audit recovered from clients, or absorbed as a capability investment?
