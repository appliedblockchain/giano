# Removing the bundler: direct `EntryPoint` submission from `wallet-api`

**Repository:** `appliedblockchain/giano`
**Branch analysed:** `experimental_paymaster` @ `03ae535`
**Date:** 2026-08-25
**Question:** the wallet UI signs a UserOperation with the passkey and posts it to `wallet-api`;
the API validates it against the paymaster rules, then signs and submits an ordinary transaction to
`EntryPoint.handleOps` itself, with no ERC-4337 bundler in the path. What does that cost, what does
it buy, and what does it mean for multi-chain support and for self-hosted deployments?

---

## 0. The one thing that reframes the whole question

The instinctive objection to removing a bundler is "you are giving up ERC-4337's shared relaying
market". **On this branch, that market is not being used.** The bundler in the stack is Giano's own:

- `services/bundler/Dockerfile` ships a pinned `@pimlico/alto@0.0.18` as a Giano-published GHCR
  image, with its own executor keys, its own healthcheck and its own CI build job
  (`.github/workflows/docker.yml`).
- `wallet-api` talks to exactly one, server-configured URL (`BUNDLER_URL`, `src/config.ts`) and
  submits against exactly one server-configured EntryPoint (`services/bundler.ts`).
- No third party ever sees these operations. There is no alt-mempool, no competitive inclusion, no
  fallback bundler, no P2P propagation.

So the decision is **not** "self-relay vs. the 4337 market". It is: *do we keep running a
third-party bundler implementation as a separate process, or absorb its job into `wallet-api`?*

That reframing matters because it moves the cost from "loss of decentralisation" (which is not
being lost) to "loss of a mature implementation of genuinely hard infrastructure" (which is real,
and is the entire substance of the risk). Everything below follows from that.

---

## 1. What the path looks like today

Traced from `specs/TRANSACTION-SUBMISSION-FLOW.md` and the code it anchors to.

```
dApp origin                wallet origin (popup)                  wallet-api                 chain
────────────               ─────────────────────                  ──────────                 ─────
eth_sendTransaction ─────▶ wallet-core provider
                           │
                           ├─▶ pm_getPaymasterStubData ─────────▶ /v1/paymaster  (rules, no reserve)
                           ├─▶ estimateFeesPerGas ─────────────────────────────────────────▶ RPC
                           ├─▶ prepareUserOperation ──────────────────────────────────────▶ ALTO
                           │      (eth_estimateUserOperationGas, nonce, factory args)      (bundler)
                           ├─▶ pm_getPaymasterData ─────────────▶ /v1/paymaster  (reserve + EIP-712 sign)
                           ├─▶ passkey signs the whole op
                           └─▶ POST /v1/userops ────────────────▶ policy → ALTO ─▶ handleOps ─▶ EntryPoint
                                                                                              │
                           GET /v1/userops/:hash/receipt ───────▶ ALTO (eth_getUserOperationReceipt)
```

Three separate things reach the bundler, and only one of them is policied:

| Call | Who makes it | Policied? | Authenticated? |
|---|---|---|---|
| `eth_estimateUserOperationGas` | the **browser**, via the tenant's `/bundler` proxy | **no** | **no** |
| `eth_sendUserOperation` | `wallet-api`, after `evaluatePolicy` | yes | yes (session) |
| `eth_getUserOperationReceipt` | `wallet-api`, public endpoint | n/a | no (by design) |

The flow document states this plainly: *"estimate + prepare are NOT policied — they hit the shared
bundler through the tenant's own proxy. Only the SIGNED op is policied."*

### 1.1 A hole this creates today

`bundlerUrl` is in the wallet SPA's public `config.json` (`services/wallet-web/src/config.ts`), and
in the e2e stack it is `http://wallet.localhost/bundler` — an nginx route on the wallet origin that
proxies to Alto, reachable from any browser that can load the wallet.

For a **sponsored** operation this is harmless: sponsorship requires an EIP-712 authorisation that
only `wallet-api`'s signer can produce, and `USEROP_ALLOWED_PAYMASTERS` pins the paymaster. But for
an **unsponsored** operation — a self-funded account, which the design fully supports — a client can
post `eth_sendUserOperation` straight at that proxy and bypass `POST /v1/userops` entirely:

- no `evaluatePolicy` (no gas caps, no fee caps, no `target-allowlist`, no `sender-binding`)
- no `userop_log` row — the operation is invisible to audit
- no per-tenant `relayLimit`

Removing the bundler removes the proxy, and with it the bypass. **This is the strongest
security argument for the change, and it is independent of everything else in this report.**

---

## 2. The bundler's five jobs, and where each one lands

| # | Job | Today | After |
|---|---|---|---|
| 1 | Gas estimation (`eth_estimateUserOperationGas`) | Alto, called from the browser | `wallet-api`, new endpoint |
| 2 | Validation simulation before spending gas | Alto (`simulateValidation` / `simulateHandleOp`) | `wallet-api`, `eth_call` + state override |
| 3 | `preVerificationGas` computation — the relayer's own cost recovery | Alto, per-chain formulas | `wallet-api`, per-chain formulas |
| 4 | Submission: nonce lane, fee choice, repricing, retry, batching | Alto, funded executor EOAs | `wallet-api`, funded submitter EOA(s) |
| 5 | Status: `eth_getUserOperationReceipt` / `…ByHash` | Alto's index | `wallet-api`, from `UserOperationEvent` logs |

Jobs 1, 2, 3 and 5 are mechanical. **Job 4 is the engineering.** Job 3 is where the money is.

### 2.1 Job 1 — estimation, and the endpoint it implies

`prepareUserOperation` is currently viem's, running in the popup against Alto
(`services/wallet-web/src/wallet.ts` builds `createBundlerClient({ transport: http(config.bundlerUrl) })`).
Without a bundler there is no `eth_estimateUserOperationGas`, so the wallet needs a Giano endpoint —
call it `POST /v1/userops/prepare` — returning nonce, factory args, the three gas limits and the
paymaster stub in one round trip.

Two viable estimator implementations, both standard bundler technique:

1. **`EntryPointSimulations` via state override.** `vendor/account-abstraction/contracts/core/EntryPointSimulations.sol`
   is already vendored. `eth_call` the EntryPoint address with `stateOverride: { [entryPoint]: { code: simulationsBytecode } }`
   and call `simulateHandleOp`. Preserves the real EntryPoint's storage (deposits, nonces) because
   only code is overridden. **Requires an RPC that supports `eth_call` state overrides** — anvil,
   geth, reth and the major managed providers do; some rate-limit override size.
2. **Binary search on `eth_call handleOps`** from the submitter address, raising `callGasLimit`
   until it stops reverting. No override support needed, but several RPC round trips per estimate.

Two things this changes for the better:

- **Estimation becomes policied.** It moves behind `requireSession`, so it is tenant-attributed,
  rate-limitable and auditable — closing the gap in the table in §1.
- **The wallet SPA stops needing a bundler URL.** `config.json` loses `bundlerUrl`, the per-tenant
  edge loses its `/bundler` route, and one CORS/proxy surface disappears per tenant. The
  bring-your-own-UI contract (`e2e/wallet-byo/src/config.ts`) shrinks correspondingly.

One thing it changes for the worse: **estimation accuracy becomes Giano's problem, per chain.**
The flow document already notes `verificationGasLimit ≥ 800k` for WebAuthn validation, and the
`packages/contracts` notes record that P-256 verification is a few thousand gas where the RIP-7212
precompile exists and roughly two orders of magnitude more where the FCL/Daimo fallback is used.
That is a per-chain constant that Alto currently discovers by simulation. Any hand-tuned default
will be wrong on some chain.

### 2.2 Job 2 — simulation is not optional

If the account's `validateUserOp` or the paymaster's `validatePaymasterUserOp` reverts,
`EntryPoint.handleOps` reverts **wholesale** with `FailedOp(opIndex, reason)`. The transaction
still consumes gas, and nothing reimburses it: the paymaster's deposit is only touched on a
successful validation. So every `AA24` (bad signature), `AA25` (stale nonce), `AA31` (deposit too
low) or `AA34` (paymaster signature) becomes **gas burned directly out of Giano's submitter EOA**,
with no ledger entry and no tenant to charge.

Today Alto absorbs this: it simulates, and refuses. Losing that means losing an *adversarial second
implementation* of the validation rules. A bug in Giano's `getUserOperationHash`, in the
`paymasterData` byte layout (`encodePaymasterData` — `version(1) ‖ tenantId(16) ‖ validUntil(6) ‖ validAfter(6) ‖ feeWei(16) ‖ signer(20) ‖ signature`),
or in the EIP-712 field ordering currently surfaces as an Alto rejection. After the change it
surfaces as a burned transaction — and, if the fault is systematic, as a burn per attempt.

**Requirement: never call `handleOps` on an operation that has not just passed simulation, and
treat simulation failure as a `403`/`422` rather than a submission.**

### 2.3 Job 3 — `preVerificationGas`, where the economics actually live

This is the subtlest consequence and deserves its own treatment.

`EntryPoint` v0.7 reimburses the beneficiary `actualGasCost = (measuredGas + preVerificationGas) × gasPrice`.
`preVerificationGas` is **charged as a flat figure, not metered**: it is the client's declaration of
what the transaction costs *outside* the metered region — the 21 000 base cost, the calldata bytes,
`handleOps` overhead, and on OP-stack/Arbitrum-style rollups the **L1 data availability fee**.

The consequences of getting it wrong are asymmetric and both bad:

| | Effect on the tenant | Effect on Giano's submitter EOA |
|---|---|---|
| `preVerificationGas` too **low** | under-charged | **under-reimbursed — silent loss per operation** |
| `preVerificationGas` too **high** | over-charged | over-reimbursed |

Note the second row: because Giano is simultaneously the relayer *and* the fee-taker
(`treasury` in `GianoPaymaster._settle`), an inflated `preVerificationGas` is an undisclosed
transfer from a tenant's balance to Giano's EOA. The paymaster's whole design premise is that
*"a tenant can verify a charge from readable on-chain data rather than from Giano's books"*
(`services/paymaster-contract.ts`). A client-supplied `preVerificationGas` that the operator
silently benefits from is at odds with that premise.

Two live gaps make this concrete:

1. **`evaluatePolicy` does not check `preVerificationGas` at all.** It is read into `PolicyUserOp`
   (`services/userop-policy.ts:60`) and then never asserted against anything — there are caps for
   `callGasLimit`, `verificationGasLimit`, `maxFeePerGas` and `maxPriorityFeePerGas`, and none for
   `preVerificationGas`. Today Alto is what stands between a client-declared figure and Giano's
   money. Remove Alto and that figure goes straight to the chain.
2. **`computeMaxCost` trusts it too.** `sponsorship-rules.ts:113` reserves
   `(preVerificationGas + verificationGas + callGasLimit) × maxFeePerGas` from the tenant's
   balance — a client-supplied number driving a reservation against customer funds.

**Requirement: after the change, `wallet-api` must *compute* `preVerificationGas` itself in
`/v1/userops/prepare` and *reject* any submitted operation whose declared value is below its own
recomputation.** Per chain. Including L1 data fees on rollups. This is the single largest hidden
cost of the whole proposal, and it is exactly the piece Pimlico maintains per-chain in Alto.

### 2.4 Job 4 — the submitter: nonces, fees, retries

A bundler's least glamorous and most load-bearing job. The pieces:

**Nonce lane.** Every operation now goes out as a transaction from a Giano EOA, so the EOA's
sequential nonce becomes the **global serialisation point for the whole deployment**. One stuck
transaction blocks every subsequent operation for every tenant. Mitigations are the standard ones,
and all of them are work: an in-process nonce allocator with gap recovery, replacement-by-fee on a
timeout, and a pool of N submitter EOAs to get N parallel lanes.

Note what this does *not* break: ERC-4337's 2-D account nonce still works, and viem already picks a
random nonce key per prepare, so a single user's operations remain independently valid. The new
bottleneck is on Giano's side, not the account's.

**Fee choice, and what can and cannot be repriced.** A precise distinction:

- The **outer transaction's** fees are Giano's to choose, and Giano may replace-by-fee freely. Good.
- The **operation's** `maxFeePerGas` is signed twice over — by the passkey, and inside the
  paymaster authorisation (`gasFees` is a field in `AUTHORISATION_TYPES`,
  `services/sponsorship-signer.ts`). It cannot be raised without both signatures being redone,
  which means a **new passkey prompt**.

`EntryPoint` charges at `min(op.maxFeePerGas, basefee + op.maxPriorityFeePerGas)`. So if basefee
rises above the operation's signed `maxFeePerGas`, Giano pays basefee and is reimbursed at the
lower figure — a loss. Alto refuses such operations; `wallet-api` must too, and must surface
"fees moved, please re-approve" to the wallet.

There is a genuine *upside* here. A bundler holds operations in a mempool while it waits for a
batch, which is precisely the dwell time during which fees move. Direct submission broadcasts
immediately, so the exposure window shrinks from seconds-to-minutes to one block. Combined with
`SPONSORSHIP_VALIDITY_SECONDS` defaulting to 180, the sponsorship authorisation window becomes
comfortably slack rather than tight.

**Batching.** `handleOps` takes an array, so cross-tenant batching is *available* — and amortising
the 21 000-gas base cost across many operations is the one economic advantage 4337 claims that
Giano currently does get from Alto. But a single `FailedOp` reverts the entire batch, so batching
requires per-operation simulation plus batch-splitting on failure. **Recommendation: ship one
operation per transaction and do not build batching until throughput demands it.** On L2s, where
calldata dominates and the base cost is small, the saving is modest anyway.

**Key custody.** The submitter key holds real funds and signs continuously. `wallet-api` already has
exactly the right pattern for this: `SponsorshipSigner` (`services/sponsorship-signer.ts`) is a
two-line interface with a local implementation for dev/testnet and an HSM implementation for
production, and `loadConfig` **refuses to boot** with a local key when
`GIANO_DEPLOYMENT_CLASS=production`. A `SubmitterSigner` should be modelled identically and gated
identically. One caveat: the sponsorship signer fires once per sponsored operation; the submitter
fires once per operation, full stop — so HSM call latency and cost land on the critical path of
every transaction. Worth measuring before committing to HSM-per-transaction.

### 2.5 Job 5 — receipts, and a status model that gets better

`eth_getUserOperationReceipt` disappears and is replaced by a log query for
`UserOperationEvent(userOpHash, sender, paymaster, nonce, success, actualGasCost, actualGasUsed)`.
The public endpoint `GET /v1/userops/:hash/receipt` keeps its shape, so **the SDK and the dApp
contract are unaffected** — the receipt-polling loop in `packages/connector` does not change.

This is a net improvement, because direct submission gives `wallet-api` facts it currently cannot
have:

- **A transaction hash for every operation.** Today `userop_log.bundler_response` holds
  `{ bundlerHash }` and nothing more; the mapping from operation to transaction lives inside Alto.
  Direct submission means every row carries its tx hash — a materially better support and
  forensics story.
- **Synchronous inclusion.** `sponsorship-ledger.settle()` is currently driven only by the
  `paymaster-watcher` ingesting `Sponsored` events, with reservations otherwise expiring by TTL
  (`SPONSORSHIP_RESERVATION_TTL_SECONDS`, default 300s). With the receipt in hand, the submitter can
  settle the reservation immediately, and the watcher demotes from *sole source of truth* to
  *reconciler* — which is what its own doc comment says it wants to be
  (*"the cache converges on chain truth instead of drifting from it"*). Tenants' effective available
  balance stops being depressed by up-to-5-minute reservation tails.

**Schema change needed.** `useropLog.status` is `'accepted' | 'rejected' | 'submitted' | 'failed'`,
where `submitted` means "Alto accepted it". Direct submission needs the richer truth:
`broadcast | mined | reverted | dropped | replaced`, plus a `tx_hash` column and probably
`block_number`. `bundler_response` should be renamed (or generalised to `submission`).

---

## 3. What does *not* change

Worth stating explicitly, because it is most of the system.

- **Every contract.** `GianoSmartWallet.validateUserOp` is `onlyEntryPoint`; `GianoPaymaster`
  checks `msg.sender != address($.entryPoint)` in both `validatePaymasterUserOp` and `postOp`.
  Neither cares who called `handleOps`. **Zero Solidity changes.** No migration, no redeploy, no
  storage-layout concern, no determinism-CI churn.
- **The account is still a standard ERC-4337 account.** A third party could still submit operations
  for a Giano wallet through a public bundler. Explorers that index `EntryPoint` events (jiffyscan
  and similar) still show them. Interoperability is preserved — direct submission is an operator
  choice, not a protocol fork.
- **The whole sponsorship design.** ERC-7677 `pm_getPaymasterStubData` / `pm_getPaymasterData`,
  the two-signature model, the reservation ledger, the tenant roster, the fee/treasury/deficit
  accounting, `paymaster-admin`, `paymaster-sdk`. All of it is upstream of submission.
- **Origin isolation and the two-origin trust boundary.** Untouched; in fact tightened, since the
  wallet origin no longer proxies a bundler.
- **The passkey ceremony, WebAuthn, sessions, tenancy, ROR.** Untouched.
- **Adversarial exposure of the submitted transaction.** Alto's executor is already a known,
  funded EOA broadcasting to the public mempool. Replacing it with Giano's own EOA changes nothing
  about frontrunning or censorship exposure.

---

## 4. A capability that quietly *unlocks*: escaping ERC-7562

Bundlers enforce ERC-7562 validation rules — banned opcodes, restricted storage access, and
staking requirements for entities that touch storage not associated with the sender. Giano is
currently constrained by these in two visible ways:

1. **The paymaster must be staked.** `specs/PAYMASTER-SPECS.md` §4.6 is explicit: *"A validating
   paymaster that returns a validity window needs a stake before bundlers will accept its ops, and
   R-24 makes 'deployed but unstaked' a failed deployment rather than a puzzling client bug."*
   `GianoPaymaster` carries `addStake` / `unlockStake` / `withdrawStake` behind
   `STAKE_ADMIN_ROLE`, and `giano-doctor` checks for stake presence — an entire provisioning,
   monitoring and capital-locking concern that exists **only** to satisfy bundler policy.
2. **The e2e stack already runs Alto with `--safe-mode false`** (`deploy/docker-compose.e2e.yml:58`),
   i.e. with those checks disabled. So the local stack is not currently validating against the
   rules that a production public bundler would apply — a latent gap between what is tested and
   what would be enforced.

Remove the bundler and both evaporate. Stake becomes optional capital that can be released. The
safe-mode discrepancy stops mattering. And more generally, the design gains latitude it does not
have today: validation logic may read arbitrary storage, use block context, and evolve without
checking it against bundler policy first.

**Caveat, and it is a real one.** Exercising that latitude is a **one-way door**. The moment
`validateUserOp` or `validatePaymasterUserOp` does something ERC-7562 forbids, no public bundler
will ever accept a Giano operation again, and the fallback path in §7's phased plan is gone. The
recommendation is to *bank the savings* (drop the stake requirement, drop safe-mode ambiguity) but
**keep the validation logic rule-compliant by policy**, so the option to fall back survives.

---

## 5. Capability-by-capability impact

| Capability | Today | After direct submission |
|---|---|---|
| Passkey signing, WebAuthn, ERC-1271 | ✅ | ✅ unchanged |
| Counterfactual address, atomic deploy-and-act (`factory`/`factoryData`) | ✅ | ✅ unchanged — `handleOps` handles `initCode` |
| 2-D account nonces / per-user parallelism | ✅ | ✅ unchanged at the account; new bottleneck at the submitter EOA |
| `executeBatch` (one user, many calls) | ✅ | ✅ unchanged |
| Cross-user batching (amortised base cost) | ✅ via Alto | ⚠️ available but must be built; not recommended initially |
| Gas sponsorship, ERC-7677, tenant ledger | ✅ | ✅ unchanged, and settlement gets faster |
| Paymaster stake requirement | required | **no longer required** |
| ERC-7562 validation-rule ceiling | binding | **lifted** (keep compliance by policy) |
| Policy enforcement coverage | signed ops only; **estimation and unsponsored ops can bypass** | **complete — API is the only path to chain** |
| Audit completeness (`userop_log`) | bypassable | complete, plus tx hash and block |
| Operation → transaction traceability | inside Alto | first-class in Postgres |
| Reservation settlement latency | watcher event or 300s TTL | immediate from the receipt |
| Third-party bundler interop for Giano accounts | ✅ | ✅ preserved (accounts remain standard) |
| Explorer visibility (`UserOperationEvent`) | ✅ | ✅ unchanged |
| Chains with no bundler infrastructure (appchains, consortium) | ❌ needs an Alto per chain | ✅ **just an RPC endpoint** |
| Independent second implementation of validation | Alto | ❌ **lost — must be replaced by own simulation** |
| Per-chain `preVerificationGas` correctness (incl. L2 L1-data fees) | Alto's problem | ❌ **Giano's problem** |
| Stuck-transaction / repricing resilience | Alto | ❌ must be built |
| Mempool-mediated retry across blocks | Alto | ⚠️ outer tx repricing only; capped by the op's signed `maxFeePerGas` |
| Fee-drift exposure window | mempool dwell | ✅ **smaller** — immediate broadcast |
| Images to build, processes to run, funded EOAs | 6 images; Alto process; **2** funded EOAs (Alto executor + utility) | **5 images; no Alto; 1** funded EOA (the submitter) |

---

## 6. Multi-chain from one service

This is where the change pays for itself most clearly.

### 6.1 Where multi-chain stands today

**The configuration is strictly single-chain.** `src/config.ts` has scalar `CHAIN_ID`, `RPC_URL`,
`BUNDLER_URL`, `ENTRYPOINT_ADDRESS`, `FACTORY_ADDRESS`, `SPONSORSHIP_PAYMASTER_ADDRESS`. One
process serves one chain. `GET /v1/version` returns a single `chainId`. Multi-chain today means N
full deployments — and, critically, **N bundlers**: N Alto processes, N sets of executor keys, N
images to keep version-matched, N healthchecks, N things to monitor.

**The data model is already substantially chain-ready**, and deliberately so. Every sponsorship
table carries `chain_id`, several with it in the primary key:

| Table | Chain-scoped? |
|---|---|
| `tenant_sponsorship` | ✅ PK `(tenant_id, chain_id)` |
| `tenant_sponsorship_history` | ✅ |
| `paymaster_tenants` | ✅ PK `(tenant_id, chain_id)` |
| `sponsorship_reservations` | ✅ (+ index on `(tenant_id, chain_id, state)`) |
| `sponsorship_settlements` | ✅ PK `(chain_id, userop_hash)` |
| `sponsorship_decisions` | ✅ |
| `paymaster_state` | ✅ PK `chain_id` |
| `userop_log` | ❌ — but `userop_hash` is globally unique *because* it binds chain id + EntryPoint |
| `credentials` | ❌ — correctly: CREATE2 gives the same `wallet_address` on every chain |
| `sessions`, `users`, `challenges` | ❌ — correctly: identity is not chain-scoped |

`specs/PAYMASTER-REQUIREMENTS.md` Q6 already answers the product question — *"as many [chains] as
needed, and per-chain balances are expected… The ledger and configuration are chain-keyed from the
start so nothing has to be retrofitted."*

So the ledger is ready and the identity model is chain-agnostic **by design**: one passkey → one
CREATE2 address on every chain, and `executeWithoutChainIdValidation` (reserved nonce key `8453`)
even lets owner changes be replayed across chains. A single multi-chain `wallet-api` is a natural
fit for this design. The obstacles are the config surface and the bundler.

### 6.2 Why removing the bundler makes multi-chain much cheaper

Per additional chain, today: **an Alto deployment** (image, config, executor keys, utility key,
port, healthcheck, monitoring, version-compatibility risk) plus a paymaster deployment, plus a
stake, plus RPC access.

After the change: **an entry in a chain registry.** Something shaped like the existing
`TENANTS_SEED` pattern —

```jsonc
CHAINS_SEED: [
  { "chainId": 8453,   "rpcUrl": "...", "entryPoint": "0x...", "factory": "0x...",
    "sponsorshipPaymaster": "0x...", "submitterKeyRef": "...", "confirmations": 2 },
  { "chainId": 381185, "rpcUrl": "...", "factory": "0x...", "submitterKeyRef": "..." }
]
```

`packages/contracts/addresses.ts` already supplies per-chain defaults (8453, 84532, 381185) via
`gianoAddresses`, and `getGianoDeployment(chainId)` already exists — the registry mostly reads from
it, exactly as `config.ts` does today for one chain.

### 6.3 Concrete work items for multi-chain

1. **Chain registry** replacing the scalar chain config; `getGianoDeployment` per entry.
2. **A `Submitter` per chain**: its own nonce lane, its own key (or key ref), its own fee strategy,
   its own circuit breaker. One flaky RPC must not stall the others — a shared event loop makes
   this a real concern, so per-chain timeouts and a breaker are not optional.
3. **A `PaymasterReader` and a `paymaster-watcher` per chain.** The watcher is already chain-keyed
   in its tables, but `WATCHER_LOCK_KEY = 0x67706d77` is a single constant — it must become
   `f(chainId)`, or two chains' watchers in one deployment will lock each other out.
4. **Chain in the request shape.** `POST /v1/userops`, `/prepare`, `/v1/paymaster` and the receipt
   endpoint all need an explicit chain, and the policy/rate-limit keys become `(tenant, chain)`.
   The wallet SPA's `config.json` gains a chain list rather than a single `chainId`.
5. **`userop_log.chain_id`** — for query scoping and per-chain metrics, even though `userop_hash`
   stays globally unique.
6. **`chain` as a metric label** on every existing metric.
7. **Per-chain tenant enablement** — a tenant on Base should not implicitly be a tenant on an
   appchain; per-chain balances already exist, so per-chain enablement belongs next to them.
8. **Per-chain estimation constants.** The hard one. `verificationGasLimit` differs by roughly two
   orders of magnitude depending on whether RIP-7212 is present. `preVerificationGas` needs an
   OP-stack formula, an Arbitrum formula and a vanilla formula. `estimateFeesPerGas` needs a
   non-EIP-1559 fallback (`wallet-web` already has one). **This is the work that Alto currently
   does for free, and it does not get cheaper by being centralised — it gets N times more visible.**

### 6.4 New multi-chain risks

- **Blast radius.** One process holding N funded submitter keys is a bigger prize than N processes
  holding one each. Argues for HSM key refs per chain and hard per-chain spend caps.
- **Correlated failure.** A `wallet-api` bug takes down every chain at once, where today an Alto
  failure takes down one.
- **Per-chain accuracy debt.** Every new chain is a new estimation-correctness liability, and the
  failure mode (§2.3) is silent under-reimbursement rather than a loud error.

**Judgement: removing the bundler is close to a precondition for a credible one-service multi-chain
story.** The alternative — N Alto deployments alongside one multi-chain API — keeps the hardest
operational cost exactly where it is while adding a new source of version skew.

---

## 7. Self-hosted deployments

The self-hosted case is where this change is least ambiguous. It is a clear win.

### 7.1 The stack shrinks

Today the bundler shows up in a self-hoster's life in one of two ways, and both are costs:

- `deploy/helm/giano/templates/bundler.yaml` runs it **in-cluster**, alongside `wallet-api`,
  `wallet-web`, the migrations job and the deployer job. `.github/workflows/docker.yml` builds and
  publishes the image; the e2e compose exposes port 4337.
- `deploy/docker-compose.reference.yml` does **not** ship one at all — it requires
  `BUNDLER_URL: ${BUNDLER_URL:?ERC-4337 bundler endpoint}`, i.e. the self-hoster must *source a
  bundler from somewhere else* before the reference stack will even boot. For a deployment on a
  chain with no bundler market, that is an unbounded prerequisite dressed up as an environment
  variable.

After: **Postgres + `wallet-api` + `wallet-web` + an RPC endpoint.** For an unsponsored,
self-funded deployment that is genuinely the whole thing — a claim the project cannot make today,
because even a no-sponsorship deployment still needs a bundler.

Concretely removed from a self-hoster's burden:

- one container image to pull, pin, patch and CVE-scan
- one process to monitor and alert on, with its own liveness semantics
- one port and one nginx/ingress route per tenant (`/bundler`)
- Alto's **two** keys (`--executor-private-keys`, `--utility-private-key`)
- one third-party version-compatibility axis (Alto ↔ EntryPoint ↔ chain)
- one egress path — `wallet-api → bundler → RPC` collapses to `wallet-api → RPC`, which matters in
  a locked-down network where every egress rule is reviewed

### 7.2 Key custody: the same burden, in a better place

Today a self-hoster funds and protects Alto's executor key, which sits in an environment variable
in a third-party process — `services/bundler/entrypoint.sh` guards against the well-known Anvil key
unless `GIANO_DEV_MODE=true`, and that is roughly the extent of the discipline available.

After the change the same funded key sits behind `wallet-api`'s own signer abstraction, which is
already the strongest piece of key discipline in the repository: a narrow interface, a local
implementation for dev/testnet, an HSM implementation for production, and a `loadConfig` refusal to
boot with a local key when `GIANO_DEPLOYMENT_CLASS=production`. Extending that to a
`SubmitterSigner` gives the self-hoster **one** key-custody story instead of two, and applies the
stricter one to both.

Two caveats worth stating plainly:

- **HSM latency lands on every transaction**, not just sponsored ones. Measure before mandating.
- **The submitter key is now inside the API process's blast radius.** A `wallet-api` compromise
  currently yields the sponsorship authority (bad); afterwards it also yields the submitter's funds
  (worse, though bounded by the EOA's balance). Argues for a hot-wallet pattern: a small
  auto-topped-up submitter balance rather than a large float.

### 7.3 Private, consortium and appchain deployments

For the environment Giano is arguably best suited to — a chain the deploying organisation controls,
where chain `381185` in `addresses.ts` suggests this is already real — direct submission is
**strictly better**:

- No public bundler exists there, so a self-hoster must run Alto anyway; that requirement disappears.
- No paymaster stake needs to be locked (§4).
- No ERC-7562 or safe-mode ambiguity to reason about.
- No dependence on Alto keeping pace with a non-standard chain's fee model or RPC quirks — which is
  precisely where third-party bundlers break on private chains.
- Fee estimation is usually trivial (fixed or zero gas price), so §2.3's hardest cost largely
  vanishes in exactly the deployments where the stack shrinks the most.

### 7.4 What a self-hoster takes on

Honestly stated: they inherit responsibility for a funded EOA's nonce hygiene, and for the
correctness of Giano's estimator on their chain. In exchange they stop owning a third-party
bundler. For a chain they control, that trade is clearly favourable. For a self-hoster on Base
mainnet, it is a straight transfer of a hard problem from Pimlico's maintainers to Giano's — which
is the argument for keeping both modes (below) rather than deleting one.

---

## 8. Recommendation: two submission modes, not one

The proposal is sound, and for appchains, consortium chains and self-hosted deployments it is
clearly right. On public L2s the `preVerificationGas` and fee-market work is real enough that
deleting the working path before the new one is proven would be a mistake. Phase it, and keep both.

**Phase 0 — close the bypass, no new infrastructure risk.**
Add `POST /v1/userops/prepare` (estimation + nonce + factory args + paymaster stub) behind
`requireSession`; have `wallet-web` and the BYO reference call it instead of a bundler client;
remove `bundlerUrl` from `config.json` and the `/bundler` edge route. `wallet-api` still submits to
Alto. Add a `preVerificationGas` floor and cap to `evaluatePolicy`.
*Result: the §1.1 policy bypass is closed and estimation becomes tenant-attributed, with the
existing submission path untouched.*

**Phase 1 — a `Submitter` interface with two implementations.**
`BundlerSubmitter` (today's `services/bundler.ts`) and `DirectSubmitter`
(`simulate → handleOps → track receipt`), chosen by `SUBMISSION_MODE`. Extend `userop_log` with
`tx_hash`, `block_number` and the richer status enum. Introduce `SubmitterSigner` mirroring
`SponsorshipSigner`, with the same production gate. Default `direct` on the devnet, e2e stack and
appchains; keep `bundler` on public chains. Run both in e2e — `sponsorship.spec.ts` already asserts
accounting from chain events rather than from Giano's books, which makes it a fair adjudicator
between the two modes.

**Phase 2 — per-chain everything.**
Chain registry, per-chain submitter/reader/watcher, `WATCHER_LOCK_KEY` derived from `chainId`,
chain in the request shape and in every metric label. Per-chain `preVerificationGas` formulas,
measured against Alto's output on Base/Base Sepolia before switching those chains over.

**Phase 3 — retire Alto** on a chain only once the direct estimator has demonstrably matched it,
and only once submitter-EOA reimbursement has been reconciled against real gas spend for a
meaningful period. Keep `BundlerSubmitter` in the tree as the fallback.

**Do not build** cross-tenant batching in any phase until throughput actually demands it.

---

## 9. Findings worth acting on regardless of this decision

Surfaced while reading, and independent of whether the bundler goes:

1. **Unsponsored operations can bypass the policy relay entirely** by posting straight to the
   browser-reachable `/bundler` proxy: no gas caps, no `sender-binding`, no `userop_log` row, no
   rate limit (§1.1). The cheapest fix is Phase 0 above.
2. **`evaluatePolicy` has no `preVerificationGas` rule**, though it accepts the field
   (`userop-policy.ts:58`) and `computeMaxCost` reserves tenant funds based on it
   (`sponsorship-rules.ts:113`). Today Alto is the only thing bounding a client-declared figure
   that drives a charge against customer money.
3. **The e2e stack runs Alto with `--safe-mode false`**, so ERC-7562 validation rules — the reason
   `GianoPaymaster` needs a stake at all — are not exercised anywhere in CI. Either test against
   safe mode or record explicitly that rule-compliance is unverified.
4. **`WATCHER_LOCK_KEY` is a single constant.** Harmless on one chain; a silent single-chain-only
   constraint the moment a second chain is added to one deployment.

---

## 10. Verdict

Removing the bundler is not a retreat from ERC-4337 — the contracts do not change, the accounts
stay standard, and the operations stay visible to any 4337 explorer. It is the recognition that
Giano already operates the only bundler its users ever touch, and that keeping it as a separate
third-party process buys a mature implementation of four hard problems while costing a policy
bypass, a stake requirement, a per-tenant proxy route, and — most importantly — the ability to
serve many chains from one service.

The three problems worth respecting are `preVerificationGas` correctness on rollups, submitter-EOA
nonce and fee management, and the loss of an adversarial second implementation of validation. All
three are tractable, all three are chain-specific, and all three are much smaller on a chain the
operator controls than on Base mainnet.

Which is why the recommendation is a mode rather than a migration: **direct submission by default
for self-hosted, appchain and consortium deployments — where it makes the stack materially smaller
and the multi-chain story possible — with the bundler path retained for public mainnets until the
estimator has proven itself against it.**
