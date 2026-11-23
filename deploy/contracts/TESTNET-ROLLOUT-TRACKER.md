# Testnet rollout tracker: release v3 on Base Sepolia and Ethereum Sepolia

The working log for the rollout. [`TESTNET-ROLLOUT.md`](TESTNET-ROLLOUT.md) is the plan, and this
file records what happened: each step's status, what a person had to do, the output, and what went
wrong. Update the step's **Result** block and the summary table as you go. Record findings in the
findings register and dated entries in the run log at the end. This repository is public, so this
file holds public information only: addresses, transaction hashes, explorer links, PRs and roles. No
secrets, no internal identifiers (1Password items, Slack threads) and no personal names; the private
working log, with those, is on the Giano Notion page "Testnet v3 rollout tracker".

- **Started:** 2026-11-16
- **Tooling PR:** [#279](https://github.com/appliedblockchain/giano/pull/279) (`feat/harden-contract-deployment`)
- **Release / EntryPoint:** `v3` / v0.9 (`0x433709009B8330FDa32311DF1C2AFA402eD8D009`)
- **Chains:** Base Sepolia (84532) first, then Ethereum Sepolia (11155111)
- **Environment to cut over:** `dev` (now pinned to `5ba71241`: EntryPoint v0.7, legacy factory `0x26dCd293…`)

## Legend

| Tag | Meaning |
|---|---|
| 🤖 | The agent (or any developer) can run it unattended |
| 🧑 ACT | A person must do something: create a key, send funds, sign in a Safe, use a passkey |
| 🔍 VERIFY | A person must check the output: an explorer page, a `terraform plan`, a diff |
| ✋ APPROVE | Explicit go/no-go before an irreversible or outward-facing action (merge, on-chain tx, announce) |
| 🗳 DECIDE | A decision is needed, with its owner |
| ⛔ IRREVERSIBLE | Cannot be undone on-chain |

Status: ⬜ todo · 🔄 in progress · ⏸ blocked · ✅ done · ❌ failed · ➖ skipped

## Summary

| # | Step | Owner | Human touchpoints | Status |
|---|---|---|---|---|
| **0** | **Land the tooling (PR #279)** | | | |
| 0.1 | Fix the four blocking review comments (B1–B4) | dev | 🔍 | ✅ |
| 0.2 | Choose what to do with the non-blocking comments | dev / tech lead | 🗳 | ✅ |
| 0.3 | Record the N4 decision in the rollout docs | dev | 🔍 | ✅ |
| 0.4 | Bring level with `main`, CI green, re-review, approval | dev / reviewers | ✋ | ✅ |
| 0.5 | Merge #279 and archive the OpenSpec change | dev | ✋ | ✅ #279 + #293 merged |
| **1** | **N4: shrink the `eth_getLogs` span to 200 (wallet-api PR)** | | | |
| 1.1 | Confirm the scope of the 200-block change | dev / tech lead | 🗳 | ✅ |
| 1.2 | Implement, test, changeset, PR | dev | 🔍 ✋ | ✅ #294 approved by the reviewer |
| 1.3 | Prove it: rehearse through the public 200-block RPC | 🤖 | 🔍 | ✅ 17/17 |
| 1.4 | Merge; drop the "RPC must serve 9,000 blocks" requirement from the docs | dev | ✋ | ✅ #294 merged (`4e29eb72`) |
| **2** | **Decisions** | | | |
| 2.1 | Reset `dev` or migrate its v0.7 accounts | tech lead | 🗳 | ✅ reset; clear `dev` user data at the switch (F8) |
| 2.2 | Testnet proposer Safe and its signers | tech lead | 🗳 | ✅ one EOA admin key (the tech lead) |
| 2.3 | Holder of each immediate paymaster role | tech lead | 🗳 | ✅ same EOA admin key (the tech lead) |
| 2.4 | Timelock delays for testnet | product | 🗳 | ✅ keep 5 min–1 h |
| 2.5 | Tenants to provision, their allowlists and withdrawal addresses | tech lead / tenants | 🗳 | ✅ both tenants, test ERC-20 (`test-token`, #303), 0.02 ETH |
| 2.6 | RPC provider for deploy and `GIANO_CHAINS` | tech lead / DevOps | 🗳 | ✅ keyed QuickNode (ok up to 10,000 blocks) |
| 2.7 | Testnet ETH: amounts and source (D7) | tech lead | 🗳 | ✅ the tech lead funded (2026-11-17) |
| 2.8 | Custody of the testnet canonical deployer key (D8) | tech lead | 🗳 | ✅ own 1Password item; #296 merged; restricted access to confirm |
| 2.9 | Fix G42 before the first live deploy (D9) | tech lead | 🗳 | ✅ #298 merged |
| **3** | **Keys and operator config** | | | |
| 3.1 | Create the testnet canonical deployer key (1Password) | dev | 🧑 ✋ | ✅ |
| 3.2 | PR: `DEPLOYERS.testnet` + `docs/key-ceremony.md` | dev | 🔍 ✋ | ✅ #296 merged (`0bcf0864`) |
| 3.3 | Bootstrap operator, sponsorship signer and bundler executor keys | dev / DevOps | 🧑 | ✅ admin `0x0331…3030`, signer `0x48bC…8a44`, executor `0x945B…60aC` (0.1 ETH each chain) |
| 3.4 | Create the proposer Safe on each chain | Safe signers | 🧑 | ➖ superseded: admin key is the proposer (#302) |
| 3.4b | PR: admin key as `roleAdmin` and `timelock.proposers` in both profiles | dev | 🔍 ✋ | ✅ #302 merged |
| 3.5 | Write the operator env files | dev | 🔍 | ✅ filled and checked (key → admin, RPCs → right chain IDs) |
| **4** | **Rehearse with the real configuration** | | | |
| 4.1 | Read-only preflight against both public chains | 🤖 | 🔍 | ✅ both chains, all OK; only blocker funding |
| 4.2 | Fork rehearsal, Base Sepolia, `--platform` | 🤖 | 🔍 | ✅ 17/17 (2026-11-17) |
| 4.3 | Fork rehearsal, Ethereum Sepolia, `--platform` | 🤖 | 🔍 | ✅ passed incl. browser smoke (2026-11-17) |
| **5** | **Funding** | | | |
| 5.1 | Print the funding amounts per chain | 🤖 | 🔍 | ✅ operator 0.2 ETH = suggested ~0.2 on both chains |
| 5.2 | Fund the deployer, bootstrap operator and bundler executor | dev / DevOps | 🧑 | ✅ funded by the tech lead (2026-11-17) |
| 5.3 | Confirm balances | 🤖 | 🔍 | ✅ deployer 0.05 / admin 0.2 on both chains; executor to check |
| **6** | **Deploy Base Sepolia** | | | |
| 6.1 | `contracts:deploy` | 🤖 | ✋ ⛔ 🔍 | ✅ 2026-11-17 |
| 6.2 | `contracts:provision` | 🤖 | ✋ ⛔ 🔍 | ✅ 2026-11-17 |
| 6.3 | `contracts:timelock` | 🤖 | ✋ ⛔ 🔍 | ✅ 2026-11-17 |
| 6.4 | `contracts:handoff` | 🤖 | ✋ ⛔ 🔍 | ✅ 2026-11-17 |
| 6.5 | `contracts:doctor` | 🤖 | 🔍 | ✅ green (2 expected warnings) |
| 6.6 | `deploy:cli test-token` (test ERC-20 alone, D5; F12; PR #303) | 🤖 | ✋ ⛔ 🔍 | ✅ 2026-11-18 (`0xb37e4709…1ad4`, block 60413516) |
| **7** | **Deploy Ethereum Sepolia** (repeat 6.1–6.5) | 🤖 | ✋ ⛔ 🔍 | ✅ core, provision, timelock, hand-off, doctor (2026-11-17); test ERC-20 2026-11-18 (`0x886ce086…800b`) |
| **8** | **Publish the records** | | | |
| 8.1 | PR: deployment records, profiles, `addresses.ts`, changeset | dev | 🔍 ✋ | ✅ #304 merged |
| 8.2 | Release `@appliedblockchain/giano-contracts` | dev | ✋ | ✅ 7.1.0 published (2026-11-18) |
| **9** | **Sponsorship rules per tenant per chain** | 🤖 | 🔍 | ✅ 2026-11-23: 4 rules installed and read back |
| **10** | **Cut over `dev`** | | | |
| 10.1 | Snapshot the current `dev` configuration | DevOps | 🧑 | ✅ RDS snapshot (DevOps, 2026-11-19) |
| 10.2 | Announce the maintenance window / reset | dev | ✋ | ➖ |
| 10.3 | Update the `chains` secret and Terraform variables | DevOps | 🧑 🔍 | ✅ `chains` secret applied; full apply from `main` on 2026-11-19 19:40 (revision `:40`, F21 fixed) |
| 10.4 | `deploy/dev-<sha>` PR and roll | DevOps | ✋ | ✅ #314 merged (`22ddb623`); all 7 services on `3c8f8b58` |
| 10.4b | Clear `dev`'s user data at the switch: users, credentials, sessions; keep tenants, config, admins (D1, F8) | DevOps / dev | ✋ ⛔ 🔍 | ✅ reset 2026-11-19 (6 users, 24 sessions cleared; backup schema kept) |
| 10.5 | `GET /v1/version` lists both chains ready | 🤖 | 🔍 | ✅ both chains `ready`; console and roles checked; no breach, no drift; Base lag still catching up (F22) |
| **11** | **Smoke test each chain** (passkey account, sponsored tx, console) | dev | 🧑 🔍 | ✅ 2026-11-23 by `pnpm -F @appliedblockchain/giano-e2e smoke` (#328), both tenants, both chains |
| **12** | **Retire the legacy deployment** | DevOps / tenants | 🧑 ✋ | ⏸ deferred: ≈ 0.35 ETH recoverable, documented below |
| **13** | **Timelocked upgrade queued by the admin key** (Base Sepolia; no Safe on testnet, D2) | dev | 🧑 ✋ | ⏸ deferred (2026-11-23) |
| **14** | **Close out**: report, memory, tickets | dev | 🔍 | 🔄 tracker committed (this file, public-safe version); follow-ups in G46; backup-schema drop and closing message left |

---

## Phase 0: land the tooling (PR #279)

Nothing below can run from `main` until #279 is merged.

### 0.1 Fix the four blocking review comments

Raised by the reviewer on #279. Each one can leave roles in the wrong hands on a live chain, so all
four are blocking.

| ID | Where | Problem | Fix |
|---|---|---|---|
| B1 | `packages/contracts/scripts/provision-paymaster.ts:238` | A failed run followed by a rerun leaves SIGNER_ADMIN, STAKE_ADMIN and TENANT_ADMIN on the bootstrap key: the rerun sees the role already held and never adds it to `temporary`. | Wrap the steps in `try/finally` so the revoke always runs; let the end state decide what is revoked (any needed role the bootstrap key holds without a named holder). |
| B2 | `provision-paymaster.ts:316` | `--role-holder-*` values are validated only after ETH has been spent. | Validate every named holder before the first transaction (near line 191). |
| B3 | `packages/contracts/deploy/preflight.ts:467` | An empty `catch` turns a failed `eth_getLogs` into a passed "no extra proposers" check. On a 200-block RPC the query always fails. | Fail closed, or query in chunks. Cover CANCELLER_ROLE and EXECUTOR_ROLE too. The 200-block chunking fits the N4 decision. |
| B4 | `packages/contracts/deploy/cli.ts:857` | On the profile path, `handoff` never compares `--timelock` with `profile.timelock.address`. | Refuse a `--timelock` that differs from the published one; take `deployedIn` from the matching record only. |

- **Who:** dev (agent can implement). 🔍 The reviewer checks the fixes.
- **Done when:** each fix has a test; `pnpm lint`, `pnpm -F @appliedblockchain/giano-contracts test:deploy` and `typecheck` pass; each thread has a reply.

**Result:**
> ✅ **2026-11-16**, commit `2695cb43` on #279.
> - **B1:** the run's steps sit in a `try`; on failure the run roles (signer, stake and tenant admin) are given up before rethrowing. What is revoked follows the end state: any of the three the bootstrap key holds without being its named holder. Verify fails if one is left. **Behaviour change:** a bootstrap key that held one of these roles before the run, with no named holder, now loses it.
> - **B2:** holders, `--grant-all-to`, signers, stake and tenant funding are all checked before the first transaction.
> - **B3:** role-grant history read in 200-block chunks from the deployment block; PROPOSER, CANCELLER, EXECUTOR and DEFAULT_ADMIN grants compared with who may hold them; a failed query or unknown deployment block fails the hand-off. New `--from-block` flag on `deploy:cli handoff`.
> - **B4:** `timelockMismatch` refuses a `--timelock` other than the profile's (else the record's); `deployedIn` only from the matching record.
> - Also found while testing: viem caches `getBlockNumber` for ~4 s, so the chunked scan read a stale head and missed fresh grants. It now reads the head with `cacheTime: 0`.
> - OpenSpec: spec scenarios and tasks 11.1–11.4 added; `openspec validate` passes.
> - Tests: `test:deploy` 111/111, `test:deploy:integration` 4/4, typecheck clean. Replied on all four threads (not resolved; that's for the reviewer).

### 0.2 Non-blocking comments: in #279 or a follow-up

🗳 The remaining five comments: wrapper accepts a partial or duplicate `ROLE_HOLDER_*` set (mainnet
should require all six, distinct); signer address vs key drift; preflight reports every error as
"Cancun unavailable"; doctor and rehearse print keyed RPC URLs unredacted; `DEPLOYMENTS_DIR` switches
before the fork check. The RPC URL leak matters for steps 4–7 because they run with keyed RPCs.

- **Who:** dev proposes, tech lead decides.
- **Recommendation:** fix the URL redaction and the signer drift check in #279 (both bite during this rollout); the rest in a follow-up.

**Result:**
> ✅ **2026-11-16**: the user chose the recommendation. Commit `97a453b7`:
> - **RPC URL redaction (R1):** a new `redactRpcUrls` in `deploy/config.ts`. The doctor catches `chainPrerequisites` errors and reports them redacted, and its top-level handler redacts the connected RPC, `RPC_URL` and `--rpc`. The rehearsal redacts the fork URL in step logs and details. `deploy:cli` uses the same helper.
> - **Signer drift (R2):** `provision-paymaster.sh` refuses when the address and the key's address differ; `operator.env.example` updated.
> - OpenSpec tasks 11.5–11.6. Tests: `test:deploy` 113/113, integration 4/4. Replied on both threads.
> - **Follow-up PR (not started):** mainnet requiring all six distinct role holders, the Cancun error classification (`preflight.ts:236`), `DEPLOYMENTS_DIR` resolving before the fork check (`records.ts:39`).

### 0.3 Record the N4 decision

The tech lead answered the N4 question on #279: _"Let's shrink the getLogs block span to 200 for
now. We can optimize the entire process later."_ Update the "Decisions needed first" table in
`TESTNET-ROLLOUT.md`, the evidence file and the PR body: decided, done in Phase 1, and steps 3 and 9
no longer need a 9,000-block RPC once Phase 1 has merged.

- **Who:** dev. 🔍 Read the diff.

**Result:**
> ✅ **2026-11-16**, in `2695cb43`: `TESTNET-ROLLOUT.md` (decision row, step 3, `GIANO_CHAINS` draft), `DEMO.md`, `rehearsal-evidence.md`. PR body: "Decision needed" section replaced by "Decided" plus a "Review fixes" section.

### 0.4 Rebase, CI, review, approval

The branch is 6 commits behind `main` (as of 2026-11-16). Rebase, push, `gh pr checks 279`, reply to
and resolve every thread (`main` requires resolved threads to merge), re-request review.

- **Who:** dev. ✋ Approval from the reviewers.
- **Done when:** approved, every required check green, no open thread.

**Result:**
> 🔄 **2026-11-16**: merged `origin/main` into the branch (`0ad45429`, clean) instead of rebasing, so no force-push is needed. `main` bumped Biome 2.5.15 → 2.6.5, which formats YAML: reformatted the two compose files this PR adds (`84f39459`). Pushed `c950c904..84f39459`. Local `pnpm lint` still reports two errors that aren't ours: `e2e/devnet/state-31338.json`, tracked from `main` and over Biome's 1 MiB limit, and the untracked `.claude/settings.local.json`. CI running; re-review not yet requested.
> ✅ **Final:** #279 merged 2026-11-16 (`dacd42ee`).

### 0.5 Merge and archive

✋ Merge only when the user asks (`gh pr merge 279 --merge`). Then archive the OpenSpec change
`harden-contract-deployment` in its own PR.

**Result:**
> 🔄 **2026-11-16 13:19 UTC**: #279 merged with a merge commit (`dacd42ee`) after CI green at `9174def1` (40 pass), the reviewer's approval and all 12 threads resolved. The six deferred threads were answered "moved to the follow-up PR" (R3–R8). **Left:** archive the OpenSpec change `harden-contract-deployment` in its own PR. Notion ticket G42 created for the six follow-ups (Notion).
> ✅ **Final:** #279 merged; the OpenSpec change archived in #293 (merged 2026-11-17).

## Phase 1: N4, shrink the `eth_getLogs` span to 200

`https://sepolia.base.org` refuses an `eth_getLogs` wider than 200 blocks. Today the paymaster watcher
asks for up to 9,000 (5,000 on a cold start), is refused, retries the same range forever, and every
tenant reads as unfunded, so every sponsorship is refused. Decision (tech lead, answered on #279 by
2026-11-16): use a 200-block span now, optimise the whole process later.

### 1.1 Confirm the scope

🗳 Three code paths assume a wide window. The decision clearly covers the first; the others are
the same problem in the console and the deploy tooling.

| Path | Today | With a 200-block RPC |
|---|---|---|
| wallet-api watcher, `MAX_POLL_RANGE` (`services/wallet-api/src/services/paymaster-watcher.ts:107`) | 9,000; cold start looks back 5,000 | Never ingests. **The blocker.** At 200 blocks per 4 s poll it still catches up about 100× faster than Base produces blocks. |
| Paymaster SDK `DEFAULT_LOG_WINDOW` 9,000 and `MIN_LOG_WINDOW` 250 (`packages/paymaster-sdk/src/log-window.ts`), used by the console; wallet-api's `PLATFORM_RPC_MAX_LOG_BLOCKS` must be ≥ 9,000 (`config.ts:157`) | Narrows on refusal, but stops at 250 | The console's History and pending-operations views fail. A published package, so it needs a changeset. |
| Contracts hand-off proposer check (`preflight.ts:467`) | One query from the timelock's deploy block | Covered by B3 in step 0.1. |

- **Recommendation:** a 200-block constant in the watcher (optionally an env override, default 200)
  and in the SDK window, with `MIN_LOG_WINDOW` at or below 200 and the relay minimum lowered to match.
  Ask the tech lead whether the console part belongs in the same PR.

**Result:**
> ✅ **2026-11-16**: the user said to start Phase 1; scope set by the recommendation, open for the tech lead's review on the PR.
> - **Measured `sepolia.base.org`:** it serves `toBlock - fromBlock` up to 200 (199, 200 and 201 blocks inclusive served; 202, 250 and 9,000 refused with `eth_getLogs is limited to a 200 range`, -32614).
> - **Watcher:** `MAX_POLL_RANGE` from 9,000 to 200 (the blocker).
> - **SDK/console:** the SDK already narrows a refused span by halving, and its matcher recognises Base's message; only its floor (`MIN_LOG_WINDOW` = 250) was above Base's cap. Floor from 250 to 200. The first request stays 9,000, so wide RPCs keep wide windows.
> - **Relay:** `PLATFORM_RPC_MAX_LOG_BLOCKS` (at least 9,000) unchanged; it passes node errors through unchanged (`rpc-read-relay.ts`), so the SDK sees Base's refusal.
> - **No OpenSpec change:** no main spec pins either number.

### 1.2 Implement, test, PR

Branch `fix/watcher-log-span` (or as agreed), tests for the clamp, `pnpm changeset` if the SDK changes,
lint, `pnpm -F <package> test` and `typecheck` for each package touched. PR title like
`fix(wallet-api): shrink the watcher's eth_getLogs span to 200 blocks`.

- 🔍 Review. ✋ Merge when the user asks.

**Result:**
> 🔄 **2026-11-16**: branch `fix/getlogs-span-200`, commit `5172a2f0`, **draft PR [#294](https://github.com/appliedblockchain/giano/pull/294)**.
> - Code: watcher span 200 (comment explains the measurement and the decision); SDK floor 200; patch changeset for `@appliedblockchain/giano-paymaster-sdk`.
> - Tests: watcher range tests now assert Base's cap (a 79,409-block backlog takes 398 passes); new SDK test models Base (201 blocks inclusive) and narrows 9,000 → … → 200.
> - Results: wallet-api 604/604 (testcontainers Postgres), paymaster-sdk 158/158, paymaster-admin 172/172, typecheck clean for all three, lint no errors.
> - Docs: PAYMASTER-SPECS §8.2, DEMO.md, TESTNET-ROLLOUT.md (decision row "done", step 3 no longer needs `--fork-url`, `GIANO_CHAINS` draft).
> - Added commit `a41b9b86`: rehearsal step `watcher-caught-up` (polls `giano_paymaster_watcher_lag_blocks`), and TESTNET-ROLLOUT step 10 waits for the lag. PR body has the gate results. **Marked ready for review**; no reviewers requested yet.
> ✅ **Final:** #294 approved and merged 2026-11-17 (`4e29eb72`).

### 1.3 Prove it

Rehearse with the profile's public RPC, which the 9,000 span failed against before:
`pnpm contracts:rehearse --chain base-sepolia --platform` (no `--fork-url`). The gate must pass,
including the sponsored smoke; the watcher metrics must show the cursor advancing.

- 🤖 Agent runs. 🔍 Read the gate output.

**Result:**
> ✅ **2026-11-16**: `pnpm contracts:rehearse --chain base-sepolia --platform`, **no `--fork-url`** (fork reads through `sepolia.base.org`), forked at block 59577592. **17/17 steps passed.**
> - `watcher-caught-up`: caught up in 84 s (lag 1 block). `browser-smoke` ✓.
> - Sponsored ops booked by the watcher: account deploy `0x28002a10bac5a3f3b39af59eea4ba2c7e40d62d40bd3a17a28ace92733fd26cc` (block 59577755) and `#send` `0xe8167618d6ad6f75fab161a66604810c4d6d9d8683d1f7b47b3ea56134d5c6a0` (block 59577757); ledger balance 0.05 → 0.048462722990639061 ETH.
> - wallet-api logs: 0 sponsorship refusals, 0 `limited to a 200 range` errors. One false `paymaster-unexplained-drawdown` alert 60 s after start, during the cold-start replay (F5).
> - The first run (before the new step) was 15/16: the smoke started during the replay (F5). The smoke rerun alone passed once the watcher had caught up.
> - Cleanup: rehearsal stack and fork taken down; e2e stack restarted (healthy).

### 1.4 Merge and update the docs

✋ Merge. Then remove the 9,000-block RPC requirement from `TESTNET-ROLLOUT.md` steps 3 and 9 and from
the `GIANO_CHAINS` draft.

**Result:**
> ✅ **2026-11-17**: #294 merged with a merge commit (`4e29eb72`) after the reviewer's approval (2026-11-16 16:27, on the last commit `1dd2b2ba`) and green CI. The docs change shipped in the PR itself: `TESTNET-ROLLOUT.md` no longer asks for a 9,000-block RPC (checked), and its `GIANO_CHAINS` draft carries `"bundler": {"maxBlockRange": 200}` for the public Base RPC.

## Phase 2: decisions

Each needs an answer, with who gave it and when, before the step that depends on it.

**Draft for the owners:** [`TESTNET-ROLLOUT-DECISIONS.md`](TESTNET-ROLLOUT-DECISIONS.md) (facts, options, recommendation for each; D7–D9 added; updated after D8 and the #294 review). Posted in the team channel on 2026-11-16; all answered or approved by 2026-11-17.

| # | Decision | Owner | Needed by | Answer | Date |
|---|---|---|---|---|---|
| 2.1 | Reset `dev` (announce, drain the legacy paymaster, let test wallets go) or migrate the legacy v0.7 accounts (no tool exists) | tech lead | 10, 12 | Reset: switch `dev`, clear users/credentials/sessions (keep tenants, config, admins), then withdraw the legacy paymaster | 2026-11-17 |
| 2.2 | The testnet timelock's proposer Safe and its signers, on each chain | tech lead | 3.4 | The tech lead: one EOA admin key for every admin role, proposer included; no Safe on testnet (Phase 13 becomes an upgrade queued by that key) | 2026-11-17 |
| 2.3 | One address per `ROLE_HOLDER_*`, or `PAYMASTER_GRANT_ALL_TO` for a developer-held testnet | tech lead | 3.5 | The tech lead: the same EOA admin key for every immediate role (`PAYMASTER_GRANT_ALL_TO`) | 2026-11-17 |
| 2.4 | Keep the profiles' rehearsal timelock delays (5 min to 1 h) for testnet? | product | 4.2 | Keep the profiles' delays (5 min–1 h) | 2026-11-17 |
| 2.5 | Tenants (`slug:existing-uuid` pairs from `dev`), each tenant's `SPONSOR_ALLOWLIST` per chain, `TENANT_WITHDRAW_ADDRESS`, `TENANT_FUND_ETH` | tech lead / tenants | 3.5 | `example` and `byoui` on both chains; test ERC-20 (`deploy:cli test-token`, #303; first planned with `testing --fund-eth 0`, see F13) allow-listed for both; team withdrawal address (the admin key); `TENANT_FUND_ETH` 0.02 | 2026-11-17 |
| 2.6 | Keyed RPC for the deploy and for the `chains` secret, or the public endpoints | tech lead / DevOps | 3.5 | Keyed: `dev`'s QuickNode (ok up to 10,000 blocks; no `bundler` section) | 2026-11-17 |
| 2.7 (D7) | Testnet ETH: amounts and where it comes from | dev / DevOps | 5.2 | The tech lead funds (Giano accounts take no funds from other projects' accounts). Requested 2026-11-17: per chain, deployer `0xBf8e…41B5` 0.05 ETH and admin `0x0331…3030` 0.2 ETH (0.5 ETH total). Funded the same day, plus a deployer top-up (F14: 0.01 ETH asked, 0.05 ETH sent on each chain) | 2026-11-17 |
| 2.8 (D8) | Custody of the testnet canonical deployer key | tech lead | 3.1 | Own 1Password item; created (`0xBf8e…41B5`); #296 merged 2026-11-17; restricted access still to confirm (the reviewer's question) | 2026-11-16 |
| 2.9 (D9) | Fix G42 (R4–R6) before the first live deploy? | tech lead | 6 | Fix all six (R1–R6) in one PR before Phase 6: done, #298 merged 2026-11-17. G42's R1–R6 are this tracker's findings R3–R8 | 2026-11-16 |
| N4 | How wallet-api survives an RPC that caps `eth_getLogs` | tech lead | 1.1 | Shrink the span to 200 now; optimise later | by 2026-11-16 |

## Phase 3: keys and operator config

### 3.1 Testnet canonical deployer

🧑 ACT. Generate an independent random key and store it in its own 1Password item with restricted
access. It fixes the testnet wallet address space for good: treat it as long-lived and never reuse
it. The key never goes in a file; load it into the deploying shell only (`CANONICAL_DEPLOYER_PRIVATE_KEY`).

- ✋ The tech lead agrees the item name and who can read it.
- **Record:** the public address and the 1Password item name (not the key).

**Result:**
> ✅ **2026-11-16**, created by the developer with `create-testnet-deployer.sh` (`multichain-keygen` piped into `op item create`; key never displayed).
> - **Address:** `0xBf8e1e80ac0687f2dd0b2909f5a68E3f6d5c41B5`
> - **1Password:** item "Giano testnet canonical deployer"; the item also holds the address and the tool version.
> - **Tool:** `multichain-keygen 2.0.0`, `--rng openssl`, quiet mode. Not HD or derived.
> - **Open:** confirm the vault's members match D8 (devs who deploy + tech lead).
>
> Plan used:
> - **Policy:** ABIP-8 (Key Generation Ceremony) exempts "testnet-only keys that can never hold or move real value" (Exceptions §1), and `docs/key-ceremony.md` puts both canonical deployers out of ABIP-8 scope: the dev team creates them and keeps them in 1Password, as independent random keys, no ceremony record. Still, follow ABIP-8's generation method, because this key fixes the testnet addresses for good.
> - **Steps:** (1) the tech lead decides vault, item name and access (D8); (2) a clean shell with history off, `op signin`; (3) get `multichain-keygen` (toolbox installer via `gh`, or the GHCR image pinned by digest) and note its version; (4) `generate --type evm --rng openssl --quiet` piped through `jq` into `op item create --vault <vault> -`, never shown; (5) derive the address from the stored key with `op read … | derive --quiet` and save it on the item; (6) record vault, item, address and tool version here; (7) step 3.2's PR.
> - Repo check: `op` 2.33.1 and `jq` installed locally; `op item create -` takes a JSON template on stdin (keeps the key out of argv and history).

### 3.2 PR: `DEPLOYERS.testnet`

Set `DEPLOYERS.testnet` in `packages/contracts/deploy/config.ts` to the address from 3.1 and name the
1Password item in `docs/key-ceremony.md`. CI `check:determinism` then covers the testnet class, and the
target addresses change from the rehearsal ones.

- 🔍 Review. ✋ Merge.

**Result:**
> 🔄 **2026-11-16**: branch `feat/testnet-canonical-deployer`, commit `e3fd2d55`, **PR [#296](https://github.com/appliedblockchain/giano/pull/296)**, review requested from the tech lead.
> - `DEPLOYERS.testnet` = `0xBf8e1e80ac0687f2dd0b2909f5a68E3f6d5c41B5`; `docs/key-ceremony.md` names the 1Password item; `specs/MULTICHAIN_SPECS.md` §4.5 updated; empty changeset (`deploy/` is not published).
> - `check:determinism`: OK for local and **testnet**. The **expected testnet addresses** (the same on every testnet; Phase 4.1 compares against these):
>
>   | Contract | Address |
>   |---|---|
>   | wallet implementation | `0x265dA930A9253fCC09E120B6f89EE8a91BcA9406` |
>   | factory | `0xA9d72F088C0Cd0B78db44D4c79E847FddD52F635` |
>   | paymaster implementation | `0x3C99Acb0e2AE5C446E5eeab23D6cd7F40e9C5540` |
>   | paymaster proxy | `0xb2C7081be89D88f1da020530Ebd5c14b8871615a` |
>
> - `test:deploy` 113/113, `test:deploy:integration` 4/4, typecheck and lint clean.
> ✅ **Final:** #296 merged 2026-11-17 (`0bcf0864`). Still open: confirm the deployer item's vault access matches D8.

### 3.3 Other keys

🧑 ACT. Separate keys, each funded in 5.2:

| Key | Variable | Notes |
|---|---|---|
| Bootstrap operator | `DEPLOYER_PRIVATE_KEY` | Holds ROLE_ADMIN until the hand-off |
| Sponsorship signer | `SPONSORSHIP_SIGNER_ADDRESS` (+ key for wallet-api) | Must be the key `dev` wallet-api signs with; check address and key match (review comment, 0.2) |
| Bundler executor(s) | `BUNDLER_EXECUTOR_PRIVATE_KEYS` | The keys the `dev` bundler already uses, or new ones in its secret |

- **Record:** public addresses only.

**Result:**
> ✅ **2026-11-17** (addresses only; derived by the developer from the 1Password keys, balances read on-chain):
>
> | Key | Address | Base Sepolia | Ethereum Sepolia |
> |---|---|---|---|
> | Bootstrap operator = testnet admin | `0x033178C012FAAB6977FE3b760e5Ca9BBAb4F3030` | 0.2 ETH | 0.2 ETH |
> | Sponsorship signer (`dev`'s `sponsorship-signer-key`) | `0x48bCd7Dd70c6861aF0844F4dBC1dE6Df24048a44` | no ETH needed | no ETH needed |
> | Bundler executor (`dev`'s `alto-executor-key`) | `0x945BA79715f48D586380604147ae6cD9050b60aC` | 0.1 ETH (nonce 9) | 0.1 ETH (nonce 0) |
>
> The executor already holds more than the 0.05 ETH it needs on both chains. Finding F11: the legacy Ethereum Sepolia paymaster has a different signer registered.

### 3.4 Proposer Safe

🧑 ACT. Create the Safe from decision 2.2 on each chain (Safe{Wallet}), and add it to
`deploy/chains/<chain>.json` under `timelock.proposers`. Leave `timelock.executors` empty for open
execution.

- 🔍 Check the Safe's owners and threshold on the explorer.

**Result:**
> ➖ **Superseded 2026-11-17**: no Safe on testnet (the tech lead, D2). The testnet admin key is the proposer; PR #302 sets `timelock.proposers` in both profiles. `timelock.executors` stays empty (open execution).

### 3.5 Operator env files

Copy `deploy/contracts/operator.env.example` to `deploy/contracts/<chain>.local.env` (ignored) for each
chain and fill it from Phase 2 and 3: keys, role holders or `PAYMASTER_GRANT_ALL_TO`, `PAYMASTER_TENANTS`,
`TENANT_WITHDRAW_ADDRESS`, `SPONSOR_ALLOWLIST`, `STAKE_ETH`, `UNSTAKE_DELAY`, `TENANT_FUND_ETH`, and the
RPC variable (`BASE_SEPOLIA_RPC_URL`, `ETHEREUM_SEPOLIA_RPC_URL`).

- 🔍 A second person checks every address against Phase 2 (a typo here is spent ETH; see B2).

**Result:**
> ✅ **2026-11-17**: written with every public value, then the developer filled the QuickNode URL and the admin key. Checked without printing secrets: `DEPLOYER_PRIVATE_KEY` derives to the admin `0x033178C012FAAB6977FE3b760e5Ca9BBAb4F3030` in both; `BASE_SEPOLIA_RPC_URL` answers chain 84532 and `ETHEREUM_SEPOLIA_RPC_URL` 11155111 (both QuickNode, https); no canonical deployer key in either file. Signer `0x48bC…8a44`, grant-all and withdrawal = admin, both tenants, stake 0.1, unstake 86400, 0.02 ETH per tenant, allowlist = test ERC-20 `0x461E…8C93`. Path note: pass `--env-file` as an absolute path (the commands run from `packages/contracts`).

## Phase 4: rehearse with the real configuration

### 4.1 Read-only preflight

Run the plan against each public chain with the real deployer: chain id, CreateX, EntryPoint v0.9
runtime, and the four target addresses empty. Sends nothing.

- 🤖 Agent runs. 🔍 Compare the target addresses with what 3.2 predicts.

**Result:**
> ✅ **2026-11-17**: `deploy/guided.ts --plan` with the real deployer against `sepolia.base.org` and publicnode Ethereum Sepolia: RPC identity, CreateX upstream runtime, EntryPoint v0.9 canonical runtime and Cancun all OK on both; the four target addresses empty and equal to 3.2's (walletImpl `0x265dA930…9406`, factory `0xA9d72F08…F635`, paymasterImpl `0x3C99Acb0…5540`, proxy `0xb2C7081b…615a`). Only blocker: the deployer is unfunded. Recorded in deploy/contracts/README.md (#296).

### 4.2 Fork rehearsal, Base Sepolia

`pnpm contracts:rehearse --chain base-sepolia --platform` with the real profile and operator file.
Until Phase 1 is merged, add `--fork-url https://base-sepolia-rpc.publicnode.com`. The rehearsal
platform and the e2e stack share ports 8081 and 4337: stop the e2e stack first.

- 🤖 Agent runs. 🔍 Every step ✓.
- **Record:** the step table, the gate result, the rehearsal addresses.

**Result:**
> ✅ **2026-11-17**: `pnpm contracts:rehearse --chain base-sepolia --platform` on `main` after #294/#296/#298 (fork of `https://sepolia.base.org` at block 60045527, stand-in deployer `0x3d7C…B349`): **17/17**. fork, prepare, deploy, provision, timelock, handoff, upgrade-propose, upgrade-execute, plan-after-upgrade, verify-after-upgrade, provision-refused-after-handoff, doctor, clock-reset, platform-up, sponsorship-rules, watcher-caught-up (84 s, lag 1 block), browser-smoke (1 passed). No `--fork-url` needed (public 200-block RPC). The profiles' `roleAdmin` and proposers are replaced by the rehearsal's throwaway keys, so #302's values do not change the run. The e2e stack was stopped for it and restarted (8 containers).

### 4.3 Fork rehearsal, Ethereum Sepolia

Same with `--chain ethereum-sepolia`.

**Result:**
> ✅ **2026-11-17**: `pnpm contracts:rehearse --chain ethereum-sepolia --platform`: exit 0, through the browser smoke (1 passed: a new passkey wallet deployed and sent a sponsored transaction; tenant balance 0.05 → 0.049474 ETH after the deploy → 0.049144 ETH after the send). The step table was not kept: the next rehearsal cleared `deploy/rehearsal/` (it does so at every start), so only the exit code and the smoke result were captured. Keep a rehearsal's output outside `deploy/rehearsal/` (finding F10).

## Phase 5: funding

### 5.1 Amounts

`pnpm contracts:funding --chain <profile> --env-file deploy/contracts/<chain>.local.env` for each chain.

- 🤖 Agent runs. Record the printed table.

**Result:**
> ✅ **2026-11-17**: `pnpm contracts:funding` on both chains: operator `0x0331…3030` holds 0.2 ETH, suggested ~0.2 (stake 0.1 + tenant balance + gas). Deployer, executor and signer are not in the operator files by design; their balances were read directly (5.3, 3.3).

### 5.2 Fund

🧑 ACT. Send testnet ETH from a faucet or the team's testnet treasury, on each chain:

| Account | Amount (per `TESTNET-ROLLOUT.md` step 4) |
|---|---|
| Testnet deployer | ≥ 0.05 ETH (the profile's reserve) |
| Bootstrap operator | 0.1 ETH stake + tenant funding (`TENANT_FUND_ETH` × tenants) + gas |
| Bundler executor | ≥ 0.05 ETH |

**Result:**
> ✅ **2026-11-17**: The tech lead funded both Giano-only accounts on both chains (requested in the decisions thread).

### 5.3 Confirm balances

🤖 Agent reads the balances. 🔍 Each meets 5.1.

**Result:**
> ✅ **2026-11-17** (public RPCs, `eth_getBalance`, nonce 0 on all four, untouched):
>
> | Account | Base Sepolia | Ethereum Sepolia |
> |---|---|---|
> | Testnet deployer `0xBf8e1e80ac0687f2dd0b2909f5a68E3f6d5c41B5` | 0.05 ETH | 0.05 ETH |
> | Testnet admin `0x033178C012FAAB6977FE3b760e5Ca9BBAb4F3030` | 0.2 ETH | 0.2 ETH |
>
> The deployer meets the profile's 0.05 ETH reserve exactly. Bundler executor (`dev`'s key) not checked yet: address needed.
> ✅ **Final:** the bundler executor `0x945B…60aC` was checked in 3.3: 0.1 ETH on each chain.

## Phase 6: deploy Base Sepolia

Each sub-step sends real transactions. Before each one: ✋ go/no-go from the user. After each one:
🔍 check the transactions on the explorer (`https://sepolia.basescan.org`). If a receipt times out,
stop and inspect the nonce on the explorer before rerunning; a rerun with the same profile, release
and keys resumes (README "Recovery and evidence"). Never delete a record to force progress.

| # | Command | Irreversible effect | Check after |
|---|---|---|---|
| 6.1 | `pnpm contracts:deploy --chain base-sepolia` | ⛔ CREATE3 contracts at fixed addresses | Record written; addresses match 4.1 |
| 6.2 | `pnpm contracts:provision --chain base-sepolia --env-file …` | ⛔ Stake and tenant deposits sent; roles granted | Every immediate role on the admin key (`PAYMASTER_GRANT_ALL_TO`, D3), which is also the bootstrap key |
| 6.3 | `pnpm contracts:timelock --chain base-sepolia --env-file …` | ⛔ Timelock deployed; address saved in the profile | Proposers = the admin key `0x0331…3030` (D2); delays = 2.4 |
| 6.4 | `pnpm contracts:handoff --chain base-sepolia --env-file …` | ⛔ Timelocked roles moved; bootstrap ROLE_ADMIN renounced. Only the timelock can undo it, after the role delay | ✋ The user reads the plan output before it sends; `--timelock` equals the profile's (B4) |
| 6.5 | `pnpm contracts:doctor --chain base-sepolia` | none | Green |
| 6.6 | `deploy:cli testing --fund-eth 0 …` with the canonical deployer (D5) | ⛔ Test ERC-20 and an unfunded PermissivePaymaster at CREATE3 addresses | Token address recorded; PermissivePaymaster deposit 0 (F9) |

**Results:**

| # | Tx hashes / output | Status | Notes |
|---|---|---|---|
| 6.1 | walletImpl `0xd0cb69bb…55bf` (block 60059579), factory `0x36c39744…a874` (60059584), paymasterImpl `0x1ccf1318…be32` (60059592), proxy `0x8aca69de…39be` (60059598) | ✅ 2026-11-17 | All four from the deployer, status 1. Addresses = 4.1, `deterministic: true`; on-chain codehashes equal the record's; proxy implementation slot = paymasterImpl; `entryPoint()` = v0.9; `ROLE_ADMIN` on the admin key, not on the deployer. Deployer left with 0.04995 ETH (nonce 4). Record `packages/contracts/deployments/84532.json` written (commit at 8.1); the wizard re-saved the profile (formatting only) |
| 6.2 | 15 txs from the admin key `0x0331…3030` (nonce 0 → 15) | ✅ 2026-11-17 | EntryPoint deposit info: staked, stake 0.1 ETH, unstake delay 86400 s, deposit 0.04 ETH. Signer `0x48bC…8a44` registered (signerCount 1). Tenants `example` and `byoui`: registered, enabled, 0.02 ETH each, withdraw to the admin key, no deficit. Fee 0.0001 ETH, post-op 40000 gas, penalty 1000 bps, not paused. The admin key holds all six immediate roles and, until the hand-off, ROLE_ADMIN, UPGRADER, FEE_ADMIN and WITHDRAW_ADDRESS_ADMIN. Admin left with 0.05999 ETH |
| 6.3 | timelock `0x7Da25D415f9b68422F905C015137Af8D915F8A78`, tx `0xa8c8d50f…74b3` (block 60061948), from the admin key | ✅ 2026-11-17 | Release GianoTimelock (codehash `0x69373afb…bb5a` = record). PROPOSER and CANCELLER = admin key only; EXECUTOR = zero address (open execution); DEFAULT_ADMIN = the timelock itself. minDelay 300 s; effective delays on the paymaster: upgrade/grant/revoke/renounce 3600 s, withdraw address 1800 s, default fee 1200 s, tenant fee 600 s (= 2.4). Address saved in the profile and the record. Hand-off pre-flight (`deploy:cli handoff` without `--execute`): all checks pass; plan = 8 txs (grant UPGRADER, FEE_ADMIN, WITHDRAW_ADDRESS_ADMIN and ROLE_ADMIN to the timelock, revoke them from the admin key, renounce ROLE_ADMIN last) |
| 6.4 | 8 txs from the admin key (nonce 16 → 24; 15 was the timelock deploy in 6.3) | ✅ 2026-11-17 | ⛔ done. On-chain: ROLE_ADMIN, UPGRADER, FEE_ADMIN and WITHDRAW_ADDRESS_ADMIN held by the timelock only; the admin key holds exactly the six immediate roles (SIGNER_ADMIN, PARAM_ADMIN, PAUSER, STAKE_ADMIN, TENANT_ADMIN, FEE_COLLECTOR) |
| 6.5 | `pnpm contracts:doctor --chain base-sepolia` | ✅ 2026-11-17 | "all critical checks passed". Two expected warnings: signer `0x48bC…8a44` reported but not asserted (no `--signers`); proposer is a key, not a Safe (D2). Probe account (factory.getAddress, nonce 0) `0x8Db438C5676481Df22178Ba8d9Cb9C1c5C90c8b3`: must match on Ethereum Sepolia (MC-22). P-256 via RIP-7212 precompile on Base Sepolia |
| 6.6 | first refused by R-29 (nothing sent); then `test-token` (#303): `0xb37e4709…1ad4`, block 60413516 | ✅ 2026-11-18 | `deploy:cli testing` refuses 84532 (`PRODUCTION_CHAIN_IDS` includes the served testnets, on purpose: no permissive paymaster there), and the registry refused `testErc20` there too. D5 option 1 chosen: PR #303 adds `deploy:cli test-token` (token alone, canonical deployer only, never mainnet) and lets the registry carry `testErc20` on the served testnets. Run after #303 merges |

## Phase 7: deploy Ethereum Sepolia

Repeat Phase 6 with `--chain ethereum-sepolia`, the same release, deployer and bootstrap admin.
Explorer: `https://sepolia.etherscan.io`. Same go/no-go before each step.

| # | Tx hashes / output | Status | Notes |
|---|---|---|---|
| 7.1 deploy | | ✅ 2026-11-17 | see the results below |
| 7.2 provision | | ✅ 2026-11-17 | see the results below |
| 7.3 timelock | | ✅ 2026-11-17 | see the results below |
| 7.4 handoff | | ✅ 2026-11-17 | see the results below |
| 7.5 doctor | | ✅ 2026-11-17 | see the results below |

**7.1 result (2026-11-17):** ✅ after two stops (F15) and one refused rerun (F14), all four contracts at the deterministic
addresses, from the deployer, status 1: walletImpl `0x4fc273d9…1d42` (block 12155749), factory `0x1a8f5e62…6e21`
(12155820), paymasterImpl `0xb4e115f2…8a71` (12155821), proxy `0x7128edb6…59d2` (12155832). Codehashes equal the
record; proxy implementation slot = paymasterImpl; `entryPoint()` = v0.9; `ROLE_ADMIN` on the admin key, not the deployer.
Record `packages/contracts/deployments/11155111.json` (commit at 8.1). Deployer left with 0.09999 ETH (nonce 4).

**7.2 result (2026-11-17):** ✅ 15 txs from the admin key (nonce 0 → 15). EntryPoint: staked 0.1 ETH, unstake delay 86400 s,
deposit 0.04 ETH. Signer `0x48bC…8a44` registered (count 1). `example` and `byoui` registered, enabled, 0.02 ETH each, withdraw
to the admin key. Fee 0.0001 ETH, post-op 40000 gas, penalty 1000 bps, not paused. The admin key holds all ten roles until
the hand-off. Admin left with 0.06 ETH. Same state as Base Sepolia after 6.2.

**7.3 result (2026-11-17):** ✅ timelock `0x7Da25D415f9b68422F905C015137Af8D915F8A78` (the same address as on Base Sepolia),
block 12155866, from the admin key; codehash equal to the record and to Base's. PROPOSER and CANCELLER = admin key only;
EXECUTOR = zero address (open); DEFAULT_ADMIN = the timelock itself. minDelay 300 s; effective delays: upgrade/grant/revoke/
renounce 3600 s, withdraw address 1800 s, default fee 1200 s, tenant fee 600 s (= D4). Saved in the profile and the record.
Hand-off pre-flight: all checks pass; the same 8-tx plan as Base.

**7.4 result (2026-11-17):** ✅ after four runs (three stopped on out-of-gas reverts from stale gas estimates, F15; one refused by the
public RPC's failed log query). Final state: ROLE_ADMIN, UPGRADER, FEE_ADMIN and WITHDRAW_ADDRESS_ADMIN on the timelock only; the
admin key holds exactly the six immediate roles. At no point did the admin key give up ROLE_ADMIN before the timelock held it.
Admin key left with 0.06 ETH (nonce 28).

**7.5 result (2026-11-17):** ✅ `contracts:doctor --chain ethereum-sepolia`: "all critical checks passed", with the same two
expected warnings as Base (signer not asserted; key proposer, D2). Probe account `0x8Db438C5676481Df22178Ba8d9Cb9C1c5C90c8b3`
equals Base Sepolia's: the factory derives the same wallet address on both chains (MC-22). P-256 via the RIP-7212 precompile.

## Phase 8: publish the records

### 8.1 PR

Commit `packages/contracts/deployments/84532.json` and `11155111.json`, both profiles (with their
timelock addresses) and the regenerated `addresses.ts`, plus a changeset for
`@appliedblockchain/giano-contracts`. Stage the files by name: never `git add -A` under
`packages/contracts`.

- 🔍 Review: the addresses equal Phase 6 and 7. ✋ Merge.

**Result:**
> ✅ **2026-11-18**: PR #304 merged (`cfbe9135`) after the reviewer's approval (he re-verified both chains with `cast`) and his three doc comments (`9fa34563`); a conflict with #303 in TESTNET-ROLLOUT resolved in `095ba46e`. The test ERC-20 records followed in PR #309, merged (`918023cf`). `main` now carries both chains' records and `addresses.ts` with factory, implementation, paymaster and `testErc20`.
>
> Opened **2026-11-17**: PR #304 (`feat/testnet-v3-records`, `08288d74`): both deployment records, regenerated `addresses.ts` (2 chains), the profiles' timelock address, INFRASTRUCTURE §13 / deployments README / TESTNET-ROLLOUT steps 5–7, minor changeset. `check:determinism` OK for the four testnet addresses; `test:deploy` 123/123; wallet-api multichain 47/47; bundler, paymaster-sdk green; wallet-kit's 6 failures also on `main` (local Node 26 `localStorage`). The test ERC-20 follows after #303.

### 8.2 Release

✋ Merge the Changesets "version packages" PR and confirm the package is published. With the package
released, `factory` and `entryPoint` may be left out of `GIANO_CHAINS`.

**Result:**
> ✅ **2026-11-18**: #291 merged (`f6596229`) after the tech lead's approval and the lockfile fix (F17). Release run 44316032265: CI and Determinism green, then "packages published successfully" for all seven at **7.1.0** (connector, contracts, paymaster-sdk, tx-describe, wallet-core, wallet-kit, wallet-transport); tag `v7.1.0` pushed; the `docker.yml` build for `v7.1.0` started. (The packages are restricted, so `npm view` needs registry credentials.)
>
> Before: 🔄 **2026-11-18**: the version PR #291 bumps all seven packages 7.0.1 → 7.1.0. Its `giano-contracts` changelog carries #279, #298, #303, #304 and #309, plus other unreleased work on `main` (Silent Data H6: bundler `stateOverride`, `GianoTestPrivateErc20`, the proxy read without `eth_getStorageAt`, `--signed-rpc`). No checks run on the bot's PR; the release workflow publishes only after CI and Determinism pass on `main`. Asked the tech lead and the reviewer (the team channel) whether `main` is OK to release and for an approval. Merging publishes to npm and tags `v7.1.0`.

## Phase 9: sponsorship rules

For each tenant on each chain: `pnpm contracts:sponsorship --chain <profile> --env-file …` with the
tenant's `SPONSOR_ALLOWLIST`, or the console. An empty allowlist sponsors nothing, wallet management
included.

- 🤖 Agent runs. 🔍 The rules read back as decided in 2.5.

| Tenant | Base Sepolia | Ethereum Sepolia |
|---|---|---|
| `example` (`cf0d5345…`) | ✅ 2026-11-23 | ✅ 2026-11-23 |
| `byoui` (`743480a4…`) | ✅ 2026-11-23 | ✅ 2026-11-23 |

Allowlist: the test ERC-20 `0x461E0641a3615336b7D2E4C5D71fB2BB88038C93` (D5). Through `dev`'s wallet-api, so after the cut-over
(Phase 10) once it serves both chains.

## Phase 10: cut over `dev`

### 10.1 Snapshot

🧑 DevOps saves the current `chains` secret, `infra/versions.json` `dev` SHA, Terraform variables,
tenant policies and the wallet/account inventory, for the rollback.

- **Record:** where the snapshot is kept.

**Result:**
> ✅ **2026-11-19, DevOps:** manual RDS snapshot taken (runbook step 1). Snapshot name not reported in the thread.

### 10.2 Announce

✋ Post the maintenance window and, if 2.1 is a reset, that legacy test wallets go away. Draft in
`the team channel`; post only when the user says so.

**Result:**
> ➖ **Skipped (2026-11-16, user):** the team controls `dev`, so no announcement is needed for this cut-over.

### 10.3 Secret and Terraform

🧑 DevOps updates the `chains` secret (`GIANO_CHAINS`, drafts in `TESTNET-ROLLOUT.md`), and
`paymaster_address` / `factory_address` in `infra/iac/ecs_services.vars.tf`. Set the dApp's `defaultToken`
to the test ERC-20 from 6.6 (D5); clear any `TEST_PAYMASTER_ADDRESS` override (the PermissivePaymaster is
never served).

- 🔍 Review the `terraform plan`.

**Result:**
> ⚠️ **2026-11-19, DevOps:** `chains` secret updated and applied with `-target`; reset run on the new task definition
> (before: 6 users, 6 credentials, 24 sessions; after: 0; tenants 2 and platform admins 1 kept); full `terraform apply` run.
> But three services still run the env from before #311 (F21): the full apply ran from a local checkout without #314, so it
> registered task definitions with image `5ba71241`, which is gone from ECR, and the circuit breaker rolled every service back to
> `deploy.yml`'s revision. DevOps will pull `main` and apply again.
>
> ✅ **2026-11-19 19:40 UTC, DevOps:** pulled `main` and applied; services on `3c8f8b58` (revision `:40`), up since 2026-11-20 07:00.
> Checked 2026-11-23 10:38 UTC: both dApps' `config.js` carry `defaultToken` `0x461E…8C93` on both chains, and `wallet-byo`'s bundle has
> the v3 factory `0xA9d7…F635` (no legacy factory).

### 10.4 Roll

`deploy/dev-<sha>` PR bumping `infra/versions.json` `dev` to the tested `main` SHA (which includes
Phase 1). ✋ Merge, then DevOps rolls.

**Result:**
> ✅ **2026-11-19:** #314 merged as `22ddb623`; Deploy rolled all 7 `dev` services to `3c8f8b58`.

### 10.5 Readiness

🤖 `GET /v1/version` lists both chains ready. Check the watcher's cursor advances on both chains
(the `dev-logs` skill reads wallet-api's CloudWatch logs).

**Result:**
> 🔄 **2026-11-19 15:53 UTC:** `GET /v1/version` → 7.1.0, Base Sepolia `ready`, Ethereum Sepolia `ready`. The watcher lag
> metric (`/metrics` needs the bearer token) and the console check are not done yet. Blocked for the `byoui` tenant by F21.
> ✅ **Final (2026-11-23):** readiness complete. Metrics: both chains available, no invariant breach, no drift after Phase 9;
> console and Roles tab checked; F21 fixed (both dApps carry `defaultToken`, the BYO wallet uses the v3 factory). The Base
> Sepolia watcher lag (F22) is expected after each scale-down.

## Phase 11: smoke test each chain

🧑 ACT (passkeys need a person at a browser). On each chain: create a passkey account, sign, send a
sponsored transaction. Then 🔍 check the operator console shows the tenant, its balance and the
timelock (the fork rehearsal never covered the console). Check sponsorship accounting and executor
reimbursement.

| Chain | Account address | Sponsored tx | Console | Status |
|---|---|---|---|---|
| Base Sepolia | `example` `0x3523…DB7a`; `byoui` `0xC017…E0b3` | mint, `example` `0x7d2e45c1…9f2e`; `byoui` `0xccb87e48…1f95` | balances dropped (84532: byoui 0.0198, example 0.0196) | ✅ 2026-11-23 |
| Ethereum Sepolia | same addresses (MC-22) | mint, `example` `0x3a4327cc…d658`; `byoui` `0x01e9c7c2…adc6` | not checked in the console (the smoke test checked each transaction on chain) | ✅ 2026-11-23 |

## Phase 12: retire the legacy deployment

Only after Phase 11 passes on both chains (until then the legacy contracts are the rollback).
🧑 Withdraw the legacy paymaster's tenant balances to each tenant's withdrawal address, unlock the
stake, wait the unstake delay, withdraw the stake. ✋ The tenants agree to the withdrawal.

- **Done when:** the legacy deposit and stake are zero.

**Result:**
> 🔄 **2026-11-23, legacy state read on chain** (proxy `0xf98b56de…0718` on both chains, implementation `0xec7bfa2e…0434`, EntryPoint v0.7,
> role ids `keccak256("giano.paymaster.<ROLE>")`):
>
> | | Base Sepolia | Ethereum Sepolia |
> |---|---|---|
> | Every role held, and every tenant's withdraw address | `0xB622…BD87` (FEE_COLLECTOR, FEE_ADMIN, PARAM_ADMIN, PAUSER: nobody) | `0xFebB…a09d` (the tech lead; all nine roles) |
> | Tenant `example` (`cf0d5345…`) | 0.049083966488 ETH | 0.02 ETH |
> | Tenant `byoui` (`743480a4…`) | 0.05 ETH | 0.02 ETH |
> | Other tenants | none | two disabled e2e ids `0xa1…01`, `0xa1…02`, 0 ETH |
> | Treasury (fees) | 0.0009 ETH (needs FEE_COLLECTOR, granted by ROLE_ADMIN) | 0 |
> | EntryPoint deposit | 0.099985178272 ETH | 0.04 ETH |
> | Stake (unstake delay 86400 s) | 0.1 ETH | 0.11 ETH |
>
> Steps per chain, signed by that chain's holder: `withdrawTenant(id, balance, to)` for each tenant (only the withdraw address may
> call it); on Base, `grantRole(FEE_COLLECTOR)` then `withdrawFees`; `unlockStake()`, wait 24 h, `withdrawStake(to)`. Open: who
> holds `0xB622…BD87`, and where the recovered ETH goes.
>
> ⏸ **Deferred (2026-11-23, user):** recoverable ≈ 0.2 ETH on Base Sepolia and 0.15 ETH on Ethereum Sepolia, left in place to be
> handled later. Nothing depends on it: `dev` no longer uses the legacy contracts. Before acting: re-read the balances (they do not
> change while nobody signs), find the holder of `0xB622…BD87`, and choose the destination.

## Phase 13: timelocked upgrade queued by the admin key

On Base Sepolia (runbook `docs/PAYMASTER-TIMELOCK-RUNBOOK.md` §6, with an EOA instead of a Safe: no Safe
on testnet, D2): queue a paymaster upgrade with the testnet admin key as proposer, wait the delay, execute. The tooling reconciles the upgrade
into the record; then `contracts:doctor` must be green.

**Result:**
> ⏸ **Deferred (2026-11-23, user).** Plan when it resumes: there is no release after v3, so `deploy:cli upgrade --contract paymaster
> --timelock 0x7Da2…8A78` deploys `giano.paymaster.impl@v3` (the same v3 code at a new address) and prints the proposal; the admin key
> schedules it, wait 1 h, anyone executes, the tooling reconciles the record, `contracts:doctor` green, a PR with the record. Then
> `pnpm -F @appliedblockchain/giano-e2e smoke --target …` (#328) confirms sponsorship on the upgraded paymaster.

## Phase 14: close out

Summarise the run log and findings for the team, update the Notion ticket, and commit this tracker
(addresses and hashes only).

**Result:**
> 🔄 **2026-11-23.** Left:
> - **Reviews:** #326 (runbook, F19 and F21) and #328 (smoke test), both green, review requested from the reviewer (GitHub, and the team channel
>).
> - **Backup schema:** `DROP SCHEMA cutover_v3_backup CASCADE` through `dev-db-run.sh`: go-ahead given 2026-11-23, asked of DevOps in the
>   the DevOps request thread, with thanks for the cut-over. The 19 Nov RDS snapshot stays as the last resort.
> - ✅ **This tracker and the decisions file:** committed in a public-safe version (2026-11-23): no 1Password IDs, Slack
>   references or personal names. The full working log is on the private Notion tracker page.
> - ✅ **Follow-up ticket G46** (Backlog, (Notion): R1 F15, R2 F17, R3 F22, R4 F23,
>   R5 Phase 12 (legacy funds), R6 Phase 13 (upgrade); links G44 (#310's deferred items), G35 (R27/F19), G33, #326, #328.
> - **Small items:** The reviewer's #296 questions (the deployer item's restricted access, the ticket code); keep or revoke the Phase 9 tenant
>   admin keys.
> - **Closing message** in the team channel and the final Notion update.
> - **Watch:** The reviewer's #329 rolls dev to `2ddc170f` (7.2.1, iron-kestrel) with Terraform changes from #318: apply from a checkout that
>   includes it (F21), then run the smoke test against both dApps.

---

## Findings register

Anything unexpected: a failure, a doc that was wrong, a gap in the tooling. Carried over from the
rehearsal (N1–N5 in `openspec/changes/archive/2026-11-16-harden-contract-deployment/rehearsal-evidence.md`) only where
it still affects this rollout.

| ID | Date | Step | Finding | Severity | Resolution | Status |
|---|---|---|---|---|---|---|
| N4 | 2026-11-12 | rehearsal | Watcher's 9,000-block `eth_getLogs` refused by `sepolia.base.org` (200 cap); every tenant reads as unfunded | blocker | Shrink to 200 (tech lead); PR #294 merged (`4e29eb72`) | ✅ |
| B1 | 2026-11-16 | review #279 | Provision rerun leaves temporary roles on the bootstrap key | blocker | Fixed in `2695cb43` | ✅ |
| B2 | 2026-11-16 | review #279 | Role holders validated after ETH is spent | blocker | Fixed in `2695cb43` | ✅ |
| B3 | 2026-11-16 | review #279 | Hand-off proposer check passes silently when `eth_getLogs` fails | blocker | Fixed in `2695cb43` (200-block chunks, fail closed) | ✅ |
| B4 | 2026-11-16 | review #279 | Hand-off doesn't compare `--timelock` with the profile's | blocker | Fixed in `2695cb43` | ✅ |
| R1 | 2026-11-16 | review #279 | Keyed RPC URLs printed unredacted by doctor and rehearse | medium | Fixed in `97a453b7` | ✅ |
| R2 | 2026-11-16 | review #279 | Signer address and key can drift apart; every sponsorship then fails | medium | Fixed in `97a453b7` | ✅ |
| R3 | 2026-11-16 | review #279 | Wrapper accepts a partial or duplicate set of role holders; mainnet should require six distinct | low | Fixed in PR #298 (G42), merged `e0cc95e1` | ✅ |
| R4 | 2026-11-16 | review #279 | Preflight reports transport errors as "Cancun unavailable" | low | Fixed in PR #298 (G42), merged `e0cc95e1` | ✅ |
| R5 | 2026-11-16 | review #279 | `DEPLOYMENTS_DIR` switches to rehearsal before the fork check | low | Fixed in PR #298 (G42), merged `e0cc95e1` | ✅ |
| R6 | 2026-11-16 | re-review #279 | `handoff` accepts any timelock when neither the profile nor the record names an address | low | Fixed in PR #298 (G42), merged `e0cc95e1` | ✅ |
| R7 | 2026-11-16 | re-review #279 | `--from-block` later than the deployment block skips earlier grants | low | Fixed in PR #298 (G42), merged `e0cc95e1` | ✅ |
| R8 | 2026-11-16 | re-review #279 | `--unstake-delay` is parsed after the first transaction | low | Fixed in PR #298 (G42), merged `e0cc95e1` | ✅ |
| F4 | 2026-11-16 | 1.1 | The SDK's log-read narrowing stopped at 250 blocks, above Base's 200 cap, so every console log read on `sepolia.base.org` failed as well (same root cause as N4, console side) | high | Floor 200 in PR #294, merged (`4e29eb72`) | ✅ |
| F5 | 2026-11-16 | 1.3 | With a 200-block span, a fresh wallet-api (empty database) needs ~2 minutes to replay its 5,000-block cold-start lookback through a public RPC. Until then every tenant reads as unfunded and sponsorship is refused (`insufficient-balance`). The rehearsal's browser smoke started inside that window and failed | medium | Rehearsal waits on `giano_paymaster_watcher_lag_blocks` (new `watcher-caught-up` step, #294); TESTNET-ROLLOUT step 10 waits for it too. Also: the `paymaster-unexplained-drawdown` alert fires falsely once during the replay (relevant to G28) | ✅ |
| F6 | 2026-11-16 | review #294 | The bundler's receipt lookup (operations it didn't submit) reads `bundler.maxBlockRange` = 2,000 blocks, refused by `sepolia.base.org` | medium | Docs: `"bundler": {"maxBlockRange": 200}` with the public RPC, or keyed RPC (recommended; D6) | ✅ docs |
| F7 | 2026-11-16 | review #294 | Console forward reads re-narrowed from ~9,000 to 200 for every 200 blocks (6 refused calls each); a 45,000-block read ≈ 650 relay calls, can hit the relay's rate limit | medium | Ask for the narrowed span after a narrowing (`1dd2b2ba`): 1 refused + 225 served | ✅ |
| F8 | 2026-11-16 | D1 review | wallet-api stores each credential's wallet address at registration and never recomputes it; after the switch to v3, existing `dev` users would log in to their legacy v0.7 address, which the v0.9 stack can't operate | high | A reset must clear `dev`'s user data (users, credentials, sessions; keep tenants and admins) at the switch (Phase 10), not in Phase 12. D1 decided (reset): step 10.4b | ✅ reset 2026-11-19 (10.4b) |
| F9 | 2026-11-16 | D5 review | `deploy:cli testing` deploys a `PermissivePaymaster` (sponsors anything) next to the test ERC-20 and funds its deposit with `--fund-eth`; on a public testnet anyone can drain it | medium | Superseded: the served testnets refuse `testing` (R-29, F13); the token goes through `test-token` (#303), which deploys no permissive paymaster | ✅ |
| F10 | 2026-11-17 | 4.3 | A rehearsal clears `deploy/rehearsal/` (logs included) at every start, so running two in a row loses the first one's logs; also its platform and fork stay up afterwards and keep ports 8081/4337 from the e2e stack | low | Capture the summary outside `deploy/rehearsal/`; tear down with `docker compose -p giano-rehearsal down` and `-p giano-fork down` before restarting e2e | ✅ workaround |
| F11 | 2026-11-17 | 3.3 | `dev`'s legacy paymasters have different sponsorship signers: Base Sepolia `0x48bC…8a44` (= `dev`'s `sponsorship-signer-key`), Ethereum Sepolia `0xEc8e…9cD1` (no known key). wallet-api signs with one key, so legacy sponsorship on Ethereum Sepolia is refused; the executor's Ethereum Sepolia nonce is 0 | medium (legacy only) | The new deployment registers `0x48bC…8a44` on both chains (`SPONSORSHIP_SIGNER_ADDRESS`); the legacy one retires in Phase 12 | ✅ handled by the rollout |
| F12 | 2026-11-17 | 6.6 | `deploy:cli testing` (and `core`) sign with `DEPLOYER_PRIVATE_KEY`, the same name the operator files use for the admin key, and `testing` never checks the signer is the canonical deployer: run with the operator file loaded, the test ERC-20 would deploy from the admin key at another address than the allowlist's `0x461E…8C93` | medium | Run 6.6 with the canonical deployer key passed inline as `DEPLOYER_PRIVATE_KEY`, without the operator file, and check the printed signer; follow-up: refuse a signer that is not the class deployer | ✅ `test-token` refuses another signer (#303 merged) |
| F13 | 2026-11-17 | 6.6 | D5's premise was wrong: `deploy:cli testing` and the registry treat the served testnets as production (R-29), so the test ERC-20 could not be deployed or recorded there | medium | PR #303: token-only `test-token` command; registry refuses `testErc20` only on mainnets | ✅ #303 merged |
| F14 | 2026-11-17 | 7.1 | The deployer was funded with exactly the profile's 0.05 ETH reserve (`minDeployerBalanceEth`). The first contract's gas (0.0000000003 ETH) left it just below, so the rerun after the stop was refused ("has at least 0.05 ETH"): a deployer funded at the reserve can't resume a stopped deploy | low | The tech lead topped the deployer up (now ~0.1 ETH on both chains). Next time fund the reserve plus a margin | ✅ |
| F15 | 2026-11-17 | 7.1 | `contracts:deploy` stopped twice on Ethereum Sepolia right after a contract landed, each time at the step that depends on it (factory → wallet implementation; proxy `initialize` → paymaster implementation): the next simulation ran on a load-balanced RPC that had not seen the new code yet. Nothing was sent either time; reruns resume. Same cause at 7.4: the hand-off's "revoke UPGRADER from the admin key" (`0x4e465539…6bdc`, block 12155877) was gas-estimated on the state before the previous grant (80,296 gas; it needs 106,564 once the timelock holds UPGRADER), ran out of gas and reverted. The CLI stops on any revert, so the final renounce can never go out after a failed grant | medium | Rerun once the state is visible. Follow-up: estimate after the previous receipt is visible on a fresh read, add a gas margin, retry a failed simulation | ⬜ follow-up |
| F16 | 2026-11-18 | 8.1 | New advisory GHSA-fc5q-39xc-vjpf (picomatch ReDoS, high, no fix) fails the dependency audit on every PR, #303 and #304 included | medium (CI) | The reviewer's #305 accepts it (AF-044/AF-045, owner the reviewer, expires 2026-12-16, not reachable at runtime); the developer reviewed and approved. After it merges, merge `main` into #303 and #304 | ✅ #305 merged; #303 and #304 green and merged |
| F17 | 2026-11-18 | 8.2 | The version PR #291 failed 22 checks: `changeset version` raised five `workspace:^7.0.1` specifiers in the services to `^7.1.0` without updating `pnpm-lock.yaml`, so every `--frozen-lockfile` install failed (same as #281 last release) | medium (release) | `bc081ae4` on `changeset-release/main` regenerates the lockfile (5 lines). Lost if `main` moves before #291 merges. Follow-up: have the release workflow run `pnpm install --lockfile-only` after versioning | ✅ fixed for 7.1.0; workflow follow-up open |
| F18 | 2026-11-18 | 10 | The paymaster watcher's cache is keyed by chain only: `paymaster_state` (cursor) and `paymaster_tenants` would keep naming the legacy paymaster after the switch, and ingestion would resume from the legacy cursor, past the v3 paymaster's provisioning events. Balances self-correct on the next reconcile (it reads the configured paymaster), history would not | medium | `dev-v3-reset.sql` clears both tables (and the legacy ledger); the watcher cold-starts and reconciles from the v3 paymaster. Restart wallet-api after the reset (runbook step 7) | ✅ handled by `dev-v3-reset.sql` (#311 merged) |
| F23 | 2026-11-23 | 9 | `pnpm contracts:sponsorship … --env-file deploy/contracts/base-sepolia.local.env` fails with `node: deploy/contracts/base-sepolia.local.env: not found`: `deploy:operate` runs `node … deploy/operations.ts` in `packages/contracts`, and Node (v26.13.1 here) reads the `--env-file` flag itself, relative to that directory. The README's relative form no longer works | low | Pass an absolute path (`--env-file "$PWD/deploy/contracts/<chain>.local.env"`); `--plan` passes that way. Follow-up: fix the README or resolve the path in `run.sh` | ⬜ follow-up |
| F22 | 2026-11-23 | 10 | Base Sepolia now makes about 5 blocks a second (0.2 s: 285,872 blocks between 2026-11-22 20:02 and 2026-11-23 11:55 UTC), but the watcher still reads at most 200 blocks per 4 s poll (`MAX_POLL_RANGE`, sized for a 2 s chain). Net catch-up is about 45 blocks a second, so after dev's nightly scale-down (12 h, about 216,000 blocks) the Base watcher needs about 80 minutes to reach the head, and after a weekend about 6.7 hours. Metrics at 11:54 UTC on Monday: lag 285,872 blocks on 84532 (cursor at Sunday 20:02), 1 block on 11155111 | medium | Wait for the lag to drop before the smoke test. Follow-up: let the span follow the RPC (dev's QuickNode serves 10,000), the option #279 left for later | 🔄 |
| F21 | 2026-11-19 | 10 | After the full `terraform apply`, three services still run the task definitions `deploy.yml` cloned at 13:46 from the pre-#311 revisions: `custom-example` and `custom-example-byoui` serve `config.js` without `defaultToken` (last-modified 13:46:56), and `wallet-byo`'s bundle has the legacy factory `0x26dCd293…7050` instead of `0xA9d7…F635`. No variable override in the repo explains it. the DevOps re-plan: 0 to add, 7 services `:38 → :39`, so the first apply's `:39` revisions exist but every service is back on `deploy.yml`'s `:38`: most likely the deployment circuit breaker (`rollback = true`) rolled them back | high (byoui) | Cause (DevOps, 2026-11-19): the `:39` tasks used image `5ba71241`, not found in ECR. Terraform takes the image tag from `infra/versions.json`, so the apply ran from a checkout with #311 but without #314 (`3c8f8b58`'s versions.json still says `5ba71241`). Fix: pull `main` (`6cec9ea9`) and apply again. Runbook: step 7 must run from a checkout that includes the deploy PR | ✅ re-applied from `main` 2026-11-19; verified 2026-11-23 |
| F20 | 2026-11-19 | 10 | After #314 merged (`22ddb623`), "Docker images" on `main` failed: Trivy found a new Go stdlib CVE, CVE-2026-97054 (HIGH, fixed in Go 1.26.11, 1.27.4), in the esbuild 0.25.4 binary of `giano-wallet-byo`, both arches. Same cause as AF-011 to AF-036; nothing in #314. Deploy still rolled all 7 `dev` services to `3c8f8b58`, whose images were built earlier. Every new PR and `main` push fails until it is accepted | medium (CI) | AF-046 added to `security/accepted-findings.json` (owner the developer, expires 2027-02-07 with AF-011 to AF-036): #317, merged as `6cec9ea9` | ✅ |
| F19 | 2026-11-19 | 10 | `dev`'s pinned image `wallet-api:5ba71241` has expired from ECR (lifecycle keeps 120 images ≈ 20 `main` commits; 134 since). No task can start from the current task definitions, so the runbook's reset-before-roll order cannot run (known risk R27, seen before on 2026-10-20). `dev` may already be down since the 07:00 scale-up | high (cut-over) | New order: merge #314 first (new task definitions, wallet-api stays at 0), then `dev-db-run.sh dev-v3-reset.sql` on the new task definition (init migrates, then the reset), then scale wallet-api to 1. Posted to DevOps; the reset ran this way on 2026-11-19 (SQL OK). Runbook updated in #326 (open) | 🔄 #326 |
| F3 | 2026-11-16 | 0.4 | CI "Solidity static analysis": the Aderyn binary download returns 404. Upstream removed the Linux binaries from every release (issues #1096–#1098, 2026-11-13, retiring installers). Breaks every PR and `main`; blocks merging #279 | blocker (CI) | Resolved by #288 (merged to `main` as squash `a8876704`) | ✅ |
| F1 | 2026-11-16 | 0.1 | viem caches `getBlockNumber` (~4 s), so a log scan can stop at a stale head. Matters for any "scan to head" loop, including the coming watcher change | low | `cacheTime: 0` in the hand-off scan | ✅ |
| F2 | 2026-11-16 | 0.4 | Biome 2.6.5 (from `main`) formats YAML and flags `e2e/devnet/state-31338.json` (over 1 MiB) | low | PR's YAML reformatted; the state file comes from `main`, not this PR | 🔄 |

## Run log

Dated, newest last. One entry per session or per meaningful event: what ran, the outcome, links.

- **2026-11-16:** Tracker created. #279 is ready for review with one review (four blocking comments,
  five others); branch 6 commits behind `main`. The tech lead decided N4: shrink the `eth_getLogs`
  span to 200 now, optimise later. Nothing has been sent to a public chain.
- **2026-11-16:** Phase 0 started. B1–B4 fixed (`2695cb43`), N4 decision recorded in the docs and the PR body,
  `main` merged in (`0ad45429`), YAML reformatted for Biome 2.6 (`84f39459`), pushed. Replied on the four blocking
  threads. Local: `test:deploy` 111/111, `test:deploy:integration` 4/4, typecheck clean. CI running.
- **2026-11-16:** 0.2 done. RPC URL redaction and signer drift fixed in `97a453b7`, pushed, both threads answered; PR
  body updated. CI on `84f39459`: 38 pass, Slither/Aderyn failed because the Aderyn release binary is gone upstream
  (F3), which fails the "CI passed" aggregate. Everything else green. CI rerunning on `97a453b7`.
- **2026-11-16:** CI on `97a453b7`: 38 pass. Two fail, both from F3 only (Aderyn install 404, then the "CI passed"
  aggregate); Slither's own steps pass. Review not re-requested, since the condition was "CI green".
- **2026-11-16:** F3 options posted to the tech lead in the team channel. Recommended option 1. No CI change
  until he answers. Also checked: crates.io has only yanked 0.1.x Aderyn versions, so it's not an option.
- **2026-11-16:** The reviewer opened #288, which removes Aderyn (Cyfrin retired it). Reviewed it: no blocking issues.
  Its own checks pass locally (register check, 87 tests; CI-gate check, 20 tests). Merged its branch into #279
  (`68efd7bc`), pushed, and noted it in the PR body. CI rerunning. #288 should merge first.
- **2026-11-16:** CI on #279 at `68efd7bc` (with #288 merged in): 40 pass, 1 skipped (image publish, not run on PRs).
  #288 green too (38 pass). Re-requested review from the reviewer and the tech lead. #279 is BLOCKED only on approval and
  resolved threads. #288 reviewed (no blockers, 2 tracking points: AF-005's 0xEF defect and locked ether below
  Slither's High gate). Review posted as APPROVE with 3 inline nits (pullrequestreview-5920263448).
- **2026-11-16:** The reviewer approved #279: all fixes verified, the three non-blocking points can go to a follow-up PR,
  and he asks for a ticket on the Giano Notion page. He left three new non-blocking inline comments (R6–R8). #288
  merged as a squash, so #279 went DIRTY. Merged `main` (`9174def1`), taking `main`'s version of the five #288 files
  (#279's own commits never touched them). #288 is out of the diff; PR body updated. CI rerunning. 12 review threads
  are unresolved.
- **2026-11-16 13:19 UTC:** #279 merged (`dacd42ee`). All 12 threads resolved: six fixed, six deferred with a reply
  pointing to the follow-up PR (R3–R8). Left in Phase 0: archive the OpenSpec change. The reviewer's request for a Notion
  ticket for the follow-up is open. Next phase: Phase 1 (the watcher's 200-block span).
- **2026-11-16:** Archive PR #293 opened (`chore/archive-harden-contract-deployment`). Delta specs synced into
  `openspec/specs/contract-deployment` (1 modified, 10 added) and `production-key-ceremony` (1 modified). The change
  moved to `openspec/changes/archive/2026-11-16-harden-contract-deployment/`; the evidence link in
  `TESTNET-ROLLOUT.md` was updated. `openspec validate --specs` 30/30.
- **2026-11-16:** Notion ticket **G42** created (Backlog) for the six review follow-ups (R3–R8), each linked to
  its #279 thread: (Notion) Worth fixing before Phase 6, since
  provisioning and the hand-off can't be undone.
- **2026-11-16:** Phase 1 started. Measured `sepolia.base.org`'s cap (`toBlock - fromBlock` ≤ 200). Found F4: the
  SDK floor of 250 broke the console on it too. Draft PR #294 (`5172a2f0`): watcher span 200, SDK floor 200, docs.
  wallet-api 604/604, sdk 158/158, admin 172/172. Next: 1.3, the rehearsal without `--fork-url`.
- **2026-11-16:** 1.3 started. Stopped the e2e stack (`docker compose … stop`; containers and volumes kept;
  restart with `docker compose --profile portless -f deploy/docker-compose.e2e.yml start`). Running
  `pnpm contracts:rehearse --chain base-sepolia --platform` with no `--fork-url`, so the fork reads through
  `sepolia.base.org`. Log: session scratchpad `rehearse-294.log`.
- **2026-11-16:** 1.3 first run (no `--fork-url`, fork at block 59575216 via `sepolia.base.org`): **15/16**. All
  contract steps, platform-up and sponsorship rules passed; browser smoke failed because wallet-api refused the
  first sponsorship (`insufficient-balance`) while the watcher was still replaying its cold-start lookback (F5).
  The watcher caught up in about 2 minutes. The smoke rerun alone against the same stack then **passed** (12.1 s):
  2 sponsored ops recorded by the watcher (`0x69b8d328…355a` block 59575412, `0xe0c0ddb2…b7cb` block 59575415),
  ledger balance 0.05 → 0.048463851990646964 ETH. Added the `watcher-caught-up` step to `rehearse.ts`
  and started a clean full rerun.
- **2026-11-16:** 1.3 done. Clean rerun **17/17** with no `--fork-url` (watcher caught up in 84 s; smoke passed;
  0 refusals, 0 range errors). Pushed `a41b9b86`, updated the PR body with the gate, **#294 marked ready**.
  Rehearsal stack and fork removed; e2e stack restarted. Left in Phase 1: review and merge #294 (1.4).
- **2026-11-16:** Review of #294 requested from the reviewer; announced in the team channel with a mention. Waiting on review for 1.4.
- **2026-11-16:** Phase 2 decisions drafted in `TESTNET-ROLLOUT-DECISIONS.md` (D1–D10, not posted). Measured for it:
  the legacy paymaster still holds 0.09999 ETH deposit + 0.1 stake on Base Sepolia and 0.04 + 0.11 on Ethereum
  Sepolia (1-day unstake delay); Ethereum Sepolia's public RPC serves 50,000-block `eth_getLogs`.
- **2026-11-16:** D10 (maintenance window and announcement) dropped by the user: the team controls `dev`, no
  announcement needed now. Step 10.2 marked skipped.
- **2026-11-16:** D8 / 3.1 prepared. Read ABIP-8 (Notion) and `docs/key-ceremony.md`: the testnet deployer is
  exempt from the ceremony (ABIP-8 Exceptions §1; repo policy), but its generation method is followed anyway. Steps
  written into 3.1. Nothing generated yet.
- **2026-11-16:** The reviewer requested changes on #294 (7 points). Fixed in `1dd2b2ba`: (1) bundler receipt lookup on the
  public Base RPC → docs (F6); (2) console forward reads re-narrowing → fix + 2 tests that fail without it (F7);
  (3) rehearsal metrics poll: 5 s timeout, last status in the error; (4) PAYMASTER-SPECS 8.2 figures for 200 and
  rewrapped; (5) TESTNET-ROLLOUT N4 row in the past tense; (6) drawdown false alarm linked to G28 in the PR body;
  (7) console showing a 200-block window: no change (follows the decision). paymaster-admin 174/174, typecheck
  clean, lint clean. Reply posted (issuecomment-6922244777) and review re-requested from the reviewer.
- **2026-11-16:** 3.1 done. Testnet canonical deployer `0xBf8e1e80ac0687f2dd0b2909f5a68E3f6d5c41B5`, 1Password in, `multichain-keygen 2.0.0`. Next: 3.2 PR.
- **2026-11-16:** 3.2 PR #296 opened (`e3fd2d55`). The determinism gate now covers testnet; expected testnet
  addresses recorded in 3.2. Waiting on CI and review.
- **2026-11-16:** Review of #296 requested from the tech lead.
- **2026-11-16:** Decisions draft updated before posting: status column; D8 done (address, item, #296; vault
  membership to confirm); D6 adds the bundler receipt-lookup finding (F6), which favours a keyed RPC; D3 notes
  reuse of existing `dev` keys (never the deployer); D7 names the deployer address and `dev`'s executor key; D2's
  Safe{Wallet} support marked unchecked. Phase 2 table gained D7–D9.
- **2026-11-16:** Walking the decisions one by one with the developer before the tech lead's sign-off. D1 review found F8
  (stored wallet addresses go stale at the switch, so a reset includes clearing `dev`'s user data) and added the
  in-place UUPS upgrade as a third option.
- **2026-11-16:** D1 proposed by the developer: reset (option 1), clearing `dev`'s user data at the switch. Awaiting
  The tech lead's ok.
- **2026-11-16:** D2 left for the tech lead's input and view; Safe{Wallet} support on both testnets checked (same
  address on both possible via multi-chain creation).
- **2026-11-16:** D3: The developer leans to one address for all roles; the tech lead's input asked. Checked that no service
  holds a role key (console and CLI only).
- **2026-11-16:** D4 proposed by the developer: keep the testnet delays. Awaiting the tech lead's ok.
- **2026-11-16:** D5 proposed by the developer as recommended. Found while reviewing it: `deploy:cli testing` also
  deploys a `PermissivePaymaster` and funds it with `--fund-eth`; run it with `--fund-eth 0` on public testnets
  (F9). The test ERC-20 deploy has no step in the tracker yet; add one before Phase 9 once D5 is final.
- **2026-11-16:** D6 proposed by the developer: keyed RPCs, `dev`'s QuickNode. Open: measure the plan's `eth_getLogs`
  cap before 3.5.
- **2026-11-16:** D7 proposed by the developer: a team testnet wallet. Measured: deployer 0 ETH on both chains; gas
  negligible on both.
- **2026-11-16:** D9 decided by the developer: one PR fixing all of G42 (R1–R6) before Phase 6. R4–R6 confirmed still
  open on `main`. Decision walk-through done: D1, D4–D7 proposed (awaiting the tech lead's ok), D2 and D3 put to
  The tech lead for input, D8 and D9 decided.
- **2026-11-16:** D7 decided: The developer funds both chains himself. Funding the deployer and forwarding from it was
  considered and dropped (works, CREATE3 addresses don't depend on the nonce, but `docs/key-ceremony.md` limits
  the deployer to a gas float).
- **2026-11-16:** Decisions posted to the team channel for the tech lead: D2 and D3 his call; ok
  asked on D1, D4, D5, D6; #296 review asked; D7 (the developer funds, ~0.6 ETH) and D9 (fix all of G42) as FYI.
- **2026-11-17:** G42 fixed on branch `fix/g42-deploy-tooling-follow-ups` (all six, R1–R6 = tracker R3–R8).
  `test:deploy` 118/118, `test:deploy:integration` 4/4, fork rehearsal (no platform) 12/12 with records in
  `deploy/rehearsal/records`.
- **2026-11-17:** PR #298 opened (`c08878a7`), review requested from the reviewer; G42 moved to In review.
- **2026-11-17:** #298 review asked of the reviewer in the team channel.
- **2026-11-17:** The reviewer requested changes on #298: one blocker (R5: with only the profile naming the timelock,
  `--from-block` was unbounded) and seven suggestions. All fixed in `143feb21`: `--from-block` checked against
  historical code (`scanStartProblem`), mainnet provisioning rules moved into the script
  (`deploy/provision-rules.ts`, operator key refused as a holder, unstake delay ≥ 1 d on mainnet), Cancun counts only
  missing-opcode text. `test:deploy` 122/122, integration 4/4, rehearsal 12/12. Replies posted, re-review requested.
- **2026-11-17:** The reviewer approved #298 (one non-blocking note: the script detected mainnet by chain id only).
  Fixed in `2143f16a` (`provisioningIsMainnet`: chain id, `GIANO_NETWORK`, or the committed profile). Unit
  123/123, integration 4/4, rehearsal 12/12.
- **2026-11-17 12:33 UTC:** #298 merged with a merge commit (`e0cc95e1`) after the reviewer's approval, CI green (40 pass)
  and all 9 threads resolved. Notion G42 → Done. D9 complete.
- **2026-11-17:** The tech lead answered the decisions thread: D2 and D3 one EOA admin key for every admin role; #296
  looks good (GitHub approval still to come); Giano accounts must take no funds from accounts tied to other
  projects, so D7 changes (the developer asked the tech lead to fund). D1, D4, D5, D6 not commented yet.
- **2026-11-17:** #294 needs no re-review: The reviewer approved it at 16:27 on 2026-11-16, after the last commit (`1dd2b2ba`).
  CI green. Review of #293 requested from the reviewer (GitHub + the team channel).
- **2026-11-17:** #294 merged (`4e29eb72`, Phase 1.4 done: the 200-block span is on `main`). #293 merged (`486947b1`,
  The reviewer approved 12:41; OpenSpec archive of `harden-contract-deployment` done). Review of #296 requested from the reviewer as well
  (GitHub + the team channel); the tech lead ok'd it in Slack only.
- **2026-11-17:** The reviewer requested changes on #296 (a test guard that no longer runs; five docs still saying the testnet
  deployer is unset; rollout drafts showing rehearsal addresses; line-wrap nit). Fixed in `33e4fb33`, `main` merged in,
  replies posted, re-review requested. Read-only plans with the real deployer against both public testnets: every
  check OK, the four addresses empty, only blocker funding (recorded in deploy/contracts/README.md). Open: his
  questions on the 1Password item's restricted access and a ticket code for the PR title.
- **2026-11-17:** QuickNode `eth_getLogs` cap measured by the developer (URLs never printed): Base Sepolia and Ethereum Sepolia
  both ok at 200, 2,000, 5,000 and 10,000 blocks (EntryPoint filter; Base returned 0/2/2/4 logs, Sepolia 0 at every
  range, no refusals). The bundler's default `maxBlockRange` 2,000 fits: no `bundler` section in `GIANO_CHAINS`.
- **2026-11-17:** #296 merged (`0bcf0864`) after the reviewer's approval on `33e4fb33`, CI green, the one thread resolved.
  `DEPLOYERS.testnet` is on `main`. The reviewer's two questions (1Password item access, ticket code) still to answer on the PR.
- **2026-11-17:** Testnet admin key created by the developer (`multichain-keygen` 2.0.0): 1Password item "Giano testnet admin", address `0x033178C012FAAB6977FE3b760e5Ca9BBAb4F3030`. Decided: it is also the bootstrap
  operator (`roleAdmin`). PR #302 sets it as `roleAdmin` and `timelock.proposers` in both testnet profiles. Needs gas on
  both chains (the tech lead's funding).
- **2026-11-17:** Funding requested from the tech lead in the decisions thread: per chain, deployer
  `0xBf8e…41B5` 0.05 ETH and admin `0x0331…3030` 0.2 ETH (0.25 per chain, 0.5 total). Executor: `dev`'s key, balance to
  check. Review of #302 requested from the reviewer (GitHub + the team channel).
- **2026-11-17:** Tracker brought up to date: Phase 2 rows show the proposed/decided state of D1–D9 (2.7–2.9 added);
  3.4 superseded and 3.4b (#302) added; 4.1 done, 4.2/4.3 running; 5.1/5.2 requested; new 6.6 (test ERC-20 with
  `--fund-eth 0`, D5/F9) and 10.4b (clear `dev` user data, D1/F8); 10.3 sets the dApp's `defaultToken`; Phase 13 is
  an upgrade queued by the admin key (no Safe, D2).
- **2026-11-17:** Funding confirmed: deployer 0.05 ETH and admin 0.2 ETH on both Base Sepolia and Ethereum Sepolia,
  nonces 0. Bundler executor balance still to check (address needed).
- **2026-11-17:** Phase 4 done: Base Sepolia platform rehearsal 17/17 (watcher caught up in 84 s), Ethereum Sepolia
  passed through the browser smoke. F10 logged (rehearsal folder wiped at each start; rehearsal stack keeps e2e ports).
- **2026-11-17:** #302 merged after the reviewer's approval and his two doc nits (`5a890340`): the admin key is `roleAdmin` and
  `timelock.proposers` in both testnet profiles on `main`.
- **2026-11-17:** D1, D4, D5 and D6 approved: The tech lead is aware of the proposals and the developer confirmed them as approved.
  Phase 2 is complete.
- **2026-11-17:** 3.3 done. Signer `0x48bCd7Dd70c6861aF0844F4dBC1dE6Df24048a44` (read from the legacy paymaster's signer set in
  storage, confirmed by the developer's derivation), executor `0x945BA79715f48D586380604147ae6cD9050b60aC` (0.1 ETH on each chain).
  F11: the legacy Ethereum Sepolia paymaster has another signer. Test ERC-20 will land at `0x461E0641a3615336b7D2E4C5D71fB2BB88038C93`
  (CREATE3, testnet deployer; empty on both chains today).
- **2026-11-17:** 3.5 and 5.1 done. Read-only `contracts:deploy --plan` for Base Sepolia through the keyed RPC with the
  operator file: every check OK, `ROLE_ADMIN` = admin key, four addresses empty, deployer reserve met, "Requirements
  passed". Ready for 6.1.
- **2026-11-17:** 6.1 done: The developer ran `contracts:deploy --chain base-sepolia`. Four contracts at the deterministic addresses,
  all receipts ok (blocks 60059579–60059598), codehashes match the record, proxy → paymasterImpl, EntryPoint v0.9,
  `ROLE_ADMIN` on the admin key. Gas: 0.00005 ETH.
- **2026-11-17:** 6.2 done: Base Sepolia provisioned and verified on-chain (stake 0.1 ETH / 86400 s, deposit 0.04 ETH,
  signer registered, both tenants funded 0.02 ETH, all roles on the admin key until the hand-off).
- **2026-11-17:** 6.3 done: Base Sepolia timelock `0x7Da25D41…8A78` verified (roles, open execution, delays = D4). Hand-off
  pre-flight green; plan reviewed (8 txs). Next: 6.4, the irreversible hand-off.
- **2026-11-17:** 6.4 hand-off done and verified; 6.5 doctor green (two expected warnings). Phase 6 core done on Base
  Sepolia; 6.6 (test ERC-20) pending. F12 logged (`deploy:cli testing` signs with any `DEPLOYER_PRIVATE_KEY`).
- **2026-11-17:** 6.6 refused by R-29 (nothing sent). D5 premise corrected (F13). The developer chose option 1: PR #303
  (`deploy:cli test-token`, review requested from the reviewer). Phase 7 started in parallel: Ethereum Sepolia core deploy running.
- **2026-11-17 17:05:** Phase 7.1 (Ethereum Sepolia `contracts:deploy`) stopped after the first contract: wallet
  implementation deployed (`0x4fc273d9…1d42`, block 12155749, 20.2M gas) and recorded; then "Deployment stopped" with
  the provider error suppressed. Checked: nothing else sent (nonce 1, nothing pending), factory/paymaster addresses
  empty, deployer 0.05 ETH. Likely a stale RPC read before the factory's simulation. Rerun of the same command
  advised (it resumes).
- **2026-11-17:** Rerun of 7.1 refused before sending: deployer 0.0499999997 ETH < 0.05 reserve (F14). Fix: 0.01 ETH from the
  admin key to the deployer on Ethereum Sepolia, then rerun.
- **2026-11-17:** Top-up asked of the tech lead instead (the developer's call): 0.01 ETH to the deployer on Ethereum Sepolia and Base Sepolia (the tech lead sent 0.05 ETH on each),
  in the decisions thread. 7.1 resumes when it lands.
- **2026-11-17:** Top-up landed: deployer 0.09995 ETH on Base Sepolia, 0.1 ETH on Ethereum Sepolia (nonce 1). 7.1 can resume.
- **2026-11-17 17:16:** 7.1 rerun: factory (`0x1a8f5e62…6e21`, block 12155820) and paymaster implementation (`0xb4e115f2…8a71`,
  12155821) deployed; stopped again before the proxy. Nothing else sent (nonce 3). QuickNode now returns the implementation's
  code consistently. F15 logged (stale read before a dependent simulation). Rerun advised for the proxy only.
- **2026-11-17:** 7.1 done: Ethereum Sepolia core deployed and verified (same four addresses as Base Sepolia).
- **2026-11-17:** 7.2 done: Ethereum Sepolia provisioned and verified (identical to Base Sepolia).
- **2026-11-17:** 7.3 done: Ethereum Sepolia timelock verified (same address as Base), hand-off pre-flight green.
- **2026-11-17 17:25:** 7.4 hand-off stopped after step 1: grant UPGRADER to the timelock ok (`0x340e8ecf…`, block 12155876);
  revoke UPGRADER from the admin key reverted out of gas (stale estimate, F15). Admin key still holds every role incl. ROLE_ADMIN.
  The plan now resumes with the 7 remaining steps; rerun advised.
- **2026-11-17:** 7.4 second run: revoke UPGRADER ok, grant FEE_ADMIN to the timelock ok (`0xd8b2575a…284d`), revoke FEE_ADMIN
  reverted out of gas (`0xfdae7803…d4e0`, limit 80,296, used 79,403: the same stale estimate, F15). UPGRADER now on the timelock only;
  FEE_ADMIN on both; WITHDRAW_ADDRESS_ADMIN and ROLE_ADMIN still on the admin key. 5 steps left. Next run through the public
  Ethereum Sepolia RPC (command-line `ETHEREUM_SEPOLIA_RPC_URL` overrides the operator file).
- **2026-11-17:** 7.4 run via the public Ethereum Sepolia RPC refused before sending: its `eth_getLogs` for the timelock's role
  grants returned "Invalid parameters", so the pre-flight failed closed (correct). Back to QuickNode and rerun until done.
- **2026-11-17:** 7.4 later runs (QuickNode): revoke FEE_ADMIN and grant WITHDRAW_ADDRESS_ADMIN, then revoke WITHDRAW_ADDRESS_ADMIN
  (`0x5e562d7d…e0b2`) and grant ROLE_ADMIN to the timelock (`0x55cb51c9…2e8c`) ok; renounce ROLE_ADMIN reverted out of gas
  (`0xa83d9013…d5ad`, block 12155940, limit 74,908, needs 101,101: F15 again). The timelock holds all four roles; the admin key
  still holds ROLE_ADMIN. One step left: the renounce.
- **2026-11-17:** Phase 7 done on Ethereum Sepolia: hand-off complete and doctor green; probe address identical to Base Sepolia
  (MC-22). Both chains now run release v3 with the timelock in control. Left before `dev` can move: 6.6/7 test ERC-20 (#303),
  Phase 8 (commit records, release the package), Phase 9 (sponsorship rules), Phase 10 (cut over).
- **2026-11-17:** Phase 8.1: PR #304 opened (records, registry, profiles, docs), review requested from the reviewer.
- **2026-11-17:** #303 review (the reviewer, changes requested: release pin, token publication step, stale JSDoc + 6 smaller) all fixed in
  `dce4aceb`; re-review requested. The rollout's step 8 now includes committing the token records and a second release.
- **2026-11-17:** Published the tracker's overview, decisions, deployment results and findings to Notion under Giano:
  "Testnet v3 rollout tracker" (Notion). Stale rows refreshed first (N4, F4, F8,
  F9, D5, D7).
- **2026-11-17:** End-of-day update posted to the team channel, linking the Notion tracker.
- **2026-11-18:** #303 approved by the reviewer (step 8 nit fixed in `799d4da3`); its audit check fails on the new picomatch advisory (F16).
  Reviewed and approved the reviewer's #305 (accepted findings AF-044/AF-045), every claim verified locally.
- **2026-11-18:** #305 merged (`b97ecd6e`); `main` merged into #303 (`8094c286`) and #304 (`a2bb869d`). The reviewer approved #304
  (re-verified both chains with `cast`); his three doc comments fixed in `9fa34563` (intro, step 7 split, superseded notes).
- **2026-11-18:** #303 merged (`90971faf`): `deploy:cli test-token` is on `main`. #304 conflicted on `TESTNET-ROLLOUT.md`
  rows 5–8; resolved (#304's steps 5–7 + #303's step 8) in `095ba46e`; `gen:addresses` unchanged, `test:deploy` 126/126;
  waiting for CI to merge.
- **2026-11-18:** #304 merged: both deployment records and the registry for 84532 and 11155111 are on `main`. Next: the
  test ERC-20 on both chains (step 8 / 6.6), its records PR, then the package release (8.2).
- **2026-11-18:** Test ERC-20 deployed by the developer with `test-token` on both chains at `0x461E…8C93` (Base `0xb37e4709…`, block
  60413516; Ethereum Sepolia `0x886ce086…`, block 12161440), from the canonical deployer; identical code, supply on the admin key, no
  permissive paymaster. First attempt without a signed-in `op` was verify-only (nothing sent). Both runs wrote their records (an early check
  of mine read the Ethereum Sepolia file before that run had finished; a verify-only rerun kept the entry unchanged). PR #309 publishes the records (review requested from the reviewer).
- **2026-11-18:** Posted in the team channel: test ERC-20 live on both testnets; #309 review asked of the reviewer.
- **2026-11-18:** #309 merged (the reviewer approved; CI 39 pass): the test ERC-20 is in the records and the registry on `main`. The next
  release (version PR #291, changesets) publishes the testnet records and the token.
- **2026-11-18:** Release (8.2): version PR #291 bumps all seven packages 7.0.1 → 7.1.0, with the testnet registry and token
  plus other unreleased work on `main` (Silent Data H6). Asked the tech lead and the reviewer in the team channel whether `main`
  is OK to release and for an approval; merging publishes to npm and tags `v7.1.0`.
- **2026-11-18:** Tracker refreshed (8.1 result with #304 and #309, 8.2 result with #291, Phase 9 tenant rows) and the Notion page
  updated to match (status, test ERC-20, next steps, phase rows 6.6/7/8, findings F12/F13/F16).
- **2026-11-18:** #291 approved by the tech lead the tech lead, then 22 checks failed on an outdated lockfile (F17). Pushed `bc081ae4` onto
  `changeset-release/main` (lockfile only, as on #281); CI rerunning.
- **2026-11-18:** #291 merged (`f6596229`) after CI green on `bc081ae4` (41 pass) and the tech lead's approval; release workflow
  publishing 7.1.0.
- **2026-11-18:** Phase 8 done: 7.1.0 published (all seven packages), tag `v7.1.0`. Next: Phase 10, the `dev` cut-over.
- **2026-11-18:** Phase 10 prepared in PR #311 (`feat/dev-v3-cutover-infra`, review requested from the reviewer): Terraform defaults to the
  v3 proxy and factory, `test_erc20_address` → dApp `defaultToken`; `dev-v3-reset.sql` (dry-run on the e2e DB: users 52→0, tenants
  and admins kept; rolled back); the cut-over runbook (secret first via `-target`, then the roll, full apply, reset, wallet-api
  restart, readiness, rollback with RDS snapshot) and the final `GIANO_CHAINS` document (schema-validated). F18 logged. The
  `versions.json` deploy PR waits for #311 to merge.
- **2026-11-18:** The reviewer requested changes on #311 (3 blocking: console timelock missing from the chains document; wrong 1Password
  edit; `psql` DSN/access) plus 7 more. All fixed in `fc8aeb39`: `dev-v3-chains.mts` (bundle rewrite from records/profiles,
  schema-checked), `dev-db-run.sh` (one-off wallet-api task with node+pg; the image has no shell/psql), new order (stop
  wallet-api → reset on the current schema → roll → start), `cutover_v3_backup` + `dev-v3-restore.sql` (round trip verified
  byte for byte on a scratch DB), per-workspace `test_erc20_address`. Re-review requested.
- **2026-11-19:** #311 merged after the reviewer's approval (all ten points) and a `main` merge (#308 stricter lint, #310) with CI green.
  The cut-over runbook, `dev-v3-chains.mts`, `dev-db-run.sh`, `dev-v3-reset.sql`/`dev-v3-restore.sql` and the Terraform defaults are on
  `main`. Next: the `versions.json` deploy PR (runbook step 4) and the cut-over with DevOps. Reviewed and approved the reviewer's #310 (merged).
- **2026-11-19:** Runbook step 4: draft deploy PR #314 (`deploy/dev-3c8f8b58`, `versions.json` dev `5ba71241` → `3c8f8b58`, the #311 merge).
  Merge only at step 8, after `docker.yml` has published `3c8f8b58`'s images. Next: the cut-over with DevOps (weekday 07:00–19:00 UTC).
- **2026-11-19:** DevOps request for the cut-over drafted and posted in the team channel for team review,
  due today before 19:00 UTC. To post in the DevOps request once the team agrees.
- **2026-11-19:** Team approved the DevOps request; posted in the DevOps request, due today before
  19:00 UTC, technical contact the developer. Waiting for DevOps to schedule the session.
- **2026-11-19:** DevOps hit `Image container giano-dev/wallet-api:5ba71241… does not exist in ECR` (F19, R27). Posted the
  updated order in the DevOps request thread: secret → wallet-api 0 → merge #314 → reset on the new
  task definition → wallet-api 1 → full apply. Runbook PR to follow.
- **2026-11-19:** "Docker images" failed on `main` at `22ddb623` (#314): new CVE-2026-97054 in `giano-wallet-byo`'s esbuild
  binary (F20). Deploy rolled all 7 `dev` services to `3c8f8b58`. Opened #317 (AF-046), review requested from the reviewer.
- **2026-11-19:** #317 (AF-046) approved by the reviewer and merged as `6cec9ea9`; F20 closed.
- **2026-11-19:** DevOps finished the cut-over (thread in the DevOps request). Readiness: both chains `ready` on 7.1.0.
  Found F21: `custom-example`, `custom-example-byoui` and `wallet-byo` still run the pre-#311 env (no `defaultToken`, legacy
  factory in the BYO wallet).
- **2026-11-19:** "Docker images" passed on `main` at `6cec9ea9` (run 44559219992): F20 confirmed fixed.
- **2026-11-19:** F21: the DevOps re-plan shows the services back on `:38` with `:39` registered (likely circuit-breaker
  rollback). He is re-applying; asked in the thread for the events and `stoppedReason` if it fails again.
- **2026-11-19:** F21 cause found: the re-apply rolled back on `5ba71241: not found`, so the DevOps checkout predates #314.
  Next: apply from current `main`.
- **2026-11-19 18:45 UTC:** DevOps is on `6cec9ea9` and proposed a `versions.json` bump to it. Replied: no bump
  needed, `versions.json` at `6cec9ea9` already says `3c8f8b58` (image in ECR); apply from this checkout, tomorrow after 07:00 UTC is fine.
  F21 still open; dev unchanged (dApps without `defaultToken`, BYO wallet on the legacy factory).
- **2026-11-19 19:02 UTC:** DevOps confirmed his local checkout was behind ("I think I need to pull and run terraform apply").
  Dev scaled to 0 at 19:00 (all endpoints 503). Next: DevOps pulls `main` and applies (after 07:00 UTC on 2026-11-20 is fine), then
  re-check F21 and run the readiness checks.
- **2026-11-19:** End-of-day status posted in the team channel: stopped at the Terraform re-apply (F21);
  next: re-apply from `main`, readiness, Phase 9, Phase 11, runbook PR.
- **2026-11-19 19:40 UTC:** DevOps pulled `main` and re-applied; services on `3c8f8b58` (revision `:40`); dev was already at 0.
- **2026-11-20 09:16 UTC:** DevOps: all services up with `3c8f8b58`.
- **2026-11-23 10:38 UTC:** F21 verified fixed: both dApps serve `defaultToken` `0x461E…8C93`, `wallet-byo` has the v3 factory;
  `/v1/version` 7.1.0 with both chains `ready`. Left for 10.5: watcher lag and the console check.
- **2026-11-23:** Opened #326 (`docs/dev-cutover-runbook-order`): the runbook now merges the deploy PR before the reset
  (F19) and runs the full apply from a checkout that includes it (F21).
- **2026-11-23 11:54 UTC:** `/metrics` (10.5): both chains available, watchers active, no invariant breach, no divergence,
  paymaster deposit 0.04 ETH on both chains, Base tenants `example` and `byoui` at 0.02 ETH each. Base watcher lag 285,872 blocks (F22,
  catching up, about 13:45 UTC); Ethereum Sepolia lag 1. Ethereum Sepolia reports 2 drifted tenants and no tenant balances: the
  reconcile reads only tenants with a ledger row or a sponsorship rule on that chain, and the reset left none for 11155111; Phase 9
  adds the rules.
- **2026-11-23:** Console (10.5): sign-in as the bootstrap platform admin works (the wallet had to disconnect and reconnect
  once: error 4100 from the wallet, not wallet-api). Base Sepolia shows `example` and `byoui` at 0.02 ETH each. Timelock and Roles
  tabs not yet reported; Ethereum Sepolia balances wait for Phase 9.
- **2026-11-23:** Console Roles tab (chain selected in the console, Base Sepolia): the timelock `0x7Da2…8A78` holds ROLE_ADMIN (1 h),
  UPGRADER (1 h), FEE_ADMIN (10–20 min) and WITHDRAW_ADDRESS_ADMIN (30 min); the admin key `0x0331…3030` holds SIGNER_ADMIN,
  FEE_COLLECTOR, STAKE_ADMIN, TENANT_ADMIN, PARAM_ADMIN and PAUSER, each its only holder. Matches D3, D4 and `contracts:doctor`.
- **2026-11-23:** Phase 9 prep: admin keys issued in the console for `example` and `byoui` (labelled for Phase 9) and saved to
  1Password. The seed keys (2026-10-21) stay active.
- **2026-11-23:** Phase 9 done. `contracts:sponsorship` for `example` and `byoui` on 84532 and 11155111 (absolute `--env-file`, F23),
  with the admin keys issued for Phase 9. Read-back: all four `configured`, `valid`, `enabled`, allowlist `0x461e…8c93` only.
  Metrics after: both tenants at 0.02 ETH on both chains, drifted tenants 0 on both, no invariant breach. Base watcher lag
  83,012 blocks (down from 285,872 at 11:54, about 42 blocks/s), so caught up around 13:50 UTC; Ethereum Sepolia lag 1.
- **2026-11-23 15:0x UTC:** Phase 11 automated: `e2e/smoke` (#328, `smoke --target <dApp URL>`, all inputs from the dApp's
  `/config.js`). First run failed on the test's own reading of the dApp ledger (in-flight entries are stored as `timed-out`); fixed.
  Then passed for `example` and `byoui` on Base Sepolia and Ethereum Sepolia: mint of the test ERC-20, sponsored by the v3 paymaster
  `0xb2C7…615a`, account the same on both chains. Checked on public RPCs: all four `status 0x1` via EntryPoint v0.9; the Ethereum
  Sepolia `AccountDeployed` events name the v3 factory `0xA9d7…F635`. Full hashes in the #328 description.
- **2026-11-23:** Console after the smoke test (84532): `byoui` 0.0198 ETH (1 user), `example` 0.0196 ETH (3 users: the two first,
  failed smoke runs also registered), no deficits; 0.0394 ETH held for 2 tenants. Phase 11 console column done.
- **2026-11-23:** Phase 12 deferred by the user: the legacy funds (≈ 0.2 ETH Base Sepolia, 0.15 ETH Ethereum Sepolia) are documented
  in Phase 12 for later.
- **2026-11-23:** Phase 13 deferred by the user; plan recorded in its section.
- **2026-11-23:** Review of #326 and #328 requested from the reviewer on GitHub and in the team channel. Phase 14 list recorded.
- **2026-11-23:** Notion ticket **G46** created (Backlog) for F15, F17, F22, F23 and the deferred Phases 12 and 13; #310's items are
  already G44.
- **2026-11-23:** Tracker and decisions committed in #331 (`docs/testnet-rollout-tracker`). In the DevOps request thread: thanked DevOps, reported dev working as expected, and asked him to drop `cutover_v3_backup`.
- **2026-11-23:** #326 and #328 merged. Fresh deployment guide in #333 (`docs/FRESH-DEPLOYMENT.md`), review requested.
  Closing message posted in the team channel. Left: the backup-schema drop (asked of DevOps) and the reviews of this PR and #333.
