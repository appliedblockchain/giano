# Testnet rollout: decisions D1–D9 (all decided by 2026-11-17)

Phase 2 of [`TESTNET-ROLLOUT-TRACKER.md`](TESTNET-ROLLOUT-TRACKER.md). These are the answers the rollout needs before
it creates keys (Phase 3), funds accounts (Phase 5) and deploys (Phases 6–7). Each decision lists what it blocks,
the facts it rests on, the options and a recommendation. Facts marked *measured* were read from the chain on
2026-11-16.

**Context in one paragraph.** `dev` runs `5ba71241` (EntryPoint v0.7, legacy factory `0x26dCd293…7050`, legacy
paymaster `0xf98b56de…0718`) on Base Sepolia and Ethereum Sepolia. Current `main` can't be rolled to it: wallet-api
refuses to start when a chain it serves has no registry entry for release `v3` on EntryPoint v0.9. The rollout puts
release `v3` on both testnets with the tooling merged in #279, then moves `dev` onto it. Already settled: the
`eth_getLogs` question (N4, 200-block span, #294 in review) and the testnet canonical deployer (D8, #296 in review).
Updated 2026-11-16, after the deployer key was created and the reviewer's review of #294.

## Summary

| # | Decision | Owner | Blocks | Recommendation | Status |
|---|---|---|---|---|---|
| D1 | Reset `dev`, or migrate its v0.7 accounts | tech lead | 10, 12 | **Reset**, clearing `dev`'s user data | **approved** (2026-11-17: The tech lead aware, confirmed by the developer) |
| D2 | The testnet proposer Safe: signers, threshold, executors | tech lead | 3.4, 6.3 | **2-of-3 Safe**, same address on both chains; open execution | **decided** (the tech lead, 2026-11-17): one EOA admin key for every admin role, proposer included; no Safe on testnet |
| D3 | Who holds the six immediate paymaster roles | tech lead | 3.5, 6.2 | **Separate holders**, dev-team keys | **decided** (the tech lead, 2026-11-17): the same EOA admin key holds every immediate role (`PAYMASTER_GRANT_ALL_TO`); role keys can come later |
| D4 | Timelock delays on testnet | product / tech lead | 4.2, 6.3 | **Keep** the profiles' 5 min–1 h | **approved** (2026-11-17: The tech lead aware, confirmed by the developer) |
| D5 | Tenants, their sponsorship allowlists and the test ERC-20 | tech lead | 3.5, 9 | **Both dev tenants**; deploy the **test ERC-20** and allow-list it | **approved** (2026-11-17: The tech lead aware, confirmed by the developer) |
| D6 | RPCs for the deploy and for `GIANO_CHAINS` | tech lead / DevOps | 3.5, 10.3 | **Keyed** RPC for both (`dev` already has one) | **approved** (2026-11-17: The tech lead aware, confirmed by the developer) |
| D7 | Testnet ETH: amounts and where it comes from | dev / DevOps | 5.2 | Team testnet wallet | **decided** (2026-11-17): the tech lead funds the testnet accounts; Giano accounts take no funds from other projects' accounts. Funded 2026-11-17 |
| D8 | Custody of the testnet canonical deployer key | tech lead | 3.1 | Own 1Password item, dev team + tech lead only | **done**: #296 merged 2026-11-17; vault membership still to confirm |
| D9 | Fix G42 before the first live deploy? | tech lead | 6 | **Yes** for R4, R5, R6; R1 to R3 may follow | **done**: all six (R1–R6) fixed in #298, merged 2026-11-17. G42's R1–R6 are the tracker's findings R3–R8 |

---

## D1. Reset `dev`, or migrate its legacy v0.7 accounts

**Blocks:** retiring the legacy deployment (12).

**Facts**
- Release `v3` uses EntryPoint v0.9 and a new factory at a CREATE3 address. Existing `dev` wallets are v0.7 accounts
  under the legacy factory `0x26dCd293…7050`. Nothing moves them; a user's passkey derives a **different** account
  address under the new factory.
- No migration tool exists. A migration would need its own design: users moving assets from old to new accounts,
  and the database mapping old accounts to new ones (README §5 warns never to reinterpret old addresses silently).
- The legacy paymaster still holds funds (*measured*, EntryPoint v0.7 `getDepositInfo`):

  | Chain | Deposit (all tenants' balances plus slack) | Stake | Unstake delay |
  |---|---|---|---|
  | Base Sepolia | 0.09999 ETH | 0.1 ETH | 1 day |
  | Ethereum Sepolia | 0.04 ETH | 0.11 ETH | 1 day |

- `dev` is a testnet environment; its users are the team and demo tenants.
- **Reset also means a data reset** (found 2026-11-16). wallet-api computes a wallet address once, at passkey
  registration, and stores it in `credentials.wallet_address` (`routes/webauthn.ts`). Nothing records which factory
  derived it, and nothing recomputes it later: the MC-22 identity check in `chain-verify.ts` lives in memory and
  never compares with stored rows. After the switch, every existing `dev` credential still logs in to its **legacy
  v0.7 address**, which the v0.9 stack can't operate. So existing users, credentials and sessions must be cleared
  (tenants, their config and admins kept), or those users get a broken wallet with no error that names the cause.
- The wallet is UUPS, and `docs/ENTRYPOINT-V09-UPGRADE.md` §"Existing deployments" allows an owner-signed in-place
  upgrade that keeps the address. It only covers deployed accounts (counterfactual ones have no code), needs a
  storage-compatibility check between the legacy and v3 implementations, and conflicts with wallet-api assuming
  every stored address is the v3 factory's derivation. Nothing implements it.

**Options**
1. **Reset (recommended).** After the new contracts are live and smoke-tested, switch `dev` and clear its user data
   (users, credentials, sessions and the rows that hang off them; keep tenants, tenant config, admins). Then withdraw
   each legacy tenant balance to its withdrawal address, unlock and withdraw the stake. Test wallets on the old
   factory are left behind. Cost: everyone re-registers a passkey on `dev`, gets a new address, and loses whatever
   test assets the old one held.
2. **Migrate (new accounts).** Keeps users' wallets meaningful. Cost: a separate design and tool, user action per
   wallet, and a rollout that waits for both. Hard to justify for test assets.
3. **Upgrade in place.** Each owner signs a UUPS upgrade of their legacy account. Cost: as option 2, plus the
   storage check and wallet-api changes above; counterfactual accounts can't use it.

**Needed:** a yes on reset (and on clearing `dev`'s user data), or a decision to plan a migration first.

**Proposed (the developer, 2026-11-16):** option 1, reset. Awaiting the tech lead's ok.

## D2. The testnet proposer Safe

**Blocks:** creating the Safe (3.4) and deploying the timelock (6.3).

**Facts**
- After the hand-off (6.4), the timelock holds `ROLE_ADMIN`, the upgrader, fee-admin and withdraw-address-admin
  roles. The proposer schedules (and can cancel) every timelocked change: upgrades, role changes, fee and
  withdrawal-address changes.
- The hand-off refuses an EOA proposer **only on a mainnet**. On testnet a key would pass, but then the runbook §6
  rehearsal (step 13, an upgrade through a real Safe) cannot happen, and the testnet would not resemble production.
- The profile lists proposers per chain (`timelock.proposers`), and `executors: []` means open execution: anyone
  may run an operation once its delay has passed, nobody can run it early.
- Safe{Wallet} supports both chains (*checked* 2026-11-16 on the Safe config service: Base Sepolia and Sepolia
  each have a transaction service, Safe Apps and multi-chain Safe creation). Multi-chain creation can give the Safe
  the **same address on both chains** when created with the same signers and threshold.
- Runbook §5 suggests a second, independent proposer Safe kept for recovery: it can cancel a hostile proposal if
  the first Safe is compromised.

**Options**
1. **A 2-of-3 Safe on each chain (recommended).** Signers, for example: tech lead, a developer, DevOps. Open
   execution. Mirrors production and lets step 13 run.
2. A 1-of-1 Safe: faster for a testnet, but step 13 then rehearses nothing about multi-party approval.
3. An EOA proposer: allowed on testnet, not recommended (step 13 impossible).

**Needed:** the signers (by name), the threshold, and whether execution stays open. The Safe addresses follow when
the Safes are created.

**For the tech lead (the developer, 2026-11-16):** left open for his input and view. Questions: threshold and type; the three
signers; signer keys (personal wallets or vault keys); open execution; a recovery Safe now or not on testnet.

## D3. Who holds the six immediate paymaster roles

**Blocks:** the operator env files (3.5) and provisioning (6.2).

**Facts**

| Role | What it can do, immediately (no timelock) |
|---|---|
| `SIGNER_ADMIN` | add or remove the sponsorship signer (whose signatures spend tenants' balances) |
| `PARAM_ADMIN` | set the post-op gas allowance and the penalty basis points |
| `PAUSER` | pause and unpause sponsorship |
| `STAKE_ADMIN` | add stake, unlock and withdraw the EntryPoint stake |
| `TENANT_ADMIN` | register tenants, enable or disable them |
| `FEE_COLLECTOR` | withdraw collected fees |

- `docs/key-ceremony.md` puts testnet role holders out of ABIP-8 scope: developer-held keys are acceptable.
- Provisioning supports either one holder per role (`ROLE_HOLDER_*`) or `PAYMASTER_GRANT_ALL_TO` (one address;
  refused on mainnet). The fork rehearsal tested the separate-holder path.
- The operator console and the giano-paymaster CLI act with these keys later: registering a new tenant needs the
  `TENANT_ADMIN` key, staking needs `STAKE_ADMIN`.
- G42 R1 (mainnet must name all six, distinct) does not apply to testnet.
- The Giano 1Password vault already holds `dev` keys. Role holders may reuse dev-team keys that aren't used anywhere
  else; they must never be the canonical deployer, and the bootstrap operator (which holds `ROLE_ADMIN` until the
  hand-off) must not be the deployer either (the tooling refuses it).

**Options**
1. **Separate holders, dev-team keys (recommended).** One key per role in 1Password, so testnet runs the production
   topology and the console flows get exercised per role. More keys to manage.
2. **`PAYMASTER_GRANT_ALL_TO` one dev-team address.** Simplest. Testnet stops resembling production, and one leaked
   key holds every immediate power on the testnet paymaster.
3. A mix: `PAUSER` and `TENANT_ADMIN` on separate keys, the rest on one.

**Needed:** the option, and for each role who holds the key and where it is stored.

**Leaning (the developer, 2026-11-16):** option 2, one address for every role. The tech lead's input asked before it is final.
Checked: no service holds a role key; only the operator console (a browser wallet) and the CLI use them.

## D4. Timelock delays on testnet

**Blocks:** the rehearsal with the real configuration (4.2) and the timelock deploy (6.3).

**Facts** (both profiles, identical)

| Operation | Delay |
|---|---|
| floor (`minDelay`), and anything not listed (e.g. adding a proposer) | 5 min |
| upgrade (`upgradeToAndCall`) | 1 h |
| grant, revoke or renounce a role | 1 h |
| change a tenant's withdrawal address | 30 min |
| change the default fee | 20 min |
| change a tenant's fee | 10 min |

- The runbook calls delays a promise to tenants, so a product decision. The upgrade delay must be long enough for
  a tenant to withdraw its balance (R-51), and role changes must wait at least the longest other delay (enforced).
- Changing a delay later is itself queued and waits at least the delay it changes: lengthening is easy, shortening
  takes as long as the current delay.
- Production delays are a separate, open decision (not needed for testnet).

**Options:** keep them (recommended: step 13 can then run in about an hour), or set longer ones now to rehearse
production-like waits (every testnet change then waits that long).

**Needed:** keep, or the new values.

**Proposed (the developer, 2026-11-16):** keep the profiles' delays. Awaiting the tech lead's ok.

## D5. Tenants, their sponsorship allowlists and the test ERC-20

**Blocks:** the operator env files (3.5) and installing sponsorship rules (9).

**Facts**
- `dev` has two tenants. Their on-chain IDs are their database UUIDs and must stay the same, or every sponsorship
  is refused as an unknown tenant:

  | Tenant | ID | Shape |
  |---|---|---|
  | `example` | `cf0d5345-0fdb-4688-b1db-9a288c9d9aed` | stock wallet UI |
  | `byoui` | `743480a4-bdc8-4792-8ddf-625e074bd6c2` | brings its own wallet UI |

- An **empty allowlist sponsors nothing**, wallet management included (finding N3). Each tenant needs at least one
  contract on each chain.
- The reference dApp's ERC-20 card needs Giano's test ERC-20. It isn't deployed on either testnet yet
  (`infra/iac/_locals.tf` and `ecs_services.tf` wait for it as `defaultToken`). `deploy:cli testing` may deploy the
  test fixtures on a testnet; it refuses only on production and mainnet chains (R-29).
- `deploy:cli testing` deploys **two** fixtures (`deploy.ts` `deployTesting`): the test ERC-20 (`PrivateERC20`,
  `mint(amount)` open to anyone, so it is its own faucet) and a `PermissivePaymaster`, which sponsors **any**
  operation. It funds the permissive paymaster's deposit with `--fund-eth`. On a public testnet anyone could drain
  that deposit, so run it with `--fund-eth 0` (found 2026-11-16). Both land at CREATE3 addresses, the same on both
  testnets.
- `byoui` is enabled on `dev` only (`byo_wallet_enabled` in `infra/iac/ecs_services.vars.tf`).
- `TENANT_WITHDRAW_ADDRESS`: where a tenant's unspent balance goes. A testnet may default it to the operator; a
  real tenant names its own.
- `TENANT_FUND_ETH`: added to **each** tenant on every provisioning run (not a target balance).

**Options**
1. **Recommended:** provision both tenants on both chains; deploy the test ERC-20 on both testnets
   (`deploy:cli test-token`, added in #303: `deploy:cli testing` also deploys a permissive paymaster, F9) and allow-list it for both tenants; withdrawal address a team-held address;
   `TENANT_FUND_ETH` 0.02 per tenant per chain.
2. Allow-list a contract that already exists (as the rehearsal did with Multicall3): no extra deploy, but the
   dApp's ERC-20 card stays dead.

**Needed:** the tenant list, each tenant's allowlist per chain, the withdrawal address, and the funding amount.

**Proposed (the developer, 2026-11-16):** option 1. Both tenants on both chains; the test ERC-20 deployed on both testnets
with `--fund-eth 0` and allow-listed for both; withdrawal address a team address (the D3 address if D3 ends with
one address for all roles); `TENANT_FUND_ETH` 0.02. Awaiting the tech lead's ok.

## D6. RPCs for the deploy and for `GIANO_CHAINS`

**Blocks:** the operator env files (3.5) and the `chains` secret (10.3).

**Facts** (*measured*)
- Base Sepolia public RPC `https://sepolia.base.org`: `eth_getLogs` up to `toBlock - fromBlock = 200`. With #294
  the watcher and the console work on it, but a fresh wallet-api needs ~1.5 to 2 minutes to catch up, and public
  endpoints rate-limit.
- Ethereum Sepolia public RPC `https://ethereum-sepolia-rpc.publicnode.com`: served a 50,000-block `eth_getLogs`.
- The **bundler** is not covered by the 200-block change (the reviewer's review of #294, finding F6). It looks up receipts of
  operations it didn't submit itself (after a restart, or through another replica) with one `eth_getLogs` over the
  last `bundler.maxBlockRange` blocks, 2,000 by default. On `sepolia.base.org` that needs `"bundler":
  { "maxBlockRange": 200 }`, which covers only about the last 400 seconds of Base Sepolia.
- `dev` already reads both chains through keyed upstreams (`secret_arns`, proxied by nginx for the dApp).
- RPC URLs only ever live in the backend `chains` secret and ignored local env files, and the tooling now redacts
  them from output.

**Options:** keyed RPC for the deploy and for `GIANO_CHAINS` (recommended: reuse `dev`'s provider; no bundler
workaround needed), or the public endpoints (works after #294 with the bundler limited to a 200-block receipt
lookback, slower and rate-limited).

- `dev`'s keyed upstreams are QuickNode (`infra/iac/ecs_services.tf`): the `chains` secret is composed by hand in
  1Password; the dApp and console proxies read `rpc-url-base-sepolia` and `rpc-url-eth-sepolia`. QuickNode caps the
  `eth_getLogs` range per plan; `dev`'s cap is not measured yet. If it is under 2,000, the bundler's `maxBlockRange`
  must match it.

**Needed:** which provider, and confirmation that the same keyed URL can be used from the deploying shell.

**Proposed (the developer, 2026-11-16):** keyed, reusing `dev`'s QuickNode URLs for the deploy and `GIANO_CHAINS`. To do
before Phase 3.5: measure the plan's `eth_getLogs` cap and set `bundler.maxBlockRange` to fit.

**Measured (2026-11-17):** `dev`'s QuickNode URLs served `eth_getLogs` over 200, 2,000, 5,000 and 10,000 blocks on
both Base Sepolia and Ethereum Sepolia (filtered on the EntryPoint; no refusal at any range). The bundler's default
`maxBlockRange` (2,000) fits, so `GIANO_CHAINS` needs no `bundler` section with these URLs. Awaiting the tech lead's
ok.

## D7. Testnet ETH: amounts and where it comes from

**Blocks:** funding (5.2).

**Facts** (per chain, from `TESTNET-ROLLOUT.md` step 4; `pnpm contracts:funding` prints the exact figures)

| Account | Needs |
|---|---|
| Testnet canonical deployer `0xBf8e1e80ac0687f2dd0b2909f5a68E3f6d5c41B5` | ≥ 0.05 ETH (the profile's reserve) |
| Bootstrap operator | 0.1 ETH stake + `TENANT_FUND_ETH` × tenants (0.04 with D5's recommendation) + gas |
| Bundler executor (one key for both chains; `dev`'s existing `alto-executor-key`) | ≥ 0.05 ETH |

So roughly 0.25 to 0.3 ETH per chain, 0.5 to 0.6 ETH in total. The legacy deployment holds about 0.35 ETH
(D1 table), but only returns it at step 12, after the new contracts are live: it can't fund this rollout.

- *Measured* 2026-11-16: the testnet deployer holds 0 ETH on both chains; gas is ~0.006 gwei on Base Sepolia and
  effectively zero on Ethereum Sepolia, so the amounts are dominated by the 0.1 stake and the reserves. The stake
  comes back (unlock, 1 day, withdraw). If D3 ends with one role-holder address, it needs ~0.01 ETH for gas too.
- `dev`'s bundler executor probably holds ETH already (it runs `dev`'s bundler); check its balance at 5.1.

**Needed:** who sends it, and from where (faucets, a team testnet wallet).

**Decided (the developer, 2026-11-16):** The developer funds both chains himself and asks if more is needed. The post only tells
The tech lead the cost (~0.6 ETH total). Funding stays per account (deployer, bootstrap operator, executor); the
canonical deployer is never used to forward funds (`docs/key-ceremony.md`: gas float only).

## D8. Custody of the testnet canonical deployer key (done)

**Done 2026-11-16.** An independent random key, generated with `multichain-keygen 2.0.0` (`--rng openssl`) and
piped straight into 1Password, never displayed. ABIP-8 exempts it (Exceptions §1: testnet-only keys with no real
value) and `docs/key-ceremony.md` puts canonical deployers out of the ceremony, but its generation method was
followed anyway.

| | |
|---|---|
| Address | `0xBf8e1e80ac0687f2dd0b2909f5a68E3f6d5c41B5` |
| 1Password | item "Giano testnet canonical deployer" |
| PR | #296 sets `DEPLOYERS.testnet` (review: tech lead) |
| Testnet addresses it fixes | wallet implementation `0x265dA930…9406`, factory `0xA9d72F08…F635`, paymaster implementation `0x3C99Acb0…5540`, paymaster proxy `0xb2C7081b…615a`, the same on every testnet |

**Still needed:** confirm that the vault's members are the developers who deploy and the tech lead. The vault
already holds other `dev` keys, so it may be wider than that.

## D9. Fix G42 before the first live deploy?

**Blocks:** Phase 6.

**Facts** (Notion G42, from the reviewer's review of #279; all low severity)

| # | Point | Bites on testnet? |
|---|---|---|
| R1 | Mainnet must name all six role holders, distinct | no (mainnet only) |
| R2 | Cancun check reports transport errors as "Cancun unavailable" | only as a misleading message |
| R3 | `DEPLOYMENTS_DIR` switches to rehearsal before the fork check | only with a stale env var |
| R4 | Hand-off accepts any timelock when no address is published | narrow: `contracts:timelock` always records it |
| R5 | `--from-block` later than the deploy block skips earlier grants | only if an operator passes it |
| R6 | `--unstake-delay` parsed after the first transaction | a typo costs a transaction |

The hand-off cannot be undone, and R4 and R5 are hand-off checks.

**Options:** fix R4 to R6 first (recommended: small, and the hand-off is irreversible), the rest later; or deploy
with G42 open and follow the checklist carefully.

*Checked* 2026-11-16 on `main`: R4 (`timelockMismatch` returns nothing when no address is published), R5
(`cli.ts` takes `--from-block` as given) and R6 (`provision-paymaster.ts` reads `--unstake-delay` with `Number()`
just before `addStake`) are all still open.

**Decided (the developer, 2026-11-16):** fix all six (R1–R6) in one PR before the deployment (Phase 6). The developer opens it.

---

## Notes for the team channel post

Not part of the decisions; reminders for when the post is written.
- D1: quote option 1's full description (reset at the switch, clear users/credentials/sessions and keep tenants,
  tenant config and admins, everyone re-registers and gets a new address, legacy funds withdrawn in Phase 12), not
  just "reset", and mention F8 as the reason the data reset is needed.
- D2: no proposal from the developer; ask the tech lead for his input and his view of how the Safe should look (threshold and
  type, the three signers, personal wallets or vault keys, open execution, a recovery Safe).
- D3: The developer leans to one address for all six roles (`PAYMASTER_GRANT_ALL_TO`); ask the tech lead's input. Say the
  trade-off: simplest, but testnet stops mirroring production and one leaked key holds every immediate power.
- D4: The developer proposes keeping the testnet delays (5 min to 1 h); ask the tech lead's ok.
- D5: The developer proposes the recommendation as written; mention the `--fund-eth 0` finding (the permissive paymaster).
- D6: The developer proposes keyed RPCs (`dev`'s QuickNode); mention the bundler lookback (F6) as the main reason.
- D7: FYI only, no ask: the cost (~0.25–0.3 ETH per chain), the developer handles the funds.
- D9: decided, not a question: The developer is fixing all of G42 (R1–R6) in one PR before Phase 6; link the PR once open.

## the tech lead's answers (the team channel thread, 2026-11-17)

- **D2, D3:** "generate a EOA admin key. Use it for every admin role. In testnet we want to keep it simple, and we
  can always change to specific role keys later." So: one new EOA, used as the timelock proposer (and canceller)
  and as `PAYMASTER_GRANT_ALL_TO`. Consequence: Phase 13 (an upgrade through a real Safe) cannot run as written; it
  becomes an upgrade queued by the admin key.
- **D8:** "#296 looks good to me." Reminder from him: Giano's accounts must be disconnected from any other project,
  provisioned specifically for Giano, and must not receive funds from accounts connected to other projects.
- **D7:** that rule rules out the developer's Sepolia funds (they come from accounts used for other projects). The developer asked
  The tech lead to fund the accounts; no answer yet.
- **D1, D4, D5, D6:** no comment yet (no objection either).
- Open: is the admin EOA also the bootstrap operator (`DEPLOYER_PRIVATE_KEY` in provisioning, which holds
  `ROLE_ADMIN` until the hand-off)? The tooling allows it on testnet; only the canonical deployer is refused.
- **Admin key created 2026-11-17:** "Giano testnet admin", `0x033178C012FAAB6977FE3b760e5Ca9BBAb4F3030`. The developer decided it
  is also the bootstrap operator (`roleAdmin`). PR #302.
- **D1, D4, D5, D6 approved 2026-11-17:** The tech lead is aware of the proposals; the developer confirmed them as approved. All
  decisions are settled.
