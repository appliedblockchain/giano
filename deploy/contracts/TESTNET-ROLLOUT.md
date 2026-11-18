# Testnet and `dev` rollout checklist

The ordered steps that put release `v3` on Base Sepolia and Ethereum Sepolia, and move the `dev`
environment off its legacy contracts. Everything here was rehearsed on a fork of Base Sepolia
(`pnpm contracts:rehearse --platform`; evidence in
`openspec/changes/archive/2026-11-16-harden-contract-deployment/rehearsal-evidence.md`). **Steps 1–6 and step 7's
records are done (2026-11-17): release v3 is live on both testnets, handed to the timelock.** The rest of this page is
the plan for moving `dev` onto it.

Why `dev` needs it: `infra/versions.json` pins `dev` to `5ba71241`, from before the CREATE3 cutover
(#132). That deployment runs EntryPoint v0.7 and the legacy factory `0x26dCd293…`. Current `main`
cannot be rolled out to it, because wallet-api refuses to start when the registry has no entry for a
chain it serves and the contracts there are not release code for EntryPoint v0.9.

## Decisions needed first

| Decision | Who | Notes |
|---|---|---|
| Reset `dev`, or migrate its legacy v0.7 accounts | tech lead | README §5. A reset is the usual testnet answer: announce it, withdraw the legacy paymaster's tenant balances and stake, and let existing test wallets go. A migration needs its own plan; no tool exists for it. |
| The testnet timelock's proposer | tech lead | **Decided (2026-11-17):** no Safe on testnet. One EOA admin key, 1Password item "Giano testnet admin" (`0x033178C012FAAB6977FE3b760e5Ca9BBAb4F3030`), is the timelock's proposer in both testnet profiles. The hand-off refuses an EOA proposer only on a mainnet. |
| The holder of each immediate paymaster role on testnet | tech lead | **Decided (2026-11-17):** the same testnet admin key holds all six (`PAYMASTER_GRANT_ALL_TO`), and is also the bootstrap operator (profile `roleAdmin`, `DEPLOYER_PRIVATE_KEY` for provisioning). Specific role keys can come later. |
| How wallet-api survives an RPC that caps `eth_getLogs` | tech lead | **Decided (2026-11-16):** shrink the span to 200 blocks now and optimise the whole process later. The paymaster watcher, which tells wallet-api each tenant's balance, asked for up to 9,000 blocks per `eth_getLogs`; `https://sepolia.base.org`, the Base Sepolia profile's public RPC, serves 200, so the watcher ingested nothing, every tenant read as unfunded and every sponsorship was refused. Done (#294): the watcher reads 200 blocks a pass, the paymaster SDK (the console's log reads) narrows down to 200 when a node refuses a wider span, and the hand-off's role-grant check reads 200 blocks at a time. Not done: the bundler's receipt lookup still reads `bundler.maxBlockRange` (default 2,000) blocks, see the `GIANO_CHAINS` draft. Step 10 must roll a `main` SHA that includes it. Found by the rehearsal (N4). |
| Testnet timelock delays | product | The shipped profiles carry rehearsal delays (5 minutes to 1 hour). Keep them for testnet unless product decides otherwise. |

Before mainnet only, not before testnet: mainnet canonical deployer custody (`docs/key-ceremony.md`
now states its leak impact), production role holders and production timelock delays.

## Steps

| # | Step | Who | Done when |
|---|---|---|---|
| 1 | **Done (2026-11-16):** 1Password item "Giano testnet canonical deployer", address `0xBf8e1e80ac0687f2dd0b2909f5a68E3f6d5c41B5`. Create the **testnet canonical deployer**: an independent random key in its own 1Password item with restricted access. It fixes the testnet wallet address space for good, so treat it as long-lived. | development team | the 1Password item exists |
| 2 | **Done (#296).** PR: set `DEPLOYERS.testnet` in `packages/contracts/deploy/config.ts` to its address, and name the 1Password item in `docs/key-ceremony.md`. CI `check:determinism` then covers the testnet class. | development team | merged, CI green |
| 3 | Rehearse again against the real deployer address on a fork: `pnpm contracts:rehearse --chain base-sepolia --platform`, then `--chain ethereum-sepolia`. `--fork-url` is optional: with the 200-block span the watcher works through the profile's public RPC too. The stand-in deployer is still used, but the profiles, release and tooling are exactly what step 5 runs. | development team | every step ✓ |
| 4 | Fund on each chain: the testnet deployer (≥ 0.05 ETH, the profile's reserve), the bootstrap operator (0.1 ETH stake plus tenant funding plus gas) and the bundler executor (≥ 0.05 ETH). `pnpm contracts:funding --chain <profile> --env-file <operator-file>` prints the amounts. | development team / DevOps | balances confirmed |
| 5 | **Done (2026-11-17).** **Base Sepolia**, in order: `pnpm contracts:deploy --chain base-sepolia`, then `contracts:provision`, `contracts:timelock`, `contracts:handoff` and `contracts:doctor` (deploy/contracts/README.md §3–4, runbook §2). | development team | doctor green; record written |
| 6 | **Done (2026-11-17).** **Ethereum Sepolia**: repeat step 5 with `--chain ethereum-sepolia`, the same release, deployer and bootstrap admin. | development team | doctor green |
| 7 | Commit `packages/contracts/deployments/84532.json` and `11155111.json`, both profiles (with their timelock addresses) and the regenerated `addresses.ts` (**done: #304**). Then release `@appliedblockchain/giano-contracts`. | development team | records committed (#304); package published |
| 8 | **Token deployed (2026-11-18)** at `0x461E0641a3615336b7D2E4C5D71fB2BB88038C93` on both chains; its records are in the registry. Deploy the test ERC-20 on each chain (D5), from the canonical deployer only and without an operator file loaded: `DEPLOYER_PRIVATE_KEY=<testnet canonical deployer> node --import tsx deploy/cli.ts test-token --rpc <url> --chain <profile> --holder <admin>` (in `packages/contracts`). It lands at the same address on both chains, with the profile's release. **Then publish it like step 7:** commit the `testErc20` entry of both records and the regenerated `addresses.ts`, with a changeset, and release `@appliedblockchain/giano-contracts` again; step 7's release went out without the token. Then install each tenant's sponsorship rules on each chain: `pnpm contracts:sponsorship` with `SPONSOR_ALLOWLIST` set to the tenant's contracts, or the console. An empty allowlist sponsors nothing, wallet management included, so each tenant needs at least one contract. **Allow-listing the test ERC-20 lets anyone spend that tenant's balance:** anyone may `mint`, so any wallet can send sponsored mints until the balance runs out. That is the point for `dev`'s demo tenants (D5, testnet funds only); never allow-list it for a tenant whose balance matters | development team | package published; rules read back |
| 9 | Update the `chains` secret (`GIANO_CHAINS`) and the Terraform address variables: see **Cut-over runbook** below, which orders steps 9 and 10 with the user-data reset (D1). | DevOps | `terraform plan` reviewed |
| 10 | Bump `infra/versions.json` `dev` to the tested `main` SHA (a `deploy/dev-<sha>` PR) and roll. | DevOps | `GET /v1/version` lists both chains ready, and `giano_paymaster_watcher_lag_blocks` (wallet-api `/metrics`) is within a few blocks on both chains. On a fresh database the watcher replays 5,000 blocks at 200 a pass, so for a few minutes every tenant reads as unfunded and sponsorship is refused; don't start step 11 before the lag drops |
| 11 | Smoke test on each chain: create a passkey account, sign, send a sponsored transaction. Check that the operator console shows the tenant, its balance and the timelock (the fork rehearsal does not cover the console). Record the transaction hashes, explorer links and account addresses (README "Recovery and evidence"). | development team | evidence recorded |
| 12 | Retire the legacy deployment: withdraw the legacy paymaster's tenant balances (each tenant's withdrawal address) and its stake (stake admin, after the unstake delay). | DevOps / tenants | legacy deposit and stake at zero |
| 13 | Rehearse a timelocked paymaster upgrade on Base Sepolia, queued by the testnet admin key as proposer (runbook §6 with an EOA instead of a Safe; a Safe rehearsal waits for a production-like proposer). The tooling reconciles the executed upgrade into the record. | development team | doctor green after execution. Its warning that the proposer "is a key … not a Safe" is expected on testnet (D2) |

## Drafts to fill in at step 9

CREATE3 places the contracts by the testnet deployer's address, so their addresses are known before steps 5 and 6
and are the same on both testnets. The records written in those steps confirm them; copy from the records.

`GIANO_CHAINS`: the final document, with the v3 addresses filled in, is in the **Cut-over runbook** below. If
`rpcUrl` (or `bundler.rpcUrl`) were the public `https://sepolia.base.org`, the bundler would also need
`"bundler": { "maxBlockRange": 200 }`: it looks up receipts of operations it did not submit itself with one
`eth_getLogs` over the last `maxBlockRange` blocks, 2,000 by default, which that RPC refuses. `dev`'s keyed
QuickNode URLs serve 10,000 blocks, so the section is left out.

Terraform (`infra/iac/ecs_services.vars.tf`): `paymaster_address` and `factory_address` default to the v3
proxy and factory, and `test_erc20_address` gives the reference dApp's `defaultToken` on both chains (they were
the legacy `0xf98b56de…0718` and `0x26dCd293…7050` before the cut-over PR).

The real addresses, from the testnet deployer `0xBf8e1e80ac0687f2dd0b2909f5a68E3f6d5c41B5` (read-only plan
against both public RPCs, 2026-11-17; deploy/contracts/README.md, "Read-only public-network evidence"). A
rehearsal uses a stand-in deployer and lands elsewhere: never copy a rehearsal address.

| Contract | Address on both testnets |
|---|---|
| wallet implementation | `0x265dA930A9253fCC09E120B6f89EE8a91BcA9406` |
| factory | `0xA9d72F088C0Cd0B78db44D4c79E847FddD52F635` |
| paymaster implementation | `0x3C99Acb0e2AE5C446E5eeab23D6cd7F40e9C5540` |
| paymaster proxy | `0xb2C7081be89D88f1da020530Ebd5c14b8871615a` |

## Cut-over runbook (steps 9 and 10)

Moves `dev` from the legacy v0.7 contracts to release v3 on both chains. Everything the switch needs is
ready: the contracts are live and handed to the timelock (steps 5–6), `@appliedblockchain/giano-contracts`
7.1.0 carries both chains in its registry (step 7), and the test ERC-20 is deployed (step 8). DevOps runs
the infrastructure parts; the development team runs the checks and step 8's sponsorship rules afterwards.

The order matters because ECS tasks read the `chains` secret when they start, and because wallet-api refuses
a chain whose configured factory does not run release code. A new image with the legacy secret, or the legacy
image with the new secret, does not serve. So the secret changes in Secrets Manager first, without a restart,
and the roll to the new image follows straight after.

**Before the switch** (nothing changes for users yet):

1. **Snapshot** (tracker 10.1): take a manual RDS snapshot of `dev`'s database, and keep a copy of the
   current `chains` value in 1Password, the `infra/versions.json` `dev` SHA (`5ba71241`) and the current
   Terraform variables. These are the rollback inputs; the reset in step 6 is undone only by the snapshot.
2. **Merge the infrastructure PR**: `paymaster_address` and `factory_address` default to the v3 proxy and
   factory, and `test_erc20_address` gives the reference dApp's `defaultToken`. Merging applies nothing.
3. **Open the deploy PR** `deploy/dev-<sha>`: `infra/versions.json` `dev` set to the tested `main` SHA (7.1.0
   or later). Do not merge it yet.

**The switch** (a short window; `dev`'s users re-register anyway):

4. **Update the `chains` secret**: in 1Password, item `secrets-dev` (vault "Giano dev/stg"), replace the
   `chains` field with the document below, keeping any other field you already set (bundler or console
   settings), and raise its version in the item's inventory note (Terraform never reads the value back: the version is the
   only signal that it changed). Mirror it to Secrets Manager on its own:
   `terraform apply -target='module.asm-app.aws_secretsmanager_secret_version.secret["chains"]'`. Running
   tasks keep the old value until they restart.
5. **Roll**: merge the deploy PR. `deploy.yml` rolls every service to the new image; wallet-api's `init`
   container applies the migrations before the API starts. Then run the full `terraform apply`, which
   applies the new variables (the reference dApps' `defaultToken`, wallet-byo's `FACTORY_ADDRESS`, the
   provisioning task's paymaster) and converges on the deployed tag.
6. **Reset the user data** (D1, F8): once the new wallet-api task is healthy, run
   [`dev-v3-reset.sql`](dev-v3-reset.sql) once against `dev`'s database (`psql "$DATABASE_URL" -v
   ON_ERROR_STOP=1 -f dev-v3-reset.sql`). One transaction: it clears users, passkeys, sessions and their logs,
   the legacy paymaster's ledger and the watcher's cache, and keeps tenants, their configuration and the
   platform admins. It prints the counts before and after.
7. **Restart wallet-api** (`aws ecs update-service --force-new-deployment` on the wallet-api service), so the
   paymaster watcher reconciles every balance from the v3 paymaster at once instead of at its next 60-second
   pass.

**Readiness** (step 10's "done when"):

8. `GET /v1/version` lists both chains ready; wallet-api's log shows both chains admitted with the v3 factory.
9. `giano_paymaster_watcher_lag_blocks` on wallet-api's `/metrics` is within a few blocks on both chains.
10. The operator console shows both tenants with 0.02 ETH on both chains, and the timelock
    `0x7Da25D415f9b68422F905C015137Af8D915F8A78`.

Then step 8's sponsorship rules (each tenant on each chain, the test ERC-20 allow-listed) and step 11's smoke
test.

**If it fails:** before step 6, revert the deploy PR and the infrastructure PR, restore the `chains` value
in 1Password and apply. After step 6, also restore the RDS snapshot. The legacy contracts stay funded and
untouched until step 12.

The `chains` document (`GIANO_CHAINS`, read by wallet-api, the bundler and the console). The registry would
supply `entryPoint`, `sponsorshipPaymaster` and the factory, but stating them lets wallet-api check them against
the chain at boot. With `dev`'s keyed QuickNode URLs no `bundler` section is needed (measured: `eth_getLogs`
served up to 10,000 blocks on both chains; the bundler's default is 2,000). Checked against wallet-api's and the
bundler's chain schemas and `validateChainList`:

```json
[
  {
    "chainId": 84532,
    "name": "Base Sepolia",
    "rpcUrl": "<dev's QuickNode Base Sepolia URL>",
    "entryPoint": "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
    "sponsorshipPaymaster": "0xb2C7081be89D88f1da020530Ebd5c14b8871615a",
    "walletApi": {
      "factory": "0xA9d72F088C0Cd0B78db44D4c79E847FddD52F635",
      "policy": { "allowedPaymasters": ["0xb2C7081be89D88f1da020530Ebd5c14b8871615a"] }
    }
  },
  {
    "chainId": 11155111,
    "name": "Ethereum Sepolia",
    "rpcUrl": "<dev's QuickNode Ethereum Sepolia URL>",
    "entryPoint": "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
    "sponsorshipPaymaster": "0xb2C7081be89D88f1da020530Ebd5c14b8871615a",
    "walletApi": {
      "factory": "0xA9d72F088C0Cd0B78db44D4c79E847FddD52F635",
      "policy": { "allowedPaymasters": ["0xb2C7081be89D88f1da020530Ebd5c14b8871615a"] }
    }
  }
]
```

## Rollback

CREATE3 contracts cannot be removed. Until step 12, the legacy contracts stay funded, so rolling
back means restoring the previous `infra/versions.json` SHA and chains secret, and, once the user data
has been reset (cut-over step 6), the RDS snapshot taken before it. Do step 12 only after
step 11 has passed on both chains.
