# Fresh deployment guide

This guide deploys Giano from nothing: the contracts on one or more chains, and an environment (wallet-api,
wallet-web, the bundler, the operator console and the reference dApps) that serves them. It is the order the
testnet v3 rollout followed, as a checklist to repeat on another chain or in another environment.

What it does not cover:

- **Moving an environment that already serves users off older contracts.** That needs a cut-over with a
  user-data decision; see the "Cut-over runbook" in
  [`deploy/contracts/TESTNET-ROLLOUT.md`](../deploy/contracts/TESTNET-ROLLOUT.md).
- **The AWS details of a new environment** (state bucket, DNS, certificates, observability). This guide names
  the steps; [`specs/INFRASTRUCTURE.md` §18](../specs/INFRASTRUCTURE.md#18-bring-up-runbook) has the commands.

The deeper references, used throughout:

| Topic | Document |
|---|---|
| Contract deployment tooling, profiles, the mainnet guard | [`deploy/contracts/README.md`](../deploy/contracts/README.md) |
| Keys and their custody | [`docs/key-ceremony.md`](key-ceremony.md) |
| Timelock topology, proposals, upgrades | [`docs/PAYMASTER-TIMELOCK-RUNBOOK.md`](PAYMASTER-TIMELOCK-RUNBOOK.md) |
| Environment infrastructure, secrets, delivery | [`specs/INFRASTRUCTURE.md`](../specs/INFRASTRUCTURE.md) |
| Readiness gate for a new chain | [`specs/CHAIN-ADOPTION.md`](../specs/CHAIN-ADOPTION.md) |

## Overview

| # | Step | Who | Where |
|---|---|---|---|
| 1 | Decide the inputs | tech lead | this guide |
| 2 | Keys and profiles | developers | 1Password, PRs |
| 3 | Rehearse on a fork | developers | local |
| 4 | Fund the accounts | key holder | each chain |
| 5 | Deploy the core contracts, on each chain | developers | each chain |
| 6 | Publish the records and release the packages | developers | PR, npm |
| 7 | Bring up the environment | DevOps | AWS, 1Password |
| 8 | Create the tenants | platform admin | operator console |
| 9 | Provision, hand off, verify, on each chain | developers | each chain |
| 10 | Install the sponsorship rules | developers | wallet-api admin API |
| 11 | Readiness | developers | metrics, console |
| 12 | Smoke test | developers | `pnpm … smoke` |

The tools: Node.js 24 and the pnpm version pinned in `package.json`, `op` (1Password CLI), `jq`, `aws`,
`terraform` ≥ 1.11 and `gh`. Run every command from the repository root on an up-to-date `main`, after
`pnpm install --frozen-lockfile`.

## 1. Decide the inputs

Write these down before anything is signed. Each one is used in a later step.

| Input | Testnet | Mainnet |
|---|---|---|
| Chains | the profile names in `deploy/chains/` | the same |
| Network class | `testnet` | `mainnet` (the mainnet guard applies) |
| Contract release | the newest committed release (`packages/contracts/releases/`) | the same |
| Canonical deployer | the testnet class's key (`DEPLOYERS.testnet`) | the mainnet class's key (`DEPLOYERS.mainnet`), from a key ceremony |
| `ROLE_ADMIN` and timelock proposer | one admin EOA may hold both | a Safe |
| Immediate role holders (signer admin, param admin, pauser, stake admin, tenant admin, fee collector) | the admin EOA (`PAYMASTER_GRANT_ALL_TO`) | six different addresses, none of them the operator key |
| Sponsorship signer | an address whose key wallet-api holds | an address whose key stays in an HSM |
| Bundler executor | one funded EOA, shared by the chains | the same |
| Timelock delays | the profile's (5 min to 1 h) | longer, per the timelock runbook |
| Tenants | slug, withdrawal address, funding per chain | the same; a non-default withdrawal address is required |
| What each tenant sponsors | its contracts; on a testnet, also Giano's test ERC-20 | its contracts only (no test token on a mainnet) |
| RPC per chain | a keyed endpoint | a keyed endpoint |
| Environment | the Terraform workspace, DNS names, the 1Password note | the same |
| Console admins | the environment's bootstrap admins in `services/wallet-api/src/environments.ts` | the same |

The RPC must serve `eth_getLogs` over at least 2,000 blocks (the bundler's default receipt lookup). Measure it
on each chain before choosing; a provider that caps lower needs a `bundler.maxBlockRange` override in the
chain's entry of the `chains` secret.

## 2. Keys and profiles

1. **Canonical deployer.** If the class has none yet, create the key as `docs/key-ceremony.md` describes and
   set its address in `packages/contracts/deploy/config.ts` (`DEPLOYERS.testnet` or `DEPLOYERS.mainnet`), in a
   PR that names its 1Password item. The key itself never goes in a file; it is loaded into the deploying shell
   only. `pnpm -F @appliedblockchain/giano-contracts deploy:cli addresses` prints the class's deterministic
   addresses: the same on every chain of that class.
2. **Admin, signer and executor.** Create the admin key (or Safe), the sponsorship signer and the bundler
   executor, and record their addresses. Keys live in 1Password (testnet) or an HSM (mainnet signer), never in
   the repository.
3. **Chain profile.** For each chain, `deploy/chains/<chain>.json` sets: `chainId`, `network`, `name`,
   `rpcUrl` (a public fallback), `rpcUrlEnv` (the variable that holds the keyed URL), `release`, `roleAdmin`,
   `minDeployerBalanceEth`, the `paymaster` parameters, and `timelock.proposers`, `timelock.executors` (empty
   means anyone may execute) and `timelock.delays`. Leave `timelock.address` out: `contracts:timelock` writes
   it in step 9. Merge the profile
   changes in a PR.
4. **Operator file.** For each chain, copy `deploy/contracts/operator.env.example` to
   `deploy/contracts/<chain>.local.env` (gitignored) and fill in:

   | Variable | Value |
   |---|---|
   | `<rpcUrlEnv>` (for example `BASE_SEPOLIA_RPC_URL`) | the keyed RPC URL |
   | `DEPLOYER_PRIVATE_KEY` | the admin (`ROLE_ADMIN`) key, for provisioning and the hand-off |
   | `SPONSORSHIP_SIGNER_ADDRESS` | the signer's address |
   | `BUNDLER_EXECUTOR_PRIVATE_KEYS` | the executor key; the funding command reports its balance |
   | `ROLE_HOLDER_*`, or `PAYMASTER_GRANT_ALL_TO` on a testnet | the immediate role holders |
   | `STAKE_ETH`, `UNSTAKE_DELAY` | stake and unstake delay (at least 86400 s on a mainnet) |
   | `TENANT_FUND_ETH`, `TENANT_WITHDRAW_ADDRESS` | each tenant's funding, and where its balance withdraws to |
   | `PAYMASTER_TENANTS` | `slug:uuid` pairs, filled in at step 8 |
   | `SPONSOR_ALLOWLIST` | the contracts tenants sponsor, comma-separated |

   Pass this file with an **absolute** path (`--env-file "$PWD/deploy/contracts/<chain>.local.env"`). The
   commands run `node` inside `packages/contracts`, and Node 26 reads an `--env-file` flag itself, even after the
   script name, relative to that folder: a repository-relative path stops it with
   `node: deploy/contracts/<chain>.local.env: not found` before the script can resolve it.

## 3. Rehearse on a fork

```sh
pnpm contracts:rehearse --chain <chain> --platform
```

It deploys, provisions, hands off and runs a browser smoke test against a fork of the chain, with a stand-in
deployer. Every step must pass. It clears its own logs at start and leaves its compose projects running; stop
them with `docker compose -p giano-rehearsal down` and `docker compose -p giano-fork down` before starting the
e2e stack again.

## 4. Fund the accounts

```sh
pnpm contracts:funding --chain <chain> --env-file "$PWD/deploy/contracts/<chain>.local.env"
```

It prints what each account needs. Fund, on each chain:

| Account | Amount |
|---|---|
| Canonical deployer | the profile's `minDeployerBalanceEth` plus a margin of the same size: a deploy that stops part-way needs the reserve again to resume |
| Admin key | stake + every tenant's funding + gas (the testnet rollout used 0.2 ETH for a 0.1 ETH stake and two tenants at 0.02 ETH) |
| Bundler executor | an initial reserve (0.1 ETH on each testnet); it drains with use |

Fund only from accounts that belong to this project.

## 5. Deploy the core contracts, on each chain

With the canonical deployer key loaded into the shell as `CANONICAL_DEPLOYER_PRIVATE_KEY`:

```sh
pnpm contracts:deploy --chain <chain> --env-file "$PWD/deploy/contracts/<chain>.local.env"
```

The wizard checks the chain, prints the plan and asks for `deploy <chainId> <release>`. It deploys the wallet
implementation, the factory, the paymaster implementation and the paymaster proxy, and records each in
`packages/contracts/deployments/<chainId>.json`. If it stops part-way (an RPC that lags a block can make it
stop before a dependent contract), run it again: it resumes from the record. Run it without the key to verify
a finished deployment.

**Testnets only, the test ERC-20** (the dApps' default token), from the canonical deployer, with no operator
file loaded:

```sh
(cd packages/contracts && DEPLOYER_PRIVATE_KEY="$CANONICAL_DEPLOYER_PRIVATE_KEY" node --import tsx deploy/cli.ts \
  test-token --rpc "<keyed RPC URL>" --chain <chain> --holder <admin address>)
```

It lands at the same address on every testnet and is written to the chain's record. It is refused on a
mainnet.

Repeat step 5 for each chain, with the same release and deployer.

## 6. Publish the records and release the packages

1. Regenerate `packages/contracts/addresses.ts` (`pnpm -F @appliedblockchain/giano-contracts gen:addresses`)
   and open a PR with the records, the profiles and `addresses.ts`, plus a changeset for
   `@appliedblockchain/giano-contracts`.
2. Merge it. The changesets workflow opens a version PR; merging that publishes every package. If the version
   PR fails on `pnpm-lock.yaml`, run `pnpm install --lockfile-only` on its branch and push.

The services read the chain registry from the published package, so later steps need this release.

## 7. Bring up the environment

**A new environment:** follow [`specs/INFRASTRUCTURE.md` §18](../specs/INFRASTRUCTURE.md#18-bring-up-runbook),
steps 0 to 7 (1Password note, DNS, state bucket and workspace, first apply, first deploy, health). The
contract-specific inputs are below.

**An existing environment that gains a chain:** only the inputs below change.

1. **The `chains` secret.** It is the `chains` entry of the environment's 1Password note (`secrets-<env>`), a
   JSON bundle `{ "<name>": { "value": "<string>", "version": n } }`. `chains.value` is a JSON array with one
   entry per chain:

   ```json
   {
     "chainId": 84532,
     "name": "Base Sepolia",
     "rpcUrl": "<keyed RPC URL>",
     "entryPoint": "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
     "sponsorshipPaymaster": "<paymaster proxy from the record>",
     "walletApi": {
       "factory": "<factory from the record>",
       "policy": { "allowedPaymasters": ["<paymaster proxy>"] }
     }
   }
   ```

   Raise `chains.version` with every change: Terraform only rewrites a secret whose version changed. Then mirror
   it: `terraform apply -target='module.asm-app.aws_secretsmanager_secret_version.secret["chains"]'` (the dev
   and stg workspaces read the note from the `Giano dev/stg` vault; prd from its own). Running tasks keep the old
   value until they restart. Fill the addresses from each chain's record
   (`packages/contracts/deployments/<chainId>.json`), never by hand from memory.
2. **Terraform variables** (`infra/iac/ecs_services.vars.tf`): `paymaster_address` (the provisioning task),
   `factory_address` (the BYO wallet's bundle), `test_erc20_address` (the reference dApps' default token) and
   the two chains (`chain_id`, `chain_name`, `chain_b_id`, `chain_b_name`).
   **Only `test_erc20_address` (and `silent_data_chains`) are per-workspace maps today.** The addresses and the
   two chains are single values shared by dev, stg and prd, so changing them for one workspace changes them for
   all. A workspace with other addresses (a mainnet environment, whose canonical deployer gives different
   CREATE3 addresses) or other chains first needs those variables turned into per-workspace maps, in their own
   PR. A third chain that is not a Silent Data chain has no variable yet either.
3. **The deployed version.** A PR that sets the workspace in `infra/versions.json` to a tested `main` SHA whose
   images exist; merging it makes `deploy.yml` roll every service. Check the images first:

   ```sh
   for repo in wallet-api wallet-web paymaster-admin example wallet-byo bundler; do
     aws ecr describe-images --region eu-west-2 --repository-name "giano-<env>/$repo" \
       --image-ids imageTag=<sha> --query 'imageDetails[0].imageTags' --output text || echo "missing: $repo"
   done
   ```

4. **The full apply, after the deploy PR is merged**, from a checkout that includes it: `git pull` on `main`,
   check `infra/versions.json`, select the workspace, then `terraform apply`. Terraform takes the image tag from
   `infra/versions.json`, so an older checkout asks for older images. The plan registers new task definitions;
   if it only moves services to an existing revision, a previous apply was rolled back: find out why (the
   service events and a stopped task's `stoppedReason`) before applying again.

**Done when:** `GET https://<api host>/v1/version` lists every chain `ready`, and, where the workspace runs
them, the reference dApps' `/config.js` carry the chains (and `defaultToken` on testnets) and the BYO wallet's
`/main.js` contains the new factory (`byo_wallet_enabled` is on only in dev).

## 8. Create the tenants

The operator console is at `https://<paymaster host>`. Sign in with a wallet whose address is one of the
environment's bootstrap admins (Sign-In with Ethereum; no transaction). If the wallet refuses to sign, disconnect
the site in the wallet and connect again. A signed-in admin can add more admins in **Platform → Admins**.

For each tenant: **Platform → Create tenant** (slug, display name, wallet origin, dApp and CORS origins,
registration). Note each tenant's ID, and put the `slug:uuid` pairs in `PAYMASTER_TENANTS` in every chain's
operator file.

Then issue one admin key per tenant (**Issue key** on the tenant page). The console shows it once: save it to
1Password straight away. Sponsorship rules belong to the tenant and are set with this key (step 10).

## 9. Provision, hand off, verify, on each chain

Run these in order, for each chain, from a terminal (each signing command asks for a typed confirmation):

```sh
ENV_FILE="$PWD/deploy/contracts/<chain>.local.env"
pnpm contracts:provision --chain <chain> --env-file "$ENV_FILE"   # roles, signer, stake, deposit, tenants
pnpm contracts:timelock  --chain <chain> --env-file "$ENV_FILE"   # deploys the GianoTimelock, saves its address
pnpm contracts:handoff   --chain <chain> --env-file "$ENV_FILE"   # moves the timelocked roles to the timelock
pnpm contracts:doctor    --chain <chain> --env-file "$ENV_FILE"   # must report "all critical checks passed"
```

- **Provisioning** grants the immediate roles, registers the sponsorship signer, stakes the paymaster, and
  registers and funds each tenant. Each run **adds** `TENANT_FUND_ETH` to every tenant again, so do not rerun it
  to fix something unrelated. It works only while the admin key holds `ROLE_ADMIN`, that is, before the
  hand-off. A tenant created later is registered from the console (**Register on-chain**, by a wallet that
  holds the tenant admin role) and funded there (**Fund**, by any wallet).
- **The hand-off** moves `ROLE_ADMIN`, the upgrader, the fee admin and the withdraw-address admin to the
  timelock. It cannot be undone. If a transaction reverts (a stale gas estimate on a lagging RPC), run it again:
  it continues from where it stopped. From then on those changes are timelock proposals
  ([timelock runbook](PAYMASTER-TIMELOCK-RUNBOOK.md)).
- **The timelock command** writes the timelock's address into `deploy/chains/<chain>.json` and the chain's
  record. The hand-off reads the local profile, so it does not wait for a PR: commit both files in a PR after
  the hand-off.
- **Doctor** warnings that are expected on a testnet: the signer reported but not asserted, and a proposer that
  "is a key, not a Safe".

Then add the timelock to the console's view of each chain: in the `chains` secret, set
`paymasterAdmin.timelockAddress` and `paymasterAdmin.timelockDelays` (the profile's delays), raise the version
and mirror it as in step 7.

For **Base Sepolia and Ethereum Sepolia on release v3**,
[`deploy/contracts/dev-v3-chains.mts`](../deploy/contracts/dev-v3-chains.mts) does this in one run, now that
the records hold the timelock: it reads the secret bundle on stdin, fills the step 7 fields and the timelock
fields of both chains from the records and profiles, validates the result against the services' schemas, raises
`chains.version`, and prints the bundle to paste back into the note:

```sh
op item get secrets-<env> --vault '<vault>' --format json \
  | jq -r '.fields[] | select(.id == "notesPlain") | .value' \
  | (cd packages/contracts && node --import tsx ../../deploy/contracts/dev-v3-chains.mts) | pbcopy
```

Its limits: it handles exactly those two chains (the bundle needs an entry with `chainId`, `name` and `rpcUrl`
for both), only release v3, and refuses a record without a timelock or a profile whose timelock address does
not match the record. For other chains or releases, edit the entries by hand from the records.

## 10. Install the sponsorship rules

A tenant with no rules is refused every sponsored transaction, wallet management included. For each tenant, on
each chain:

```sh
export WALLET_API_URL=https://<api host>
TENANT_SLUG=<slug> ADMIN_API_KEY="$(op read '<op:// reference to the tenant admin key>')" \
  pnpm contracts:sponsorship --chain <chain> --env-file "$PWD/deploy/contracts/<chain>.local.env"
```

It installs: sponsorship on, `SPONSOR_ALLOWLIST` allow-listed (all functions), a per-transaction cost cap, and
wallet management under the platform cap. It replaces any existing rule for that tenant and chain. Narrow the
rules in the admin API afterwards if needed.

Read them back (prints no key):

```sh
K="$(op read '<op:// reference>')"
curl -sS -H "Authorization: Bearer $K" "$WALLET_API_URL/v1/admin/sponsorship?chainId=<chainId>" \
  | jq -c '{configured, valid, enabled: .config.enabled, allowlist: [.config.allowlist[]?.contract]}'
unset K
```

Every line must show `configured`, `valid` and `enabled` as `true`, with the intended allowlist.

On a testnet, allow-listing the open-mint test ERC-20 lets anyone spend that tenant's balance with sponsored
mints. Do it only for demo tenants with testnet funds.

## 11. Readiness

1. **Metrics.** `GET https://<api host>/metrics` with the environment's `metrics-bearer-token` (from the
   1Password note):

   ```sh
   T="$(op item get secrets-<env> --vault '<vault>' --format json \
     | jq -r '.fields[] | select(.id=="notesPlain") | .value | fromjson | .["metrics-bearer-token"].value')"
   curl -sS -H "Authorization: Bearer $T" https://<api host>/metrics \
     | grep -E '^giano_(chain_available|paymaster_watcher_(lag_blocks|active)|tenant_balance_wei|paymaster_(invariant_breach|drifted_tenants|reconciliation_divergence_wei))'
   unset T
   ```

   Expected on every chain: `chain_available 1`, `watcher_active 1`, `invariant_breach 0`, `drifted_tenants 0`,
   `reconciliation_divergence_wei 0`, each tenant's balance as funded, and `watcher_lag_blocks` within a few
   blocks. A tenant appears in these metrics once it has a ledger row or a sponsorship rule on that chain.
2. **Watcher lag.** A fresh or restarted wallet-api replays its look-back first, and an environment that scales
   to 0 overnight starts each day behind; on a fast chain (Base Sepolia makes about 5 blocks a second) this takes
   over an hour. Wait for the lag to drop before step 12.
3. **Console.** Each tenant shows its balance on each chain, and the Roles tab shows the timelock holding
   `ROLE_ADMIN`, the upgrader, the fee admin and the withdraw-address admin, and the intended holder for each of
   the six immediate roles.

## 12. Smoke test

```sh
pnpm -F @appliedblockchain/giano-e2e smoke --target https://<tenant dApp> [--target https://<other tenant dApp>]
```

For each target, on each chain its dApp serves, it creates a passkey account, sends one sponsored transaction
(a mint of the default token, or 0 ETH to self where the dApp has none) and checks on chain that the account has
code, the transaction succeeded with the paymaster, and the account address is the same on every chain. It
prints the account and the hashes for each chain. It refuses a chain that is not a known testnet unless given
`--allow-production`, and a chain viem does not list unless it is left out with `--chain` or the flag is given.
Each run creates a user on the tenant and spends a little of its balance. See
[`e2e/README.md`](../e2e/README.md#smoke-test-of-a-deployed-environment).

Then check in the console that each tenant's balance went down by the sponsored amount.

## After the deployment

- **Keep a record** of the step results (addresses, transaction hashes, findings). This repository is public:
  commit public information only (addresses, hashes, explorer links, PRs, roles), and keep internal references
  (1Password items, chat threads, names) in a private place.
- **Revoke or keep** the tenant admin keys issued for step 10, deliberately.
- **Rolling a new version later** is an `infra/versions.json` PR (step 7.3), followed by a full apply from a
  checkout that includes it (step 7.4) when Terraform inputs changed, and the smoke test (step 12).
- **Upgrading the paymaster** goes through the timelock:
  `deploy:cli upgrade --rpc <keyed RPC URL> --contract paymaster --timelock <address>` builds the proposal
  ([timelock runbook](PAYMASTER-TIMELOCK-RUNBOOK.md) §3).
