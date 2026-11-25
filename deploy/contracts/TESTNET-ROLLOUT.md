# Testnet and `dev` rollout checklist

The ordered steps that put release `v3` on Base Sepolia and Ethereum Sepolia, and move the `dev`
environment off its legacy contracts. Everything here was rehearsed on a fork of Base Sepolia
(`pnpm contracts:rehearse --platform`; evidence in
`openspec/changes/archive/2026-11-16-harden-contract-deployment/rehearsal-evidence.md`). **Steps 1–11 are
done:** release v3 is live on both testnets and handed to the timelock (2026-11-17), `dev` was cut over to it
(2026-11-19), its sponsorship rules are installed and the smoke test passed on both chains (2026-11-23). Steps
12 and 13 are deferred (Notion ticket G46). The rest of this page records how the cut-over ran, for the next one;
[`TESTNET-ROLLOUT-RECORD.md`](TESTNET-ROLLOUT-RECORD.md) has the results and findings.

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
| 8 | **Token deployed (2026-11-18); sponsorship rules installed (2026-11-23).** at `0x461E0641a3615336b7D2E4C5D71fB2BB88038C93` on both chains; its records are in the registry. Deploy the test ERC-20 on each chain (D5), from the canonical deployer only and without an operator file loaded: `DEPLOYER_PRIVATE_KEY=<testnet canonical deployer> node --import tsx deploy/cli.ts test-token --rpc <url> --chain <profile> --holder <admin>` (in `packages/contracts`). It lands at the same address on both chains, with the profile's release. **Then publish it like step 7:** commit the `testErc20` entry of both records and the regenerated `addresses.ts`, with a changeset, and release `@appliedblockchain/giano-contracts` again; step 7's release went out without the token. Then install each tenant's sponsorship rules on each chain: `pnpm contracts:sponsorship` with `SPONSOR_ALLOWLIST` set to the tenant's contracts, or the console. An empty allowlist sponsors nothing, wallet management included, so each tenant needs at least one contract. **Allow-listing the test ERC-20 lets anyone spend that tenant's balance:** anyone may `mint`, so any wallet can send sponsored mints until the balance runs out. That is the point for `dev`'s demo tenants (D5, testnet funds only); never allow-list it for a tenant whose balance matters | development team | package published; rules read back |
| 9 | **Done (2026-11-19).** Update the `chains` secret (`GIANO_CHAINS`) and the Terraform address variables: see **Cut-over runbook** below, which orders steps 9 and 10 with the user-data reset (D1). | DevOps | `terraform plan` reviewed |
| 10 | **Done (2026-11-19, #314).** Bump `infra/versions.json` `dev` to the tested `main` SHA (a `deploy/dev-<sha>` PR) and roll. | DevOps | `GET /v1/version` lists both chains ready, and `giano_paymaster_watcher_lag_blocks` (wallet-api `/metrics`) is within a few blocks on both chains. On a fresh database the watcher replays 5,000 blocks at 200 a pass, so for a few minutes every tenant reads as unfunded and sponsorship is refused; don't start step 11 before the lag drops |
| 11 | **Done (2026-11-23)** with `pnpm -F @appliedblockchain/giano-e2e smoke --target <dApp URL>` (#328). Smoke test on each chain: create a passkey account, sign, send a sponsored transaction. Check that the operator console shows the tenant, its balance and the timelock (the fork rehearsal does not cover the console). Record the transaction hashes, explorer links and account addresses (README "Recovery and evidence"). | development team | evidence recorded |
| 12 | **Deferred (G46).** Retire the legacy deployment: withdraw the legacy paymaster's tenant balances (each tenant's withdrawal address) and its stake (stake admin, after the unstake delay). | DevOps / tenants | legacy deposit and stake at zero |
| 13 | **Deferred (G46).** Rehearse a timelocked paymaster upgrade on Base Sepolia, queued by the testnet admin key as proposer (runbook §6 with an EOA instead of a Safe; a Safe rehearsal waits for a production-like proposer). The tooling reconciles the executed upgrade into the record. | development team | doctor green after execution. Its warning that the proposer "is a key … not a Safe" is expected on testnet (D2) |

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

Why this order:
- ECS tasks read the `chains` secret when they start, and wallet-api refuses a chain whose configured factory
  does not run release code. A new image with the legacy secret, or the legacy image with the new secret,
  does not serve. So the secret changes in Secrets Manager first, without a restart.
- The user data is reset with wallet-api stopped, before wallet-api starts on the new release. A running v3
  watcher would otherwise reconcile against the legacy paymaster's stored slack and raise the
  drawdown-divergence alert, the signal for a leaked signing key; a running legacy watcher would rewrite its
  cache straight after the reset.
- The reset runs after the deploy PR is merged, not before. The reset task starts from the current wallet-api
  task definition, and the image that definition pins can be gone: ECR keeps about 20 `main` commits of
  images per repository (`specs/INFRASTRUCTURE.md` R27), and on 2026-11-19 `wallet-api:5ba71241` had expired
  (tracker F19). Merging the deploy PR first registers task definitions on the new image. The reset task
  then runs the new image's `init` container, which applies the migrations, before the reset itself; every
  table the reset touches exists in both schemas.
- Terraform reads each service's image tag from `infra/versions.json` (`infra/iac/_locals.tf`), not from what
  `deploy.yml` rolled. So the full `terraform apply` runs from a checkout that includes the merged deploy
  PR. On 2026-11-19 an apply from an older checkout asked for the expired `5ba71241` image, every new task
  failed to start, and the deployment circuit breaker rolled each service back (tracker F21).
- wallet-api's image has no shell and no `psql` (a DHI runtime image), and only the tasks security group
  reaches the database. [`dev-db-run.sh`](dev-db-run.sh) runs a SQL file in a one-off task of the wallet-api
  task definition, through node and the `pg` driver, on the `RUN_TASK_NETWORK` subnets. It works with the
  wallet-api service at 0 and needs no hand-made connection string.

**Before the switch** (nothing changes for users yet):

1. **Pick the window**: a weekday between 07:00 and 19:00 UTC. `dev`'s scheduler scales every service to 0 at
   19:00 and back at 07:00 (`infra/iac/scheduler.tf`).
2. **Rollback inputs**: note the `infra/versions.json` `dev` SHA (`5ba71241`) and take a manual RDS snapshot
   of `dev`'s database (a last resort only: the reset keeps its own backup, see "If it fails"). 1Password
   keeps the previous `secrets-dev` note in the item's history. Check that the noted SHA's images are still
   in ECR, in each of the six repositories:

   ```sh
   for repo in wallet-api wallet-web paymaster-admin example wallet-byo bundler; do
     aws ecr describe-images --region eu-west-2 --repository-name "giano-dev/$repo" \
       --image-ids imageTag=<sha> --query 'imageDetails[0].imageTags' --output text || echo "missing: $repo"
   done
   ```

   If any has expired, rolling back to that SHA is not possible without rebuilding its images. For the
   2026-11-19 cut-over it was never possible: `5ba71241` had already expired (tracker F19).
3. **Merge the infrastructure PR**: `paymaster_address` and `factory_address` default to the v3 proxy and
   factory, and `test_erc20_address` gives `dev`'s reference dApps their `defaultToken` (blank in stg and
   prd). Merging applies nothing.
4. **Open the deploy PR** `deploy/dev-<sha>`: `infra/versions.json` `dev` set to the tested `main` SHA
   (7.1.0 or later). Do not merge it yet.

**The switch** (a short window; `dev`'s users re-register anyway):

5. **Point the `chains` secret at v3.** Its source of truth is the `notesPlain` of the 1Password item
   `secrets-dev` (vault "Giano dev/stg"): a JSON bundle `{ "<name>": { "value": "<string>", "version": n } }`,
   from which Terraform reads each secret's value and version (`infra/iac/asm.tf`). Never edit a separate
   field, and never paste the raw chain array: [`dev-v3-chains.mts`](dev-v3-chains.mts) rewrites the
   bundle for you. It sets both testnet entries to the v3 EntryPoint, paymaster, factory and allowed
   paymaster, adds the console's `paymasterAdmin.timelockAddress` and `timelockDelays`, keeps every other
   field (RPC URLs, policy limits, bundler and console settings), checks the result against the services'
   chain schemas, and bumps `chains.version`. Every value comes from the committed records and profiles.

   ```sh
   op item get secrets-dev --vault "Giano dev/stg" --format json \
     | jq -r '.fields[] | select(.id == "notesPlain") | .value' \
     | (cd packages/contracts && node --import tsx ../../deploy/contracts/dev-v3-chains.mts) | pbcopy
   ```

   It lists what changed on stderr (without RPC URLs). Paste the clipboard back into the note as-is, then
   mirror only that secret to Secrets Manager:
   `terraform apply -target='module.asm-app.aws_secretsmanager_secret_version.secret["chains"]'`. Running tasks
   keep the old value until they restart.
6. **Stop wallet-api**:
   `aws ecs update-service --cluster giano-dev-ecs --service giano-dev-wallet-api --desired-count 0`, then
   `aws ecs wait services-stable --cluster giano-dev-ecs --services giano-dev-wallet-api`.
7. **Roll**: merge the deploy PR. `deploy.yml` rolls every service to the new image and registers new task
   definitions; wallet-api stays at 0.
8. **Reset the user data** (D1, F8), once, on the new task definition:
   `deploy/contracts/dev-db-run.sh deploy/contracts/dev-v3-reset.sql` (infra/iac's `dev` workspace selected;
   it needs `aws`, `jq` and `terraform`). Its `init` container applies the migrations first. One transaction:
   it copies every row it clears into the schema `cutover_v3_backup`, then clears users, passkeys,
   challenges, sessions and their logs, the legacy paymaster's ledger and the watcher's cache. Tenants, their
   configuration and the platform admins stay. It prints the counts before and after; a second run fails and
   changes nothing.
9. **Start wallet-api and apply Terraform.**
   `aws ecs update-service --cluster giano-dev-ecs --service giano-dev-wallet-api --desired-count 1`. It
   starts with an empty watcher cache: the watcher cold-starts and its first reconcile reads every balance
   from the v3 paymaster. Then run the full `terraform apply` for the new variables (the reference dApps'
   `defaultToken`, wallet-byo's `FACTORY_ADDRESS`, the provisioning task's paymaster), **from a checkout that
   includes the merged deploy PR**: `git pull` on `main` first, and check that `infra/versions.json` shows the
   new `dev` SHA. It ignores `desired_count`, so it does not fight the scaling. The plan registers new task
   definitions; if it shows only services moving to an existing revision, a previous apply was rolled back,
   so find out why before applying again. Check that it took: both reference dApps' `/config.js` carry the
   `defaultToken`, and wallet-byo's `/main.js` contains the v3 factory.

**Readiness** (rollout step 10's "done when"):

10. `GET /v1/version` lists both chains ready; wallet-api's log shows both chains admitted with the v3 factory.
11. `giano_paymaster_watcher_lag_blocks` on wallet-api's `/metrics` is within a few blocks on both chains.
12. The operator console shows both tenants with 0.02 ETH on both chains, and the timelock
    `0x7Da25D415f9b68422F905C015137Af8D915F8A78` in its Timelock and Roles tabs.

Then rollout step 8's sponsorship rules (each tenant on each chain, the test ERC-20 allow-listed) and rollout
step 11's smoke test. When the cut-over is final, drop the backup: `DROP SCHEMA cutover_v3_backup CASCADE`.

**If it fails:**
- **Before step 7:** do not merge the deploy PR. Restore the previous `chains` value from the 1Password
  item's history with a higher `version` than the current one, apply it with the same `-target`, and scale
  wallet-api back to 1.
- **After step 7, or if step 8 failed:** the user data is untouched (the reset is one transaction, so a failed
  reset changes nothing), but the reset task's `init` container has already applied the v3 migrations. Put
  back the previous `versions.json` SHA (a new deploy PR) and `chains` value, then scale wallet-api to 1: the
  legacy image then starts on the v3 schema. Its migration runner does not refuse that schema (it skips
  applied files and ignores rows it does not know, `services/wallet-api/src/migrate.ts`), but the legacy code
  has not been tested against the added columns, so check its readiness. This needs that SHA's images in ECR
  (step 2).
- **After step 8:** scale wallet-api to 0, run `deploy/contracts/dev-db-run.sh
  deploy/contracts/dev-v3-restore.sql`, put back the previous `versions.json` SHA and `chains` value, then
  scale wallet-api to 1 (again only if that SHA's images are still in ECR). The restore clears what v3 wrote
  in the same tables (new users, and the v3 watcher's cache, which would make the legacy watcher skip events
  and report a false drawdown), then re-inserts the backed-up rows; columns are matched by name, so it works
  after the v3 migrations too. The RDS snapshot is the last resort: restoring it creates a new instance and
  loses everything written since.

For reference, a testnet entry as the script leaves it (`rpcUrl` and any other existing fields kept as they
are). The registry would supply `entryPoint`, `sponsorshipPaymaster` and the factory, but stating them lets
wallet-api check them against the chain at boot. With `dev`'s keyed QuickNode URLs no `bundler` section is
needed (measured: `eth_getLogs` served up to 10,000 blocks on both chains; the bundler's default is 2,000):

```json
{
  "chainId": 84532,
  "name": "Base Sepolia",
  "rpcUrl": "<dev's QuickNode Base Sepolia URL>",
  "entryPoint": "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
  "sponsorshipPaymaster": "0xb2C7081be89D88f1da020530Ebd5c14b8871615a",
  "walletApi": {
    "factory": "0xA9d72F088C0Cd0B78db44D4c79E847FddD52F635",
    "policy": { "allowedPaymasters": ["0xb2C7081be89D88f1da020530Ebd5c14b8871615a"] }
  },
  "paymasterAdmin": {
    "timelockAddress": "0x7Da25D415f9b68422F905C015137Af8D915F8A78",
    "timelockDelays": {
      "minDelay": 300, "upgradeToAndCall": 3600, "grantRole": 3600, "revokeRole": 3600,
      "renounceRole": 3600, "setTenantWithdrawAddress": 1800, "setDefaultFee": 1200, "setTenantFee": 600
    }
  }
}
```

The Ethereum Sepolia entry is the same with `"chainId": 11155111`, `"name": "Ethereum Sepolia"` and its own
`rpcUrl`.

## Adding iron-kestrel to dev

Adds Silent Data's iron-kestrel (19874) to `dev` next to the two testnets (openspec `silent-data-network`,
task 8.8). It is a new chain, so nothing is reset and the other chains keep working. DevOps runs steps 2 to
4; the development team runs the rest.

What changes:
- **The `chains` secret** gets a 19874 entry: the v3 addresses and timelock from the committed record,
  `rpcUrl` set to the public URL, `bundler.rpcUrl` set to the write URL with Silent Data's token, and
  `bundler.stateOverride: false`. wallet-api, the bundler and the console read it.
- **Terraform** (`var.silent_data_chains`, dev only) adds 19874 to the chain lists of wallet-web, the BYO
  wallet (`wallet-byo`) and both dApps. The dApps' entries carry `privateToken`, so each dApp shows its
  private token card.

Why this order: the image `dev` runs before 7.2.0 has no 19874 in its registry. So the new image rolls
first, with the secret unchanged, and the secret changes after it.

1. **Roll the new image**: merge the infrastructure PR (it applies nothing), then open and merge the deploy PR
   `deploy/dev-<sha>`, with a `main` SHA at release 7.2.0 or later. `GET /v1/version` still lists the two
   testnets ready.
2. **Add 19874 to the `chains` secret.** [`dev-iron-kestrel-chains.mts`](dev-iron-kestrel-chains.mts)
   rewrites the `secrets-dev` bundle, as `dev-v3-chains.mts` did in step 5 of the cut-over. It reads the
   write URL from `IRON_KESTREL_RPC_URL` and refuses the public URL. `read -s` keeps the URL out of the
   terminal and the shell history:

   ```sh
   read -rs IRON_KESTREL_RPC_URL && export IRON_KESTREL_RPC_URL
   op item get secrets-dev --vault "Giano dev/stg" --format json \
     | jq -r '.fields[] | select(.id == "notesPlain") | .value' \
     | (cd packages/contracts && node --import tsx ../../deploy/contracts/dev-iron-kestrel-chains.mts) | pbcopy
   ```

   Paste the clipboard back into the note as-is, then mirror only that secret:
   `terraform apply -target='module.asm-app.aws_secretsmanager_secret_version.secret["chains"]'`.
3. **Run the full `terraform apply`.** It changes the chain lists in the task definitions of wallet-web,
   wallet-byo and both dApps, so those four services restart.
4. **Restart the services that read the secret.** A new secret value does not change their task
   definitions, so they keep the old value until they restart:
   `aws ecs update-service --cluster giano-dev-ecs --service <service> --force-new-deployment` for
   `giano-dev-wallet-api`, `giano-dev-bundler` and `giano-dev-paymaster-admin`.
5. **Install the sponsorship rules on 19874 for each tenant, `example` and `byoui`.** The command calls
   `dev`'s wallet-api admin API, so it works only after step 4. Run it once per tenant, each with its own
   operator file: `pnpm contracts:sponsorship --chain iron-kestrel --env-file "$PWD/<file>"
   --accept-unverified-implementation`. The path must be absolute. Node itself reads `--env-file`, even after
   the script name, and resolves it from `packages/contracts`: with a path relative to the repository root
   it exits with "not found" before the script starts. The operator file sets `WALLET_API_URL` to
   `dev`'s wallet-api, the tenant's `TENANT_SLUG` and `ADMIN_API_KEY`, and `SPONSOR_ALLOWLIST` to the
   private test token `0xFA7B71b9A5397b8A4faCC9127BE1C665f2F2cA9b`. Anyone may mint that token, so the warning of step 8 in
   "Steps" applies: allow-list it only for a demo tenant.

**Readiness** (task 8.8's "done when"):

6. `GET /v1/version` lists 19874 ready, and the two testnets are still ready.
7. `giano_paymaster_watcher_lag_blocks` on wallet-api's `/metrics` is within a few blocks on 19874.
   `/metrics` needs a bearer token: the `metrics-bearer-token` value in the `secrets-dev` note of the
   "Giano dev/stg" vault. `read -s` keeps it out of the terminal and the shell history:

   ```sh
   read -rs TOKEN
   curl -s -H "Authorization: Bearer $TOKEN" \
     https://wallet.dev.giano.appliedblockchain.dev/api/metrics | grep watcher_lag
   unset TOKEN
   ```
8. Both dApps, `example` and `byoui`, show Iron Kestrel in their chain lists and the private token card on
   that chain. Then run the end-to-end check (task 9.2) on `example`, and one sponsored transaction on
   `byoui`, through the BYO wallet.

**Rollback**: restore the previous `secrets-dev` note from the 1Password item's history, apply it with the
same `-target`, and restart the three services of step 4. Then revert the infrastructure PR and run the full
`terraform apply`. The two testnets are not affected.

## Rollback

CREATE3 contracts cannot be removed. Until step 12, the legacy contracts stay funded, so rolling
back means restoring the previous `infra/versions.json` SHA and chains secret, and, once the user data
has been reset, `dev-v3-restore.sql` ("If it fails" in the Cut-over runbook). Do step 12 only after
step 11 has passed on both chains.
