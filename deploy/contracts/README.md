# Configurable contract deployment and address cutover

Reviewed against main `73059bf` (27 October 2026): [#130](https://github.com/appliedblockchain/giano/pull/130)
ports TypeScript; [#132](https://github.com/appliedblockchain/giano/pull/132) replaces Hardhat/Ignition
with Foundry and permissioned CREATE3 through CreateX; #133–135 finish the toolchain migration;
#157 publishes the breaking contracts package as 4.0.0 and #159 updates service dependencies.
The address break comes from #132, not from the TypeScript compiler itself.

**Public deployment is blocked today:** `packages/contracts/deploy/config.ts` has no `mainnet` or
`testnet` canonical deployer yet (`DEPLOYERS`, both `null`). The tooling plans but refuses to sign
for a class whose deployer is not set. `addresses.ts` has no public deployment records yet. Old
examples can still contain legacy addresses.

## Start here

From the repository root:

```sh
# Node 24+; use the pnpm version pinned by package.json.
corepack enable
corepack pnpm install --frozen-lockfile
pnpm contracts:deploy
```

The wizard loads a persisted chain profile, then asks for missing public operator inputs and the
release to deploy. It can save the public ROLE_ADMIN and release back to that profile for the next
run. Runtime RPC overrides and keys are never saved. `--plan` never changes a profile or signs.
It prints the release, the network class, the address plan (per contract: the expected
deterministic address, the address this run will use, the code found there and any deviation) and
the fee parameters, checks requirements, explains failures, and requires `deploy <network> <release>`
before signing. On a mainnet profile with any deviation it first prints a warning and requires
`deviate <profile>` (see [the mainnet guard](#the-mainnet-guard)). Cancelling sends nothing. No key is
requested in a prompt, printed, or saved. Before execution, load the canonical deployer key for the
profile's class from its 1Password item (`docs/key-ceremony.md`) into `CANONICAL_DEPLOYER_PRIVATE_KEY`
in the deploying shell only: never into a file in the repository, a dotenv file or a client's
configuration. A testnet run takes the testnet deployer's key, never the mainnet one.
`DEPLOYER_PRIVATE_KEY` remains the **operator** key used by provisioning; these are separate accounts.

For a read-only preflight, no deployment key is required:

```sh
pnpm contracts:deploy --plan --chain base-sepolia --release v2 --role-admin "$PAYMASTER_ROLE_ADMIN"
pnpm contracts:deploy --plan --chain ethereum-sepolia --release v2 --role-admin "$PAYMASTER_ROLE_ADMIN"
```

Set `PAYMASTER_ROLE_ADMIN` to the intended operator address first. Use `DEPLOY_RPC_URL` for a keyed
endpoint without putting its credentials in shell arguments. Without it, plans use the public
network default. RPC identity must match the selected network; failures suppress provider error
bodies because they may contain credentials. Noninteractive runs only print a plan and never sign;
a plan for a class whose deployer is not configured, or a mainnet plan with a deviation, exits
nonzero.
The checked-in bootstrap script (`bash deploy/contracts/run.sh deploy`) also explains missing Node,
pnpm or installed dependencies before loading TypeScript. Use it if pnpm itself is unavailable.
No Foundry installation or Solidity compilation is needed to deploy the committed release.

| Target | Chain ID | Default RPC | Explorer |
| --- | --- | --- | --- |
| Base Sepolia | 84532 | `https://sepolia.base.org` | https://sepolia.basescan.org |
| Ethereum Sepolia | 11155111 | `https://ethereum-sepolia-rpc.publicnode.com` | https://sepolia.etherscan.io |

Network references: [Base network settings](https://docs.base.org/get-started/connect-to-base),
[Sepolia client configuration](https://github.com/eth-clients/sepolia).
Fund the correct network separately; Ethereum Sepolia ETH is not Base Sepolia ETH.
Use [Base's funding instructions](https://docs.base.org/get-started/get-funds) and
[Ethereum's testnet resources](https://ethereum.org/en/developers/docs/networks/).
Public RPCs are defaults, not availability guarantees; prefer a reliable provider during deployment.

## Persisted profiles and generic commands

Network-specific data lives in `deploy/chains/base-sepolia.json` and
`deploy/chains/ethereum-sepolia.json`, not in executable scripts. The tool discovers profiles from
that directory. Add another chain by adding JSON with the same validated shape, or select an
external profile with `--config <file>`. No new TypeScript branch or shell wrapper is needed.

A profile persists chain ID/name, its **network class** (`"network": "mainnet"` or `"testnet"`), a
public RPC fallback and its credential environment-variable name, committed release, public
ROLE_ADMIN, minimum deployer balance, paymaster fee parameters and, optionally, **address
overrides**. The class selects the canonical deployer, so every chain of a class shares one set of
deterministic addresses. An override names a contract that already exists on this chain at another
address:

```json
"addresses": { "paymasterProxy": "0x…", "walletImplementation": "0x…" }
```

Overridable: `walletImplementation`, `factory`, `paymasterImplementation`, `paymasterProxy`,
`timelock`. An overridden contract is verified (its code must match a release's fingerprint, and
its immutables the chain's other addresses) and recorded, never deployed; contracts that depend on
it use it (the factory is built for an overridden wallet implementation, the proxy initialised with
an overridden paymaster implementation). An override with no code or foreign code stops the run
before signing. Every override is a deviation.
The shipped profiles leave ROLE_ADMIN unset until a custodian supplies it. Interactive deployment
can persist that address and the chosen release after showing the destination file. Review/commit
those public changes for reproducibility. For a private environment, use an ignored custom profile
such as `deploy/contracts/my-environment.local.json`. Do not put credential-bearing URLs in JSON;
set the referenced environment variable instead. Runtime `--rpc` overrides are deliberately ephemeral.
Unknown profile fields (including keys/passwords) are refused. `--plan` never writes configuration.

Operator-specific inputs are separate dotenv data, selected explicitly:

```sh
cp deploy/contracts/operator.env.example deploy/contracts/base-sepolia.local.env
pnpm contracts:deploy --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
pnpm contracts:funding --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
pnpm contracts:provision --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
pnpm contracts:sponsorship --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
pnpm contracts:doctor --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
```

All commands accept `--config <file>` in place of `--chain`. Operator commands support `--plan` to
verify the selected target without invoking their underlying workflow. Provisioning and policy
writes require exact-text confirmation; noninteractive writes are refused. Existing exported
variables take precedence over dotenv data. Conflicting CHAIN_ID/DEPLOY_CHAIN_ID inputs stop the
operation. The selected profile's RPC environment reference takes precedence over DEPLOY_RPC_URL,
then the public profile fallback is used. No command executes a shell sourced from a profile or
operator dotenv file. No secret values are added to deployment records or generated address fragments.

Use `contracts:provision` for the EOA-admin bootstrap topology, then `contracts:timelock` and
`contracts:handoff` to move the timelocked roles (ROLE_ADMIN, upgrader, fee admin, withdraw-address
admin) to the profile's `GianoTimelock` (G9; see [the timelock runbook](../../docs/PAYMASTER-TIMELOCK-RUNBOOK.md)).
The profile's `timelock` section publishes the proposer Safe and one delay per timelocked function;
`contracts:doctor` then asserts both. Provisioning reruns add tenant funding again. `contracts:sponsorship` installs the demo
policy for the configured tenant through the real API; use the admin console/API for other policies.
The same chain-adoption/code gates apply to an added chain. A new profile is not proof of readiness.

## 1. Set the canonical deployers once

There are two canonical deployers, one per network class, each an independent EOA whose key the
development team creates and keeps in 1Password, outside ABIP-8 scope
([`docs/key-ceremony.md`](../../docs/key-ceremony.md) names the items). Never use a local anvil key,
and never derive the two from one seed. Set each **address only** in
`packages/contracts/deploy/config.ts` (`DEPLOYERS.testnet`, `DEPLOYERS.mainnet`) in a PR that names
the 1Password item; the tooling refuses equal addresses. All chains of a class get the same
deterministic addresses, so a passkey's wallet address is the same across them; testnet and mainnet
addresses differ by design.

Setting a deployer touches no generated file: local chains always use the fixed local deployer, so
the devnet state, `e2e/devnet/addresses.json` and CI stay as they are. `pnpm -F
@appliedblockchain/giano-contracts deploy:cli addresses` prints each class's deterministic addresses,
and the Determinism workflow checks them for every configured class.

The current signing adapter accepts an environment key, not a direct KMS/HSM signer. Freeze a git
commit and pin **contract release `v2`** in both testnet profiles (already set). This release
identifier is separate from the npm version. Do not recut or edit a release; changed Solidity
requires a new committed release.

## 2. Prepare each network

Start with **Base Sepolia**, validate it end to end, then repeat on **Ethereum Sepolia** with the
same release, deployer and admin. Keep the old service configuration intact until cutover.

Provide the public ROLE_ADMIN address and the class's canonical deployer key (from its 1Password item,
in the shell environment only); the operator, sponsorship signer,
executor, and existing tenant UUIDs will be needed for the later provisioning stage. Use separate
local environment files per network (for example `deploy/contracts/base-sepolia.local.env` and
`ethereum-sepolia.local.env`, gitignored). Never put keys in committed examples.

The wizard gates signing on:

- Validated profile with explicit chain identity and a matching RPC `eth_chainId`; no implicit chain default.
- A configured canonical deployer for the profile's class. A signing key other than it is not
  refused but is a deviation: it deploys at its own CREATE3 addresses, never the class's.
- Committed release, with release fingerprints for all four core contracts.
- CreateX at `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`, with the
  [upstream runtime hash](https://github.com/pcaversaccio/createx#security-considerations).
- Canonical EntryPoint v0.9 runtime, including its SenderCreator immutable, at
  `0x433709009B8330FDa32311DF1C2AFA402eD8D009`.
- Every planned address either empty or containing the selected release's code (an override may
  hold any release's). An existing factory must clone the planned wallet implementation; an existing
  proxy's implementation slot, ROLE_ADMIN membership, EntryPoint and fee parameters must match. An
  upgraded proxy or unexpected bytecode stops adoption.
- The configured gas reserve (**0.05 test ETH** in both shipped profiles) on the signing key when a
  contract is missing. This is a conservative reserve, not an exact cost estimate. Check gas conditions and maintain headroom,
  including Base's L1 data fee. A fully deployed rerun needs no deployment balance.

### The mainnet guard

For a `"network": "mainnet"` profile the wizard expects the mainnet canonical deployer's key and the
deterministic addresses for every contract. A **deviation** is any of: an address override; a signing
key that is not the mainnet canonical deployer (every contract it would deploy deviates); a contract
the chain's record already lists away from its deterministic address. With any deviation the wizard:

1. prints a warning block that names each deviation with its expected and actual address (and the
   signer beside the canonical deployer), and states that this chain's addresses will differ from the
   other mainnets permanently;
2. requires typing `deviate <profile>` (the profile's file name), before the usual
   `deploy <chainId> <release>` confirmation;
3. records every confirmed deviation, with its reason and time, in `deployments/<chainId>.json`.

Non-interactive runs refuse a deviating mainnet deployment and list the deviations. The low-level
`deploy:cli core` has no prompt, so it always refuses a deviating mainnet deployment; use the wizard.
On every non-local chain the paymaster `ROLE_ADMIN` must not be a deployer key (the signer or a class
deployer).
Testnet deviations are shown in the plan and recorded; the usual confirmation is the only gate.

Missing public-chain prerequisites require investigation or the upstream deployment procedure;
never use anvil impersonation, `setCode`, or local installation commands on either network.
Neither network receives PrivateERC20 or PermissivePaymaster: both are in the repository's R-29
protected list despite being testnets. Every chain whose profile declares `mainnet` is protected too. Production GianoPaymaster provides sponsorship.

## 3. Deploy and verify core contracts

```sh
pnpm contracts:deploy --chain base-sepolia --release v2
# After Base is validated, use --chain ethereum-sepolia --release v2.
```

The four core addresses are wallet implementation, factory, paymaster implementation and paymaster
proxy. CreateX initializes the proxy atomically. The wizard rechecks requirements (and that the
deviations are unchanged) after confirmation, and checkpoints
`packages/contracts/deployments/<chainId>.json` after each completed contract. After deployment it
checks every contract's code against the release fingerprints and the factory/proxy configuration
again, then runs `gen:addresses`. The record holds the network class, the signer and, per contract,
its expected address and whether it is deterministic, plus every deviation.

Review and commit the chain record and regenerated `packages/contracts/addresses.ts`. The wizard also
writes a gitignored, **public-address-only** `deploy/contracts/<chainId>.addresses.env`, including blank
legacy fixture overrides. Source this **after** loading your network environment to use its addresses
with provisioning tools. It never overwrites `deploy/.env` or changes serving configuration.
`deploy/sepolia` has been removed. Shared funding/provisioning/policy tools use the same selected
profile and an explicit operator dotenv file; they never load an implicit `deploy/.env`. The generic
external-chain demo is documented in [DEMO.md](DEMO.md).

## 4. Provision sponsorship and pass the adoption gate

Core deployment is not permission to serve traffic. For each chain, the operator must:

1. Fund the operator for stake, tenant balances and gas (budget at least 0.1 ETH stake plus tenant
   funding and fees), and the bundler executor for bundle gas (0.05 ETH is an initial reserve).
2. Grant the intended roles, register the sponsorship signer, stake the paymaster, register the
   **existing database tenant UUIDs**, and fund balances on the new paymaster. No balance migrates
   from the old proxy or across chains. Do not generate new tenant UUIDs.
3. Install/review each tenant's sponsorship rules for that chain through the admin API/console.
   Funding alone does not authorize sponsorship. Review any target allowlist for changed addresses.
4. Run doctor with explicit new addresses, expected admin, signer and executor; require all critical
   checks green, including P-256 verification, stake, deposit, tenant balances and role topology.

For an EOA-admin testnet, use the existing provisioning command after exporting the **operator's**
`DEPLOYER_PRIVATE_KEY` and the selected network's `RPC_URL` (not just DEPLOY_RPC_URL). Provide the
sponsorship signer's **public** address and real tenant IDs/withdrawal destinations:

```sh
set -a
. deploy/contracts/84532.addresses.env   # use 11155111 for Ethereum Sepolia
set +a
pnpm -F @appliedblockchain/giano-contracts provision:paymaster -- \
  --paymaster "$SPONSORSHIP_PAYMASTER_ADDRESS" \
  --signer "$SPONSORSHIP_SIGNER_ADDRESS" \
  --grant-all-to "$PAYMASTER_ROLE_ADMIN" \
  --stake-eth 0.1 --unstake-delay 86400 \
  --tenant "$TENANT_ID:$TENANT_WITHDRAW_ADDRESS:$TENANT_SLUG:0.05"
# Repeat --tenant for every tenant that will sponsor here.
# --grant-all-to is the explicit development topology; use separate role holders otherwise.
pnpm -F @appliedblockchain/giano-contracts doctor -- chain \
  --rpc "$RPC_URL" --chain-id "$CHAIN_ID" \
  --factory "$FACTORY_ADDRESS" \
  --sponsorship-paymaster "$SPONSORSHIP_PAYMASTER_ADDRESS" \
  --require-paymaster --role-admin "$PAYMASTER_ROLE_ADMIN" \
  --signers "$SPONSORSHIP_SIGNER_ADDRESS" --executor "$EXECUTOR_ADDRESS" \
  --tenants "$TENANT_ID"
```

Read [the external-chain demo guide](DEMO.md) for
multi-tenant details. The shared operator commands load `--env-file` explicitly, validate the selected RPC identity and
require interactive confirmation before provisioning transactions or sponsorship-policy writes. The core wizard's
public address fragment is not a replacement for provisioning credentials or tenant configuration.
Provisioning runs while the operator EOA still holds ROLE_ADMIN. Hand the timelocked roles to the
timelock afterwards (`pnpm contracts:timelock`, then `pnpm contracts:handoff`); from then on fee,
withdrawal-address, role and upgrade changes are timelock proposals signed by the Safe
([runbook](../../docs/PAYMASTER-TIMELOCK-RUNBOOK.md)).

## 5. Cut over services and clients together

The release operator owns this gate. Snapshot the current chain document, service/image versions,
address overrides, tenant policies and wallet/account inventory before changing anything. Announce a
testnet maintenance window; finish or drain in-flight operations and pause new sponsorship requests.
Existing CREATE2 accounts remain at their old addresses. They are not moved by CREATE3 deployment,
and existing passkeys can derive different accounts under the new factory. Explicitly choose between
an announced testnet reset and an account/asset migration coordinated with users; never silently
reinterpret old database addresses as newly deployed wallets. Transfer/recover old test assets before
retiring the legacy path where needed. Do not duplicate the same chain ID as two GIANO_CHAINS entries.

After both records ship in the contracts package's address registry, build/release the
dependent services and clients from the same tested revision. For the actual deployment update:

- The shared `chains` secret consumed as `GIANO_CHAINS` by wallet-api, bundler and paymaster-admin:
  each chain's `sponsorshipPaymaster`, `walletApi.policy.allowedPaymasters`, and any explicit
  `factory` or other address overrides must refer to the new addresses. Keep RPC credentials in
  that backend document; the frontend document contains public descriptors only.
- Any single-chain/local overrides: `FACTORY_ADDRESS`, `SPONSORSHIP_PAYMASTER_ADDRESS`,
  `USEROP_ALLOWED_PAYMASTERS`; clear `TEST_PAYMASTER_ADDRESS` and `TEST_ERC20_ADDRESS`.
- Infrastructure explicit inputs, including `infra/iac/ecs_services.tf`'s faucet `factory_address`
  and `ecs_tasks_oneshot.tf`'s `paymaster_address`; old values in
  `deploy/infrastructure.aws.env.example` are legacy examples, not evidence of the new deployment.
- Operator console, dApp/client package versions, sponsorship rules and stored account assumptions.
  Registry fallback is only available after the new deployment records have shipped.

Roll the backend/clients in the maintenance window. `GET /v1/version` must list both chains ready.
On **each** chain test account creation/passkey signing and a sponsored transaction with a real tenant;
record transaction hashes, explorer links and the new account addresses. Verify sponsorship accounting,
executor reimbursement and chain readiness/watcher metrics before reopening traffic.
[The chain-adoption checklist](../../specs/CHAIN-ADOPTION.md) remains the full readiness gate.

## Recovery and evidence

If a receipt times out, stop and inspect the transaction/nonce on the selected explorer before retrying.
Rerun the same profile, release, signing key and admin: existing code is checked, completed checkpoints
retain their transaction hashes, and missing contracts resume. A crash between mining and checkpointing
can leave a recovered record without that transaction hash; recover it from the explorer for the rollout
evidence. Do not run competing deployers, change salts, edit release bytecode, or delete a mismatching
record to force progress. Local filesystem checkpoints are not a substitute for on-chain receipts.

If cutover fails, keep sponsorship paused and restore the complete previous service/configuration
snapshot only if that previous stack is still serviceable. Core CREATE3 contracts cannot be rolled back
or overwritten. Do not serve old contracts with binaries that verify the new registry. Wallets or funds
already created under the new factory remain there; do not discard their records during rollback.

For each network retain: frozen git SHA, release version/compiler verification, deployer/admin public
addresses, chain ID, preflight output, deployment record/receipts, doctor output, provisioned tenant IDs,
configuration/version diff, sponsored smoke transaction and rollback snapshot reference. Keep secrets
out of this evidence.

## Read-only public-network evidence

On 27 October 2026, the new preflight reached both default public RPCs and confirmed the expected
chain IDs, pinned CreateX runtime and canonical EntryPoint v0.9 runtime on **both networks**. The
four provisional target addresses were empty on each chain. Both plans correctly exited nonzero
because the deployer was still the placeholder. (Since per-class deployers, a plan exits nonzero
because the testnet canonical deployer is not configured.) The admin supplied to these checks was an illustrative
public address, not an operational choice. No key was used and no public transaction was sent.
Recheck after the real deployer is configured; those will be different target addresses.

## Tooling gaps and disposition

| Gap found | Work in this PR / remaining closure |
| --- | --- |
| No canonical deployer configured for either class | Wizard prints the plan and reports the blocker before signing. The development team creates the testnet and mainnet keys in 1Password and sets their addresses; no artifact or devnet regeneration follows. |
| One deployer for every chain; addresses fixed as package constants | Per-class deployers, per-chain overrides, deviations recorded; code verified by release fingerprint wherever it sits; mainnet deviations need a typed confirmation. |
| Noninteractive shell deployment trusted CHAIN_ID separately from RPC | Profile-driven wizard verifies RPC identity; shared commands use the selected profile and reject conflicting environment chain IDs. |
| No guided checklist/address preview or secret-safe plan | Root `pnpm contracts:deploy`, validated JSON profiles, saved public choices, bootstrap checks, prompts, aggregated actionable checks, read-only plans, exact-text confirmation and per-chain public address output. |
| Existing code accepted without matching selected release; proxy runtime hides state | Wizard verifies release fingerprints, EntryPoint/CreateX code, factory linkage, implementation slot and initialization parameters before signing and after deployment. Low-level `deploy:cli` remains an expert primitive; use the wizard for these testnets. |
| Partial core runs saved only after all four contracts | Optional per-contract persistence hook plus interrupted-run/retry regression tests. |
| Stale public registry and legacy environment addresses | Generate registry after verification; explicit coordinated package/configuration cutover above. Actual records must come from actual deployments, not invented addresses. |
| Provisioning and policy setup are separate operator tools | Shared `contracts:funding`, `contracts:provision`, `contracts:sponsorship` and `contracts:doctor` launchers use the same profiles and explicit operator dotenv files. Tenant credentials and policies remain environment/operator inputs. The timelock is deployed and handed the timelocked roles by `contracts:timelock` / `contracts:handoff` from the profile (G9). |
| Direct KMS/HSM signing and exact Base-inclusive gas quote absent | Environment-key adapter and conservative reserve only; custody adapter required if key export is prohibited. No promise that the reserve equals transaction cost. |
| Explorer source publication absent | Release standard-input.json supports reproducible compilation; explorer upload/verification is still an operator task. Runtime verification is automated. |
| Live migration and readiness not demonstrated | Custody, funding, actual deployments, configuration rollout and sponsored smoke tests require the real operator inputs; no public-chain transactions are sent by this development PR. |

Regression tests: `pnpm -F @appliedblockchain/giano-contracts test:deploy` (mock RPC, no credentials)
and `test:deploy:integration` (real v2 transactions on a throwaway local anvil, interrupted checkpoint
recovery, idempotent rerun, and a deployment with overridden contracts). CI runs both in their appropriate jobs.
