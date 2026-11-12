# Testnet and `dev` rollout checklist

The ordered steps that put release `v3` on Base Sepolia and Ethereum Sepolia, and move the `dev`
environment off its legacy contracts. Everything here was rehearsed on a fork of Base Sepolia
(`pnpm contracts:rehearse --platform`; evidence in
`openspec/changes/harden-contract-deployment/rehearsal-evidence.md`). **Nothing has been run against
a public chain yet.** This page is the plan for doing it.

Why `dev` needs it: `infra/versions.json` pins `dev` to `5ba71241`, from before the CREATE3 cutover
(#132). That deployment runs EntryPoint v0.7 and the legacy factory `0x26dCd293…`. Current `main`
cannot be rolled out to it, because wallet-api refuses to start when the registry has no entry for a
chain it serves and the contracts there are not release code for EntryPoint v0.9.

## Decisions needed first

| Decision | Who | Notes |
|---|---|---|
| Reset `dev`, or migrate its legacy v0.7 accounts | tech lead | README §5. A reset is the usual testnet answer: announce it, withdraw the legacy paymaster's tenant balances and stake, and let existing test wallets go. A migration needs its own plan; no tool exists for it. |
| The testnet timelock's proposer Safe and its signers | tech lead | The hand-off refuses an EOA proposer only on a mainnet, but the rehearsal of the Safe flow (runbook §6) needs a real Safe on Base Sepolia. |
| The holder of each immediate paymaster role on testnet | tech lead | One address per `ROLE_HOLDER_*`, or `PAYMASTER_GRANT_ALL_TO` for a developer-held testnet. |
| How wallet-api survives an RPC that caps `eth_getLogs` | tech lead | The paymaster watcher, which tells wallet-api each tenant's balance, asks for up to 9,000 blocks per `eth_getLogs` (5,000 on a cold start). `https://sepolia.base.org`, the Base Sepolia profile's public RPC, serves 200: the watcher ingests nothing, retries the same range forever, every tenant reads as unfunded, and every sponsorship is refused. Either require a `GIANO_CHAINS` RPC that serves 9,000-block `eth_getLogs` and check it at step 9 (no code change), or change the watcher to shrink its span when an RPC refuses it (a wallet-api PR). Until decided, step 9 must use such an RPC. Found by the rehearsal (N4). |
| Testnet timelock delays | product | The shipped profiles carry rehearsal delays (5 minutes to 1 hour). Keep them for testnet unless product decides otherwise. |

Before mainnet only, not before testnet: mainnet canonical deployer custody (`docs/key-ceremony.md`
now states its leak impact), production role holders and production timelock delays.

## Steps

| # | Step | Who | Done when |
|---|---|---|---|
| 1 | Create the **testnet canonical deployer**: an independent random key in its own 1Password item with restricted access. It fixes the testnet wallet address space for good, so treat it as long-lived. | development team | the 1Password item exists |
| 2 | PR: set `DEPLOYERS.testnet` in `packages/contracts/deploy/config.ts` to its address, and name the 1Password item in `docs/key-ceremony.md`. CI `check:determinism` then covers the testnet class. | development team | merged, CI green |
| 3 | Rehearse again against the real deployer address on a fork: `pnpm contracts:rehearse --chain base-sepolia --platform --fork-url <RPC serving 9,000-block eth_getLogs>`, then `--chain ethereum-sepolia`. Without `--fork-url` the fork reads history through the profile's public RPC, and on Base Sepolia the paymaster watcher then fails as in the RPC decision above. The stand-in deployer is still used, but the profiles, release and tooling are exactly what step 5 runs. | development team | every step ✓ |
| 4 | Fund on each chain: the testnet deployer (≥ 0.05 ETH, the profile's reserve), the bootstrap operator (0.1 ETH stake plus tenant funding plus gas) and the bundler executor (≥ 0.05 ETH). `pnpm contracts:funding --chain <profile> --env-file <operator-file>` prints the amounts. | development team / DevOps | balances confirmed |
| 5 | **Base Sepolia**, in order: `pnpm contracts:deploy --chain base-sepolia`, then `contracts:provision`, `contracts:timelock`, `contracts:handoff` and `contracts:doctor` (deploy/contracts/README.md §3–4, runbook §2). | development team | doctor green; record written |
| 6 | **Ethereum Sepolia**: repeat step 5 with `--chain ethereum-sepolia`, the same release, deployer and bootstrap admin. | development team | doctor green |
| 7 | Commit `packages/contracts/deployments/84532.json` and `11155111.json`, both profiles (with their timelock addresses) and the regenerated `addresses.ts`. Release `@appliedblockchain/giano-contracts`. | development team | package published |
| 8 | Install each tenant's sponsorship rules on each chain: `pnpm contracts:sponsorship` with `SPONSOR_ALLOWLIST` set to the tenant's contracts, or the console. An empty allowlist sponsors nothing, wallet management included, so each tenant needs at least one contract. | development team | rules read back |
| 9 | Update the `chains` secret (`GIANO_CHAINS`) and the Terraform address variables (drafts below). | DevOps | `terraform plan` reviewed |
| 10 | Bump `infra/versions.json` `dev` to the tested `main` SHA (a `deploy/dev-<sha>` PR) and roll. | DevOps | `GET /v1/version` lists both chains ready |
| 11 | Smoke test on each chain: create a passkey account, sign, send a sponsored transaction. Check that the operator console shows the tenant, its balance and the timelock (the fork rehearsal does not cover the console). Record the transaction hashes, explorer links and account addresses (README "Recovery and evidence"). | development team | evidence recorded |
| 12 | Retire the legacy deployment: withdraw the legacy paymaster's tenant balances (each tenant's withdrawal address) and its stake (stake admin, after the unstake delay). | DevOps / tenants | legacy deposit and stake at zero |
| 13 | Rehearse a timelocked paymaster upgrade on Base Sepolia with the real Safe (runbook §6). The tooling reconciles the executed upgrade into the record. | development team | doctor green after execution |

## Drafts to fill in at step 9

The real addresses come from the records written in steps 5 and 6, and are not known before them: CREATE3 places
them by the testnet deployer's address. The rehearsal's values are shown only to show the shape.

`GIANO_CHAINS` (the backend `chains` secret, one entry per chain; RPC URLs stay in the secret):

```json
{
  "chainId": 84532, "name": "Base Sepolia",
  "rpcUrl": "<keyed Base Sepolia RPC that serves 9,000-block eth_getLogs (see the decisions above)>",
  "entryPoint": "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
  "sponsorshipPaymaster": "<deployments/84532.json paymasterProxy>",
  "walletApi": {
    "factory": "<deployments/84532.json factory>",
    "policy": { "allowedPaymasters": ["<the same paymasterProxy>"] }
  }
}
```

Once the contracts package that carries both records is released, `factory` and `entryPoint` may be
left out and taken from the registry.

Terraform (`infra/iac/ecs_services.vars.tf`): `paymaster_address` defaults to the legacy
`0xf98b56de…0718`, and `factory_address` to the legacy `0x26dCd293…7050`. Both must become the new
addresses (the paymaster proxy and factory are at the same address on both testnets).

Rehearsal values, Base Sepolia fork, stand-in deployer, for shape only:

| Contract | Rehearsal address |
|---|---|
| wallet implementation | `0x3Fb76CdA4e3485d04B08cC329f994f51348b1B69` |
| factory | `0x59b265B1dF4aC0Ec2489b6F1d242F9059d030e6F` |
| paymaster proxy | `0x8d48fE9401Cbf5D435d56f533356cE31593Da60e` |
| paymaster implementation after the timelocked upgrade | `0x961a7D6d41e1f0c9259Ab1984A44b0b2B0545E87` (`giano.paymaster.impl@v3`) |

## Rollback

CREATE3 contracts cannot be removed. Until step 12, the legacy contracts stay funded, so rolling
back means restoring the previous `infra/versions.json` SHA and chains secret. Do step 12 only after
step 11 has passed on both chains.
