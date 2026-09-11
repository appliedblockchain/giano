# Giano demo on Sepolia (or any EVM chain)

A second local demo stack that runs the full Giano system against a **real chain** instead of a
local anvil devnet. It defaults to **Ethereum Sepolia** but is entirely env-driven — point it at
any EVM chain by changing the values in `deploy/.env`.

| | `docker-compose.e2e.yml` (existing) | `docker-compose.sepolia.yml` (this) |
| --- | --- | --- |
| Chain | local anvil, pre-baked state | real chain via external RPC |
| Contracts | baked into `state.json` | **you deploy them once** |
| Bundler | Alto + anvil dev key | Alto + **your funded executor** |
| Gas | free anvil ETH | **real testnet ETH** |

This stack sponsors through the production `GianoPaymaster`, the same way a real deployment does —
not through the permissive test paymaster. That paymaster is still deployed as a fixture, but
nothing in the stack points at it.

> **Adoption is a gate, not a formality.** Deploying Giano to a chain means passing
> [`specs/CHAIN-ADOPTION.md`](../../specs/CHAIN-ADOPTION.md). The scripts here implement that
> checklist and refuse to continue when a step fails — in particular, the contracts are deployed
> through Ignition's **create2** strategy and every produced address is asserted against the frozen
> constants in `packages/contracts/canonical.ts`. A deployment at the wrong addresses works
> perfectly right up to the point where a user's funds arrive at an address their passkey does not
> control, which is why divergence aborts rather than warns.

## What you need to fund ⚠️

Two EOAs need testnet ETH (throwaway keys you generate — never reuse real keys). A third key is
required but needs no funding:

| Account | Suggested | Why |
| --- | --- | --- |
| **Deployer** (`DEPLOYER_PRIVATE_KEY`) | ~0.15 ETH | Deploys the contracts, stakes the paymaster (`STAKE_ETH`), funds **each** tenant's sponsorship balance (`TENANT_FUND_ETH`, spent once per entry in `PAYMASTER_TENANTS`) and seeds the test paymaster's deposit (`PAYMASTER_FUND_ETH`). |
| **Alto executor** (`ALTO_EXECUTOR_PRIVATE_KEY`) | ~0.05 ETH | Signs and pays gas for every bundle on-chain. It's reimbursed from the paymaster deposit, but must front the ETH. |
| **Sponsorship signer** (`SPONSORSHIP_SIGNER_KEY`) | none | The key wallet-api signs ERC-7677 sponsorships with. It authorises spending against the tenant's paymaster balance; it never pays gas. |

The end user's passkey wallet pays nothing.

> No P256 verifier contract is needed. Sepolia provides the RIP-7212 precompile at `0x100`, so
> passkey signatures are verified by the precompile (cheap). On chains without it, `webauthn-sol`
> automatically falls back to the in-contract FreshCryptoLib path — so the demo works either way.

## Prerequisites

- Docker (Compose), Node/pnpm (repo already bootstrapped)
- An RPC endpoint. The keyless public default (`https://ethereum-sepolia-rpc.publicnode.com`) works
  for everything here, including the bundler: the stack runs Alto with `--safe-mode false`, which
  validates userops via `eth_call` simulation rather than `debug_traceCall`. Only if you enable
  Alto's safe mode do you need a trace-capable RPC (Alchemy/QuickNode/Infura free tier).
- Three throwaway private keys. Generate one with:
  ```sh
  pnpm --filter @appliedblockchain/giano-contracts exec node -e "console.log(require('ethers').Wallet.createRandom().privateKey)"
  ```
- On the target chain: **CreateX** at `0xba5Ed0…ba5Ed` and **EntryPoint v0.7** at
  `0x000000…a032`. Ethereum Sepolia has both. `giano-doctor chain` reports them, and
  `deploy-contracts.sh` refuses to run without CreateX.

## Steps

### 1. Configure

```sh
cp deploy/sepolia.env.example deploy/.env
```

`deploy/.env` is gitignored; `deploy/sepolia.env.example` is **not**, so never put a real key in
the example. The example has two independent halves — *A. contract deployment*, whose values are
aligned with the environment described in `infra/`, and *B. the local demo stack*.

Set at minimum:
- `DEPLOYER_PRIVATE_KEY` and `SPONSORSHIP_SIGNER_KEY` (half A — deployment and provisioning)
- `ALTO_EXECUTOR_PRIVATE_KEY`, `ALTO_UTILITY_PRIVATE_KEY` (half B — only to run the stack)
- (optional) `DEPLOY_RPC_URL` — the **only** RPC the deployment needs. Prefer a keyed endpoint:
  a dropped receipt mid-run is what corrupts the Ignition journal.
- (optional) `RPC_URL` — the local stack's serving RPC; the keyless publicnode default is fine
- (optional) `BUNDLER_NODE_RPC_URL` — leave blank to reuse `RPC_URL`; only needed if you enable
  Alto's safe mode (then point it at a `debug_traceCall`-capable RPC)

### 2. Check funding

```sh
./deploy/sepolia/print-funding.sh
```

Prints each key's address and current balance. Send Sepolia ETH from a faucet
(e.g. https://www.alchemy.com/faucets/ethereum-sepolia) until the deployer and executor are funded.

### 3. Deploy the contracts (one-time)

```sh
./deploy/sepolia/deploy-contracts.sh
```

Deploys, all through the create2 strategy:

| Module | Contracts |
| --- | --- |
| `GianoAccountFactory` | `GianoSmartWallet` (implementation) + `GianoSmartWalletFactory` |
| `GianoPaymaster` | the sponsorship paymaster — implementation, deployer and proxy |
| `Testing` | `PrivateERC20` (the demo token) + `PermissivePaymaster` (fixture) |

It then asserts all five canonical addresses and writes `FACTORY_ADDRESS`,
`SPONSORSHIP_PAYMASTER_ADDRESS`, `TEST_PAYMASTER_ADDRESS` and `TEST_ERC20_ADDRESS` back into
`deploy/.env`. Re-running is idempotent (Ignition resumes the existing deployment).

If it reports divergence, **stop**: do not serve the chain and do not register the addresses. The
cause is upstream — a missing CreateX, a non-canonical EntryPoint, or a contracts build that isn't
the frozen one.

### 4. Provision the paymaster (one-time)

```sh
./deploy/sepolia/provision-paymaster.sh
```

Grants the roles, registers the sponsorship signing key, stakes with the EntryPoint, registers
every tenant in `PAYMASTER_TENANTS` and funds each balance — then verifies all of it with
`giano-doctor chain`, which must exit green before you go on.

`PAYMASTER_TENANTS` defaults to the two tenants the development environment serves
(`infra/iac/_locals.tf`): `example` and `byoui`. Their UUIDs are **pinned** in
`deploy/sepolia.env.example`, and that is load-bearing — the paymaster keys each tenant's balance
on the 16 bytes of its UUID, so the database and the chain have to agree. `wallet-api` states the
consequence directly (`services/wallet-api/src/services/tenants.ts`): a tenant seeded without an
`id` gets a random one, and *"a random id would leave every sponsorship refused as unknown
tenant"*. The id is immutable once set; changing it orphans that tenant's on-chain balance.

> ⚠ The deployed environment does not pin them today.
> `deploy/docker-compose.infrastructure.aws.yml` seeds both tenants with no `id` field, so what
> this script registers on chain cannot be matched by that deployment until its `TENANTS_SEED`
> carries the same UUIDs. That is a change to the `tenants-seed` secret, not to anything here.

Every role lands on the deployer EOA. That is the development shape the e2e devnet uses too, not a
shortcut smuggled in: a production deployment routes every grant through the timelock, and
`giano-doctor chain --role-admin` is what asserts that.

### 5. Register the chain (optional, but do it if the chain is here to stay)

```sh
pnpm --filter @appliedblockchain/giano-contracts gen:addresses
```

Commit `packages/contracts/ignition/deployments/chain-<id>/` together with the regenerated
`addresses.ts`. `gen:addresses` fails on divergence from the canonical freeze, so this is the same
gate as step 3 — expressed as a committed artefact rather than a one-off run. Once registered, the
chain's addresses default correctly everywhere and `FACTORY_ADDRESS` no longer has to be passed by
hand.

### 6. Bring up the stack

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.sepolia.yml up --build
```

| Service | URL |
| --- | --- |
| bundler (alto) | http://localhost:4337 |
| wallet-web | http://wallet.localhost:8081 |
| wallet-api | internal (via wallet-web `/api` proxy) |

### 7. Install the tenant's sponsorship rules

```sh
./deploy/sepolia/provision-sponsorship.sh
```

**Required.** Step 4 made the money available; this decides that any of it may be spent. A tenant
with no sponsorship configuration gets no sponsorship — so skipping this gives you a stack that
comes up healthy and refuses every sponsored transaction, with nothing on screen to say why.

Rules go in the way a tenant would put them in, through `PUT /v1/admin/sponsorship` with the
tenant's own admin key, and the script reads back what it wrote.

### 8. Run the sample dApp

The dApp fixture bakes `CHAIN_ID`/`RPC_URL` in at build time, defaulting to the anvil devnet
(`31337` / `localhost:8545`). For Sepolia you MUST pass the matching env, or the dApp's read/tx
path points at the wrong chain:

```sh
WALLET_URL=http://wallet.localhost:8081 \
CHAIN_ID=11155111 \
RPC_URL=https://ethereum-sepolia-rpc.publicnode.com \
pnpm --filter @appliedblockchain/giano-e2e dapp   # http://app.localhost:4400
```

Open **http://app.localhost:4400**, create a passkey wallet, connect, and send a sponsored
transaction. It lands on Sepolia — check the tx on https://sepolia.etherscan.io.

Tear down: `docker compose --env-file deploy/.env -f deploy/docker-compose.sepolia.yml down`

## Using a different EVM chain

Set `CHAIN_ID` (and `DEPLOY_CHAIN_ID`) and `RPC_URL` in `deploy/.env`, then rerun steps 2–8
(`BUNDLER_NODE_RPC_URL` only if that chain's public RPC won't serve the bundler). The deploy script
auto-uses hardhat's `custom` network for non-Sepolia chains.

Two chain prerequisites are absolute, and both fail silently if skipped — see
[`specs/CHAIN-ADOPTION.md`](../../specs/CHAIN-ADOPTION.md) steps 1 and 2. CreateX must be present
(the deploy script checks). EntryPoint v0.7 must be at its canonical address: the account
implementation hardcodes it, so a chain carrying a different EntryPoint produces different bytecode
and different addresses for everything downstream. A private chain will not have either, and both
must be deployed before any Giano contract.

## Restricting sponsorship

Sponsorship is already restricted twice over, and neither layer is optional:

- `USEROP_ALLOWED_PAYMASTERS` defaults to the deployed sponsorship paymaster, so wallet-api relays
  only ops sponsored by it.
- The tenant's own rules (step 7) allowlist contracts and selectors and cap the cost per
  transaction. `provision-sponsorship.sh` installs a deliberately generous demo config — the demo
  ERC-20 in full, a 0.5 ETH cap. Narrow it through the same endpoint.

Sponsorship rules are per `(tenant, chain)` and are never inherited from another chain.
