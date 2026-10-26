# Giano demo on Sepolia (or any EVM chain)

A second local demo stack that runs the full Giano system against a **real chain** instead of a
local anvil devnet. It defaults to **Ethereum Sepolia** but is entirely env-driven — point it at
any EVM chain by changing the values in `deploy/.env`.

| | `docker-compose.e2e.yml` (existing) | `docker-compose.sepolia.yml` (this) |
| --- | --- | --- |
| Chain | local anvil, pre-baked state | real chain via external RPC |
| Contracts | baked into `state.json` | **you deploy them once** |
| Bundler | giano-bundler + anvil dev key | giano-bundler + **your funded executor** |
| Gas | free anvil ETH | **real testnet ETH** |

This stack sponsors through the production `GianoPaymaster`, the same way a real deployment does —
not through the permissive test paymaster. That paymaster is still deployed as a fixture, but
nothing in the stack points at it.

> **Adoption is a gate, not a formality.** Deploying Giano to a chain means passing
> [`specs/CHAIN-ADOPTION.md`](../../specs/CHAIN-ADOPTION.md). The scripts here implement that
> checklist and refuse to continue when a step fails — in particular, the contracts are deployed
> by the contracts package's deploy CLI, with CREATE3 through CreateX from a committed release, so
> every address is the canonical one in `packages/contracts/canonical.ts` by construction, and the
> CLI checks the code at each one. Only the **canonical deployer** can deploy there: its key signs
> the deployment, and the CLI refuses any other key.

## What you need to fund ⚠️

Three EOAs need testnet ETH. The operator and executor are throwaway keys you generate (never reuse
real keys); the canonical deployer is the one key that owns every canonical address. A fourth key is
required but needs no funding:

| Account | Suggested | Why |
| --- | --- | --- |
| **Canonical deployer** (`CANONICAL_DEPLOYER_PRIVATE_KEY`) | ~0.05 ETH | Deploys the contracts. Its address is `CANONICAL_DEPLOYER` (`packages/contracts/deploy/config.ts`), part of every canonical address; used for nothing else. |
| **Operator** (`DEPLOYER_PRIVATE_KEY`) | ~0.25 ETH | The paymaster's `ROLE_ADMIN` on this demo. Stakes the paymaster (`STAKE_ETH`), funds **each** tenant's sponsorship balance (`TENANT_FUND_ETH`, spent once per entry in `PAYMASTER_TENANTS`) and holds the test fixtures (off production chains). |
| **Bundler executor** (`BUNDLER_EXECUTOR_PRIVATE_KEYS`) | ~0.05 ETH | Signs and pays gas for every `handleOps` transaction. It's reimbursed by the EntryPoint (from the paymaster deposit), but must front the ETH. |
| **Sponsorship signer** (`SPONSORSHIP_SIGNER_KEY`) | none | The key wallet-api signs ERC-7677 sponsorships with. It authorises spending against the tenant's paymaster balance; it never pays gas. |

The end user's passkey wallet pays nothing.

> No P256 verifier contract is needed. Sepolia provides the RIP-7212 precompile at `0x100`, so
> passkey signatures are verified by the precompile (cheap). On chains without it, `webauthn-sol`
> automatically falls back to the in-contract FreshCryptoLib path — so the demo works either way.

## Prerequisites

- Docker (Compose), Node/pnpm (repo already bootstrapped)
- An RPC endpoint. The keyless public default (`https://ethereum-sepolia-rpc.publicnode.com`) works
  for everything here, including the bundler: giano-bundler simulates userops with `eth_call`
  (state overrides) and never calls `debug_traceCall`, so no trace-capable RPC is needed.
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
- `CANONICAL_DEPLOYER_PRIVATE_KEY`, `DEPLOYER_PRIVATE_KEY` and `SPONSORSHIP_SIGNER_KEY` (half A —
  deployment and provisioning)
- `BUNDLER_EXECUTOR_PRIVATE_KEYS` (half B — only to run the stack)
- (optional) `DEPLOY_RPC_URL` — the **only** RPC the deployment needs. Prefer a keyed endpoint:
  a flaky public RPC dropping a receipt mid-run is the usual cause of a failed deploy (re-running
  is safe).
- (optional) `RPC_URL` — the local stack's serving RPC; the keyless publicnode default is fine
- (optional) `BUNDLER_NODE_RPC_URL` — leave blank to reuse `RPC_URL`

### 2. Check funding

```sh
./deploy/sepolia/print-funding.sh
```

Prints each key's address and current balance. Send Sepolia ETH from a faucet
(e.g. https://www.alchemy.com/faucets/ethereum-sepolia) until the operator and executor are funded,
and make sure the canonical deployer has gas for step 3.

### 3. Deploy the contracts (one-time)

```sh
./deploy/sepolia/deploy-contracts.sh
```

Deploys, through `pnpm --filter @appliedblockchain/giano-contracts deploy:cli` (CREATE3 via CreateX,
from the latest release, signed with `CANONICAL_DEPLOYER_PRIVATE_KEY`):

| Command | Contracts |
| --- | --- |
| `core` | `GianoSmartWallet` (implementation) + `GianoSmartWalletFactory` + the sponsorship paymaster (implementation, and proxy initialised in the same transaction with the operator as `ROLE_ADMIN`) |
| `testing` | `PrivateERC20` (the demo token) + `PermissivePaymaster` (fixture) — skipped on production chains |

It then writes `FACTORY_ADDRESS`, `SPONSORSHIP_PAYMASTER_ADDRESS`, `TEST_PAYMASTER_ADDRESS` and
`TEST_ERC20_ADDRESS` back into `deploy/.env`, and records the deployment in
`packages/contracts/deployments/<chainId>.json`. Re-running is idempotent: contracts already in place
are checked and recorded, never redeployed.

If the CLI fails, **stop**: do not serve the chain. The usual causes are upstream — a missing
CreateX, a non-canonical EntryPoint, or a key that is not the canonical deployer. While
`CANONICAL_DEPLOYER` in `deploy/config.ts` is still the placeholder, the CLI refuses every non-local
chain.

### 4. Provision the paymaster (one-time)

```sh
./deploy/sepolia/provision-paymaster.sh
```

Grants the roles, registers the sponsorship signing key, stakes with the EntryPoint, registers
every tenant in `PAYMASTER_TENANTS` and funds each balance — then verifies all of it with
`giano-doctor chain`, which must exit green before you go on.

`PAYMASTER_TENANTS` defaults to the two tenants the development environment serves
(`infra/iac/_locals.tf`): `example` and `byoui`, under the ids its database already holds — the
same ids they are registered under on Base Sepolia (recorded as `EXAMPLE_TENANT_ID` /
`BYOUI_TENANT_ID` in `deploy/infrastructure.aws.env.example`). They are **pinned** in
`deploy/sepolia.env.example`, and that is load-bearing — the paymaster keys each tenant's balance
on the 16 bytes of its UUID, so the database and the chain have to agree. `wallet-api` states the
consequence directly (`services/wallet-api/src/services/tenants.ts`): a tenant created without an
`id` gets a random one, and *"a random id would leave every sponsorship refused as unknown
tenant"*. The id is immutable once set; changing it orphans that tenant's on-chain balance.

> ⚠ Never invent tenant ids here. A tenant registered under an id no database holds can never
> be sponsored for, and its balance can only be withdrawn. A new environment's platform admins create
> its tenants in the paymaster console first, then register the ids those tenants were given.

Every role lands on the operator EOA. That is the development shape the e2e devnet uses too, not a
shortcut smuggled in: a production deployment routes every grant through the timelock, and
`giano-doctor chain --role-admin` is what asserts that.

### 5. Register the chain (optional, but do it if the chain is here to stay)

```sh
pnpm --filter @appliedblockchain/giano-contracts gen:addresses
```

Commit `packages/contracts/deployments/<id>.json` together with the regenerated `addresses.ts`.
`gen:addresses` fails if any recorded address or codehash is not canonical, so this is the same gate
as step 3 — expressed as a committed artefact rather than a one-off run. Once registered, the
chain's addresses default correctly everywhere and `FACTORY_ADDRESS` no longer has to be passed by
hand.

### 6. Bring up the stack

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.sepolia.yml up --build
```

| Service | URL |
| --- | --- |
| bundler (giano-bundler) | http://localhost:4337 |
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

On Sepolia the allowlist is empty: it is a production chain, so step 3 deploys no demo ERC-20
(`TEST_ERC20_ADDRESS` stays blank). That still sponsors wallet management, which is platform
policy rather than allowlist — and that is what the sample dApp's **Send** button is (a 0 ETH
self-call). On a non-production chain where step 3 did deploy the fixtures, the demo ERC-20 is
allowlisted too.

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

Open **http://app.localhost:4400**, create a passkey wallet, connect, and press **Send** for a
sponsored transaction. It lands on Sepolia — check the tx on https://sepolia.etherscan.io.
(**Transfer demo ERC-20** needs the test fixtures, which Sepolia does not carry; there it is
refused as not allowlisted.)

Tear down: `docker compose --env-file deploy/.env -f deploy/docker-compose.sepolia.yml down`

## Using a different EVM chain

Set `CHAIN_ID` (and `DEPLOY_CHAIN_ID`), `RPC_URL` and `DEPLOY_RPC_URL` in `deploy/.env` — the
deploy and provisioning scripts use `DEPLOY_RPC_URL` first, so leaving it on Sepolia deploys to
Sepolia — then rerun steps 2–8
(`BUNDLER_NODE_RPC_URL` only if that chain's public RPC won't serve the bundler). The deploy CLI
reads the chain id from the endpoint, so no per-chain configuration is needed.

Two chain prerequisites are absolute, and both fail silently if skipped — see
[`specs/CHAIN-ADOPTION.md`](../../specs/CHAIN-ADOPTION.md) steps 1 and 2. CreateX must be present
(the deploy CLI checks). EntryPoint v0.7 must be at its canonical address: the account
implementation hardcodes it, so on a chain without it the canonical addresses would hold wallets
bound to nothing. A private chain will not have either, and both
must be deployed before any Giano contract.

## Restricting sponsorship

Sponsorship is already restricted twice over, and neither layer is optional:

- `USEROP_ALLOWED_PAYMASTERS` defaults to the deployed sponsorship paymaster, so wallet-api relays
  only ops sponsored by it.
- The tenant's own rules (step 7) allowlist contracts and selectors and cap the cost per
  transaction. `provision-sponsorship.sh` installs a deliberately generous demo config — the demo
  ERC-20 in full where the chain has one, a 0.5 ETH cap. Narrow it through the same endpoint.

Sponsorship rules are per `(tenant, chain)` and are never inherited from another chain.
