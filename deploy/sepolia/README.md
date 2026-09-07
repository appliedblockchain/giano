# Giano e2e demo on Sepolia (or any EVM chain)

A second local demo stack that runs the full Giano system against a **real chain** instead of a
local anvil devnet. It defaults to **Ethereum Sepolia** but is entirely env-driven — point it at
any EVM chain by changing the values in `deploy/.env`.

| | `docker-compose.e2e.yml` (existing) | `docker-compose.sepolia.yml` (this) |
| --- | --- | --- |
| Chain | local anvil, pre-baked state | real chain via external RPC |
| Contracts | baked into `state.json` | **you deploy them once** |
| Bundler | Alto + anvil dev key | Alto + **your funded executor** |
| Gas | free anvil ETH | **real testnet ETH** |

## What you need to fund ⚠️

Two EOAs need testnet ETH (both are throwaway keys you generate — never reuse real keys):

| Account | Suggested | Why |
| --- | --- | --- |
| **Deployer** (`DEPLOYER_PRIVATE_KEY`) | ~0.1 ETH | Deploys the 4 contracts and seeds the paymaster's EntryPoint deposit (`PAYMASTER_FUND_ETH`, default 0.05). |
| **Alto executor** (`ALTO_EXECUTOR_PRIVATE_KEY`) | ~0.05 ETH | Signs and pays gas for every bundle on-chain. It's reimbursed from the paymaster deposit, but must front the ETH. |

The `PermissivePaymaster` is what actually sponsors the end user's gas — it's funded from the
deployer at deploy time. The end user's passkey wallet still pays nothing.

> No P256 verifier contract is needed. Sepolia provides the RIP-7212 precompile at `0x100`, so
> passkey signatures are verified by the precompile (cheap). On chains without it, `webauthn-sol`
> automatically falls back to the in-contract FreshCryptoLib path — so the demo works either way.

## Prerequisites

- Docker (Compose), Node/pnpm (repo already bootstrapped)
- An RPC endpoint. The keyless public default (`https://ethereum-sepolia-rpc.publicnode.com`) works
  for everything here, including the bundler: the stack runs Alto with `--safe-mode false`, which
  validates userops via `eth_call` simulation rather than `debug_traceCall`. Only if you enable
  Alto's safe mode do you need a trace-capable RPC (Alchemy/QuickNode/Infura free tier).
- Two throwaway private keys. Generate with:
  ```sh
  pnpm --filter @appliedblockchain/giano-contracts exec node -e "console.log(require('ethers').Wallet.createRandom().privateKey)"
  ```

## Steps

### 1. Configure

```sh
cp deploy/sepolia.env.example deploy/.env
```

Edit `deploy/.env` and set at minimum:
- `DEPLOYER_PRIVATE_KEY`, `ALTO_EXECUTOR_PRIVATE_KEY`, `ALTO_UTILITY_PRIVATE_KEY`
- (optional) `RPC_URL` — browser/api/bundler reads; the keyless publicnode default is fine
- (optional) `BUNDLER_NODE_RPC_URL` — leave blank to reuse `RPC_URL`; only needed if you enable
  Alto's safe mode (then point it at a `debug_traceCall`-capable RPC)

### 2. Check funding

```sh
./deploy/sepolia/print-funding.sh
```

Prints the deployer + executor addresses and their current balances. Send Sepolia ETH from a
faucet (e.g. https://www.alchemy.com/faucets/ethereum-sepolia) until both are funded.

### 3. Deploy the contracts (one-time)

```sh
./deploy/sepolia/deploy-contracts.sh
```

Deploys factory + implementation + `PermissivePaymaster` + test ERC-20, seeds the paymaster
deposit, and writes `FACTORY_ADDRESS` / `PAYMASTER_ADDRESS` / `TEST_ERC20_ADDRESS` back into
`deploy/.env`. Re-running is idempotent (Ignition resumes the existing deployment).

Verify the deployment on-chain before bringing up the stack (reads `deploy/.env`):

```sh
set -a; . deploy/.env; set +a
pnpm run doctor chain --rpc "$RPC_URL" --chain-id "$CHAIN_ID" \
  --factory "$FACTORY_ADDRESS" --paymaster "$PAYMASTER_ADDRESS"
```

Confirms the EntryPoint, factory and implementation have code, the paymaster's EntryPoint deposit
is funded, and — probed live — that P256 signatures verify via Sepolia's RIP-7212 precompile. Exits
non-zero if any critical check fails. See `docs/DEVELOPER-GUIDE.md` §6 for the full `giano-doctor`
reference (including `doctor wallet` to inspect a specific passkey wallet).

### 4. Bring up the stack

```sh
docker compose --env-file deploy/.env -f deploy/docker-compose.sepolia.yml up --build
```

| Service | URL |
| --- | --- |
| bundler (alto) | http://localhost:4337 |
| wallet-web | http://wallet.localhost:8081 |
| wallet-api | internal (via wallet-web `/api` proxy) |

### 5. Run the sample dApp

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

Set `CHAIN_ID` (and `DEPLOY_CHAIN_ID`) and `RPC_URL` in `deploy/.env`, then rerun steps 2–5
(`BUNDLER_NODE_RPC_URL` only if that chain's public RPC won't serve the bundler). The deploy script
auto-uses hardhat's `custom` network for non-Sepolia chains. The canonical EntryPoint v0.7 address
is assumed; override `ENTRYPOINT_ADDRESS` if your chain differs.

## Restricting sponsorship to your own app

`USEROP_ALLOWED_PAYMASTERS` defaults to your deployed paymaster, so wallet-api only relays ops
sponsored by it. `PermissivePaymaster` itself sponsors everything unconditionally (testing only) —
for production swap in a `VerifyingPaymaster` with an off-chain policy signer and/or an on-chain
target allowlist. See the contracts under `vendor/account-abstraction/contracts/samples/`.
