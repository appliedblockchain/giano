<p align="center">
 <img src="assets/logo.png" width="200"/>
 <h1 align="center">Giano</h1>
</p>

**Giano** is an ERC-4337-compliant smart wallet based on the [Coinbase Smart Wallet](https://github.com/coinbase/smart-wallet).

## Architecture at a glance

Giano ships as versioned artifacts you deploy into your own stack (it is never centrally hosted):

- **Packages** (npm, GitHub Packages): `giano-contracts` (ABIs + address registry), `giano-wallet-core` (provider, passkey smart account, injection seam), `giano-wallet-transport` (popup protocol), `giano-connector` (the thin dApp SDK).
- **Services** (Docker images, GHCR): `giano-wallet-api` (Fastify + Postgres: WebAuthn ceremonies, sessions, policied userop relay), `giano-wallet-web` (the dedicated wallet origin — passkey ceremonies + consent UI), `giano-bundler`, `giano-devnet`, `giano-contracts-deployer`.

A dApp integrates only `giano-connector` + a wallet URL; all wallet trust lives on the wallet origin.

## Prerequisites

- **Node 22** (`tsc` needs a big heap on this repo — see Troubleshooting) and **pnpm** (`corepack enable`).
- **Docker** (Compose) — for the local stacks, wallet-api integration tests, and E2E.
- **Foundry** (`curl -L https://foundry.paradigm.xyz | bash`) and **git submodules** (`pnpm git:init`) — only needed to compile contracts or run `forge test`; the published-package build path needs neither.

```sh
pnpm install
```

## Running everything locally

### Option A — full stack in Docker (recommended)

The E2E compose stack brings up the **entire system** with contracts pre-deployed into an
instant-boot devnet (EntryPoint v0.7 + Giano factory + testing paymaster baked into the anvil
state), so there is nothing to deploy by hand:

```sh
docker compose -f deploy/docker-compose.e2e.yml up --build
```

This starts:

| Service | URL | Notes |
| --- | --- | --- |
| devnet (anvil) | http://localhost:8545 | chain 31337, contracts pre-deployed |
| bundler (alto) | http://localhost:4337 | EntryPoint v0.7 |
| wallet-api | (internal) | reached via the wallet-web `/api` proxy |
| wallet-web | http://wallet.localhost:8081 | the wallet origin (open it directly for the Settings view) |

`*.localhost` hosts resolve to `127.0.0.1` automatically. Point a dApp at
`http://wallet.localhost:8081` as the wallet URL; the stack already allow-lists the E2E dApp
origin (`http://app.localhost:4400`).

To run the sample dApp against this stack (thin-SDK fixture on `http://app.localhost:4400`):

```sh
pnpm --filter @appliedblockchain/giano-e2e dapp
```

Tear down with `docker compose -f deploy/docker-compose.e2e.yml down`.

### Option B — iterate on wallet-api against a fresh devnet

`deploy/docker-compose.dev.yml` runs Postgres + a fresh anvil + alto + wallet-api (built from
source). The chain starts empty, so deploy the contracts first and pass the factory address:

```sh
# 1. start a local anvil (or use the compose one) and deploy Giano contracts
pnpm hh:node                      # anvil on :8545 (separate terminal)
pnpm hh:initlocal                 # EntryPoint + factory + testing contracts

# 2. bring up the API stack, pointing it at the deployed factory
FACTORY_ADDRESS=0x… docker compose -f deploy/docker-compose.dev.yml up --build
```

Swagger UI is available at the wallet-api's `/docs` outside production.

### Option C — legacy embedded demo (Next.js)

The original `services/custom-example` app (embedded mode: the demo *is* the wallet) still runs
for reference. It talks to the wallet-api via the reference injection:

```sh
# needs the wallet-api reachable on localhost:8080 — use the Option B stack
# (Option A's wallet-api is internal-only, behind the wallet-web proxy)
pnpm build:connector
NEXT_PUBLIC_WALLET_API_URL=http://localhost:8080 pnpm demo:dev   # http://localhost:4000
```

## Running the tests

```sh
# package unit tests (no Docker)
pnpm --filter @appliedblockchain/giano-wallet-core test        # signing, fee precedence
pnpm --filter @appliedblockchain/giano-wallet-transport test   # popup protocol, origin pinning

# wallet-api integration tests (spins up Postgres via testcontainers — needs Docker)
pnpm --filter @appliedblockchain/giano-wallet-api test

# contract tests (needs Foundry + submodules)
forge test    # from packages/contracts

# end-to-end (two real origins, Chromium + virtual authenticator)
docker compose -f deploy/docker-compose.e2e.yml up --build -d
pnpm --filter @appliedblockchain/giano-e2e exec playwright install chromium
pnpm --filter @appliedblockchain/giano-e2e test
```

The E2E suite drives the full flow — create wallet, connect, session resume, send a sponsored
transaction through consent to a receipt, reject (4001), sign message / typed data, hostile-origin
rejection, ROR well-known, and the popup-blocked path.

## Security note: committed bundler API keys

The demo `.env-*` files in `services/custom-example` contain Coinbase Developer Platform bundler
RPC URLs whose path segment is an API key. **These keys are in git history and must be rotated**
(ops task) — treat them as public. New keys must be supplied via untracked `.env` files, never
committed.

## Deploying Giano (for client projects)

- `deploy/docker-compose.reference.yml` — the reference stack (postgres + wallet-api + wallet-web)
  with a fully commented env matrix to copy into your own deployment.
- `deploy/helm/giano` — Helm chart (wallet-api + migrations hook, wallet-web, optional bundler,
  contracts-deployer pre-install Job, ingress).
- `docs/INTEGRATION.md` — DNS/TLS, proxy rules, the COOP caveat, per-container env, and the
  upgrade runbook. `docs/SECRETS.md` — secrets inventory and monitoring. `COMPATIBILITY.md` —
  versioning and upgrade order.

### Important tips

- Run `pnpm build` (or `pnpm build:connector`) after changing the contracts or packages so
  dependents pick up the changes.
- Contracts deploy with Hardhat Ignition using a `CREATE2` strategy, so addresses are identical on
  any chain **as long as the bytecode is unchanged**. Restart anvil and re-run `hh:initlocal` after
  changing contracts. Deployed addresses come from the committed registry in
  `@appliedblockchain/giano-contracts` (`addresses.ts`, regenerated via `pnpm gen:addresses`); the
  CI `determinism` job fails if the CREATE2 addresses drift.

## Troubleshooting

### Heap Out of Memory Error

If you encounter a "heap out of memory" error when running the build command, this is typically due to Node.js running out of memory during the build process. This can happen when building large projects or when the default memory allocation is insufficient.

**Solution:**

Run the build command with increased memory allocation:

```sh
NODE_OPTIONS='--max-old-space-size=16384' pnpm build
```

This increases the maximum heap size to 16GB. You can adjust the value (in MB) based on your system's available memory:
- `8192` for 8GB
- `16384` for 16GB  
- `32768` for 32GB

**Alternative solutions:**
- Close other memory-intensive applications before building
- Clear Node.js cache: `pnpm store prune`
- Restart your development environment

### Test contracts

#### Contract tests (Foundry)
```sh
forge test
```

## Components

- `GianoSmartWallet`: the smart wallet itself, which validates the signatures and executes the calls.
- `GianoSmartWalletFactory`: the contract responsible for deploying the smart wallet contracts
- `toGianoSmartAccount.ts`: module that instantiates a Viem client for the Giano Smart Wallet
- `provider.ts`: `EIP-1193`-compatible provider that intercepts EVM RPC requests and repackages transactions as user ops to be passed to the bundler
- `connector.ts`: WAGMI connector
- `gianoWallet.ts`: RainbowKit integration code

## Setting up Blockscout (block explorer)

If you want, you can use `docker compose` to start up a local Blockscout instance to explore the transactions and
contracts deployed on the local network. Start the Hardhat node at the default port and then run these commands to clone the
Blockscout repo and start up a local instance:

```sh
# run these commands OUTSIDE of the project's structure
git clone https://github.com/blockscout/blockscout/ && \
cd blockscout/docker-compose && \
docker compose -f hardhat-network.yml up -d
```

You can then access the Blockscout instance at `http://127.0.0.1/`
