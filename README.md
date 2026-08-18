<p align="center">
 <img src="assets/logo.png" width="200"/>
 <h1 align="center">Giano</h1>
</p>

**Giano** is an ERC-4337-compliant smart wallet based on the [Coinbase Smart Wallet](https://github.com/coinbase/smart-wallet).

## Architecture at a glance

Giano ships as versioned artifacts deployed into a stack you control — either self-hosted by the
integrator, or run by Applied Blockchain as a dedicated per-client deployment. There is no public
multi-tenant Giano: one deployment serves one client, and `RP_ID` is fixed per deployment.

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

# publish the stack under its names (once per boot — port 80 needs sudo)
sudo pnpm -F @appliedblockchain/giano-e2e portless:proxy
pnpm -F @appliedblockchain/giano-e2e portless:up
```

Addresses are names, not ports. [portless](https://github.com/vercel-labs/portless) runs a
local proxy on port 80 and maps each `*.localhost` name to the loopback port behind it;
`e2e/origins.mjs` is the name/port table and the single source of truth the fixtures, the
tenant seed and the tests all read.

| Service | URL | Notes |
| --- | --- | --- |
| devnet (anvil) | http://rpc.localhost | chain 31337, contracts pre-deployed |
| bundler (alto) | http://bundler.localhost | EntryPoint v0.7 |
| wallet-api | http://api.localhost | also reached via the wallet-web `/api` proxy |
| wallet-web | http://wallet.localhost | the wallet origin (open it directly for the Settings view) |

`*.localhost` hosts resolve to `127.0.0.1` automatically. Point a dApp at
`http://wallet.localhost` as the wallet URL; the stack already allow-lists the E2E dApp
origin (`http://app.localhost`).

To run the sample dApp against this stack (thin-SDK fixture on `http://app.localhost`):

```sh
pnpm --filter @appliedblockchain/giano-e2e dapp
```

Tear down with `docker compose -f deploy/docker-compose.e2e.yml down`, and drop the names with
`pnpm -F @appliedblockchain/giano-e2e portless:down`. HTTP rather than portless's default
HTTPS is deliberate: `http://*.localhost` is already a secure context, so passkeys work without
minting and trusting a local CA.

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

### Option C — Chakra sample dApp (thin SDK)

`services/custom-example` (`pnpm demo:dev`) is a Vite + React + Chakra UI demo of the thin
two-origin integration — the same model as the E2E fixture, but with a real UI: wallet basics
(connect, send, sign) plus an ERC-20 panel (read balances, transfer, approve, and sign an
EIP-2612 permit). Bring up the Option A stack, then:

```sh
pnpm demo:dev   # http://app.localhost
```

It defaults to the Option A stack (wallet origin `http://wallet.localhost`, anvil RPC
`http://rpc.localhost`, chain 31337, devnet test token prefilled). Override with `VITE_WALLET_URL`,
`VITE_RPC_URL`, `VITE_CHAIN_ID`, `VITE_TEST_ERC20` for other networks.

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

Earlier versions of `services/custom-example` committed `.env-*` files containing Coinbase
Developer Platform bundler RPC URLs whose path segment is an API key. Those files have been
removed (the thin-SDK demo needs no bundler URL), but **the keys remain in git history and must be
rotated** (ops task) — treat them as public.

## Deploying Giano (for client projects)

> **New to Giano? Start with [`specs/DEVELOPER-GUIDE.md`](specs/DEVELOPER-GUIDE.md)** — a single
> self-contained guide covering dApp integration, standing up the stack on any EVM chain, the
> `giano-doctor` verification CLI, and a production checklist, with explicit software/keys/secrets/
> infrastructure dependencies.

- `deploy/docker-compose.reference.yml` — the reference stack (postgres + wallet-api + wallet-web)
  with a fully commented env matrix to copy into your own deployment.
- `deploy/helm/giano` — Helm chart (wallet-api + migrations hook, wallet-web, optional bundler,
  contracts-deployer pre-install Job, ingress).
- `specs/INTEGRATION.md` — DNS/TLS, proxy rules, the COOP caveat, per-container env, and the
  upgrade runbook. `COMPATIBILITY.md` — versioning and upgrade order. The secrets inventory and the
  metrics to watch them by are in `specs/DEVELOPER-GUIDE.md` §2.2 and §6.
- `specs/PAYMASTER-REQUIREMENTS.md` and `specs/PAYMASTER-SPECS.md` — gas sponsorship: what it must
  do and why the decisions were made, and the technical design that implements it.

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

## Components

**Contracts** (`packages/contracts`)

- `GianoSmartWallet` — the smart account: validates passkey/ECDSA signatures and executes calls.
- `GianoSmartWalletFactory` — CREATE2 factory; `getAddress(owners, nonce)` is the counterfactual address.
- `MultiOwnable` — owner set, where each owner is a P-256 passkey or an ECDSA address.

**Wallet origin** (`services/wallet-web` + `packages/wallet-core`)

- `wallet-core/provider.ts` — the EIP-1193 provider that repackages transactions as ERC-4337
  user operations. It runs **on the wallet origin**, never in a dApp bundle.
- `wallet-core/account/toGianoSmartAccount.ts` — viem smart-account instance for the wallet.
- `wallet-core/provider-injection` — the seam between the provider and its backend;
  `createWalletApiInjection` binds it to `giano-wallet-api`.

**dApp SDK** (`packages/connector` + `packages/wallet-transport`)

- `thin/create-giano-wallet-provider.ts` — `createGianoWalletProvider`, the only provider a dApp
  needs; reads are answered locally, wallet actions go over the popup transport.
- `connector.ts` / `gianoWallet.ts` — wagmi connector and RainbowKit wallet built on top of it.
