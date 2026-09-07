# Giano Developer Guide

**Everything you need to adopt Giano in a new project** — integrate a dApp, stand up the wallet
stack on any EVM chain, verify it on-chain, and run it in production. This is the entry point;
deeper reference material is linked at the end.

Giano is a self-hosted **passkey (WebAuthn / secp256r1) ERC-4337 smart-contract wallet**, forked
from the Coinbase Smart Wallet. There is **no public multi-tenant Giano** — every deployment serves
exactly one project, whether you host it yourself or Applied Blockchain hosts it for you (see
[`PRODUCT-STRATEGY.md`](./PRODUCT-STRATEGY.md)). This guide assumes you are deploying it yourself. A
dApp integrates only the thin `@appliedblockchain/giano-connector` SDK plus a wallet URL; all wallet
trust (passkeys, signing, consent, bundler) lives on a dedicated **wallet origin**.

---

## Contents

- [1. How Giano fits together](#1-how-giano-fits-together)
- [2. Dependency inventory — software, keys/secrets, infrastructure](#2-dependency-inventory)
- [3. Part A — Run the whole thing locally in 5 minutes](#3-part-a--run-the-whole-thing-locally-in-5-minutes)
- [4. Part B — Integrate your dApp (the thin SDK)](#4-part-b--integrate-your-dapp-the-thin-sdk)
- [5. Part C — Stand up the wallet stack on a new chain](#5-part-c--stand-up-the-wallet-stack-on-a-new-chain)
- [6. Part D — Verify & operate (`giano-doctor`)](#6-part-d--verify--operate-giano-doctor)
- [7. Part E — Production checklist](#7-part-e--production-checklist)
- [8. Troubleshooting](#8-troubleshooting)
- [9. Reference index](#9-reference-index)

---

## 1. How Giano fits together

An integration has **two halves**:

1. **Your dApp** (`app.yourapp.com`) — depends only on `@appliedblockchain/giano-connector` and a
   wallet URL. Its bundle contains **no** WebAuthn, credential, signing, or bundler code.
2. **The wallet origin** (`wallet.yourapp.com`) — the Giano containers you host: the wallet-web
   popup UI, the wallet-api backend (+ Postgres), and an ERC-4337 bundler, all pointed at an EVM
   chain where the Giano contracts are deployed.

```
  Browser
  ┌────────────────────┐        postMessage (JSON-RPC)       ┌──────────────────────────────┐
  │ dApp (app.yourapp) │  ── popup transport, origin-pinned ─▶│ wallet-web  (wallet.yourapp) │
  │  giano-connector   │                                     │  passkey ceremony + consent  │
  └────────────────────┘                                     └──────────────┬───────────────┘
        │ reads (eth_call…) answered dApp-side                   nginx same-origin proxy
        ▼                                                                    │  /api  /bundler  /rpc
   EVM RPC (public)                                              ┌───────────┴───────────┐
                                                                 ▼                       ▼
                                                        wallet-api + Postgres     ERC-4337 bundler (Alto)
                                                        WebAuthn, sessions,        signs+pays bundles
                                                        policied userop relay              │
                                                                 └──────────┬──────────────┘
                                                                            ▼
                                                              EVM chain: EntryPoint v0.7 →
                                                              GianoSmartWallet (passkey account)
```

**Trust boundary:** no private key or session secret ever reaches wallet-web or the dApp. The
browser only holds the passkey (non-extractable, in the platform authenticator) and an opaque
session token. Every server secret lives in wallet-api / bundler / deployer environments only.

**Key ideas** (full detail in the repo `README.md` and `GIANO-VS-COINBASE.md`):

- **Identity = passkey.** A WebAuthn secp256r1 credential created on the wallet origin; its 64-byte
  public key becomes an owner of a `MultiOwnable` smart account. Owners can be P-256 passkeys or
  plain ECDSA addresses.
- **Deterministic address.** `GianoSmartWalletFactory.getAddress(owners, nonce)` (CREATE2) gives the
  same wallet address before and after deployment, and — with the canonical build — the same factory
  address on every chain.
- **Transactions → UserOps.** The SDK repackages `eth_sendTransaction` into an ERC-4337 UserOp
  (EntryPoint v0.7). Gas is sponsorable by a paymaster.
- **Works on any EVM chain.** P-256 signatures verify via the **RIP-7212 precompile** where present
  (cheap), falling back to an **in-contract FreshCryptoLib verifier** where it isn't. (Don't assume
  which — [`giano-doctor`](#6-part-d--verify--operate-giano-doctor) probes it live.)

> **Legacy note.** Giano 0.x ran an *embedded* model where your dApp origin *was* the wallet. That
> surface has been removed — the connector ships only the thin SDK described here. See
> `packages/connector/README.md` if you are migrating a 0.x integration.

---

## 2. Dependency inventory

Everything you must provide, made explicit. "Required" means the minimal working stack.

### 2.1 Software

| Dependency | Needed for | Notes |
| --- | --- | --- |
| **Node 22** | building/running any package or service | `tsc` needs a large heap on this repo — see [Troubleshooting](#8-troubleshooting). |
| **pnpm** (`corepack enable`) | the monorepo (workspaces, `-r` builds) | version pinned in root `package.json`. |
| **Docker** (+ Compose) | the local stacks, wallet-api tests, E2E | not required if you consume only published images + npm packages. |
| **Foundry** + git submodules (`pnpm git:init`) | compiling contracts / `forge test` / deploying to a new chain | **not** needed to consume the published `giano-contracts` package. |
| **viem** `^2.31` | the dApp SDK (required peer) | the connector's only hard peer dependency. |
| **wagmi** `^2.15`, **@rainbow-me/rainbowkit** `^2.2` | *optional* — only for `createGianoConnector` / `giano()` | omit if you use the raw EIP-1193 provider. |
| A **GitHub Packages** token | installing the `@appliedblockchain/*` npm packages | see below — they are published to GitHub Packages, not npmjs. |

**GitHub Packages auth** (the packages are `access: restricted` under `@appliedblockchain`):

```ini
# .npmrc (in your dApp repo)
@appliedblockchain:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```
> Routing the whole `@appliedblockchain` scope to GitHub Packages means you cannot also pull public
> `@appliedblockchain/*` packages from npmjs in the same project.

### 2.2 Keys & secrets

Store all of these in your platform's secret manager. Never commit them; never inline them in
compose files or `values.yaml`. Full inventory + monitoring: [`docs/SECRETS.md`](./SECRETS.md).

| Secret | Held by | Purpose | Funded? |
| --- | --- | --- | --- |
| `DEPLOYER_PRIVATE_KEY` | contracts-deployer (one-shot) | deploys contracts + seeds the paymaster deposit on a new chain | **yes** — ~0.1 test ETH; ephemeral, never mount into long-running pods |
| `ALTO_EXECUTOR_PRIVATE_KEY(S)` | bundler | signs **and pays gas** for every bundle on-chain (reimbursed by the paymaster, but fronts the ETH) | **yes** — keep topped up (~0.05+); must differ from the deployer |
| `ALTO_UTILITY_PRIVATE_KEY` | bundler | Alto nonce/gas-price management | no — any throwaway key |
| `DATABASE_URL` | wallet-api, migrate job | Postgres DSN (credentials, sessions, audit) | n/a |
| `ADMIN_API_KEYS` | wallet-api | server-to-server ceremony options + ROR admin (required unless `OPEN_REGISTRATION=true`) | n/a |
| `POSTGRES_PASSWORD` | Postgres (reference/prod stacks) | DB credentials | n/a |
| session bearer tokens | issued to browsers | authenticate `/v1/*` | short TTL, revocable, only the sha256 hash is stored |

> **Repo-history rotation task:** earlier `.env-*` files under `services/custom-example` contained
> **Coinbase CDP bundler API keys committed to git history** — the files are gone but the keys
> remain in history, so treat them as public and rotate them. Real deployments supply bundler URLs
> via untracked env only.

wallet-api itself **holds no private key** — it never signs; it relays *signed* UserOps to the
bundler and reads the chain read-only. The EntryPoint address is server-configured, never taken from
a request.

### 2.3 Infrastructure services

| Service | Image / tech | Port | Required? |
| --- | --- | --- | --- |
| **Postgres 17** | `postgres:17-alpine` or managed | 5432 | **yes** — wallet-api state (users, credentials, sessions, challenges, userop log, ROR origins) |
| **wallet-api** | `ghcr.io/appliedblockchain/giano-wallet-api` (Fastify) | 8080 | **yes** — WebAuthn ceremonies, sessions, policied userop relay |
| **wallet-web** | `ghcr.io/appliedblockchain/giano-wallet-web` (nginx + React) | 8080 | **yes** — the passkey popup origin; needs its own TLS host = the irreversible `RP_ID` |
| **ERC-4337 bundler** | `ghcr.io/appliedblockchain/giano-bundler` (Pimlico Alto) | 4337 | **yes** — needs a funded executor EOA; any ERC-4337 bundler works |
| **EVM RPC** | public or your own node | — | **yes** — a keyless public endpoint works with Alto `--safe-mode false` |
| **Deployed contracts** | factory + implementation (+ paymaster/test-ERC20 for demos) | — | **yes** — pre-deployed on chains 8453 / 84532 / 381185; deploy per-chain elsewhere |

---

## 3. Part A — Run the whole thing locally in 5 minutes

The E2E compose stack boots the **entire system** with contracts pre-baked into an instant-boot
anvil devnet — nothing to deploy by hand.

```sh
pnpm install
docker compose -f deploy/docker-compose.e2e.yml up --build
```

| Service | URL | Notes |
| --- | --- | --- |
| devnet (anvil) | http://localhost:8545 | chain 31337, contracts pre-deployed |
| bundler (alto) | http://localhost:4337 | EntryPoint v0.7 |
| wallet-web | http://wallet.localhost:8081 | the wallet origin (open directly for the Settings view) |
| wallet-api | internal | reached via the wallet-web `/api` proxy |

`*.localhost` resolves to `127.0.0.1` automatically. Run the sample thin-SDK dApp against it:

```sh
pnpm --filter @appliedblockchain/giano-e2e dapp   # http://app.localhost:4400
```

Open **http://app.localhost:4400**, create a passkey wallet, connect, and send a sponsored
transaction. For a richer UI on the same stack (wallet basics + an ERC-20 panel), run the Chakra
sample dApp instead: `pnpm demo:dev` (also `http://app.localhost:4400`). Tear down with
`docker compose -f deploy/docker-compose.e2e.yml down`.

Confirm the deployment on-chain any time:

```sh
pnpm run doctor chain --rpc http://localhost:8545 --chain-id 31337 \
  --factory 0x26dCd29390eba3B22BcCbd2143989E5994Ac7050 \
  --paymaster 0xCbc040482c1dd07D533800874DC37De7b18c8092
```

---

## 4. Part B — Integrate your dApp (the thin SDK)

### 4.1 Install

```sh
npm install @appliedblockchain/giano-connector viem
# optional, for wagmi / RainbowKit:
npm install wagmi @rainbow-me/rainbowkit
```
(plus the `.npmrc` from [§2.1](#21-software)).

### 4.2 Create the provider

`createGianoWalletProvider` returns an EIP-1193 provider pointed at your wallet origin.

```ts
import { createGianoWalletProvider } from '@appliedblockchain/giano-connector';
import { baseSepolia } from 'viem/chains';

const provider = createGianoWalletProvider({
  walletUrl: 'https://wallet.yourapp.com', // your deployed wallet origin
  chain: baseSepolia,
});
```

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `walletUrl` | `string` | — (required) | URL of your wallet-web deployment; only its origin is used |
| `chain` | viem `Chain` | — (required) | target chain |
| `transport` | viem `Transport` | `http(chain.rpcUrls.default.http[0])` | read-path transport; reads are answered dApp-side, no popup |
| `walletApiPath` | `string` | `'/api'` | path under the wallet origin that proxies to wallet-api (nginx default) |
| `storage` | `Pick<Storage,…>` | `localStorage` | session-resume persistence |
| `sdkVersion` | `string` | `'1.0.0'` | sent in the transport handshake |

**What runs where:** reads (`eth_call`, `eth_chainId`, …) are answered locally; `eth_accounts`
answers from the cached session (no popup); wallet methods (`eth_requestAccounts`,
`eth_sendTransaction`, `personal_sign`, `eth_sign`, `eth_signTypedData_v4`, and the userop methods)
open the popup where the user approves with a passkey. `waitForUserOperationReceipt` polls the
wallet-api's public receipt endpoint — **your dApp never needs a bundler URL.**

### 4.3 Wire it to wagmi or RainbowKit

```ts
// wagmi
import { createGianoConnector } from '@appliedblockchain/giano-connector';
import { createConfig, custom } from 'wagmi';
import { baseSepolia } from 'wagmi/chains';

const config = createConfig({
  chains: [baseSepolia],
  transports: { [baseSepolia.id]: custom(provider) },
  connectors: [createGianoConnector({ provider })],
});

// or RainbowKit
import { giano } from '@appliedblockchain/giano-connector';
const wallet = giano({ provider }); // use inside connectorsForWallets(...)
```

The wagmi connector adds `waitForUserOperationReceipt(hash)` returning a viem
`UserOperationReceipt` — the ERC-4337 hook to await inclusion after `eth_sendTransaction`.

### 4.4 The core flows (raw provider)

```ts
// connect (MUST be from a user gesture — opens a popup)
const accounts = await provider.request<string[]>({ method: 'eth_requestAccounts' });

// send a sponsored transaction → returns a UserOp hash, then await the receipt
const [account] = await provider.request<string[]>({ method: 'eth_accounts' });
const hash = await provider.request<string>({
  method: 'eth_sendTransaction',
  params: [{ to: account, value: '0x0' }],
});
const receipt = await provider.request<{ success: boolean }>({
  method: 'waitForUserOperationReceipt',
  params: [hash],
});

// sign
const sig = await provider.request<string>({ method: 'personal_sign', params: [hexMessage, account] });
const typed = await provider.request<string>({ method: 'eth_signTypedData_v4', params: [account, JSON.stringify(typedData)] });

// events + teardown
provider.on('accountsChanged', (accts) => { /* … */ });
provider.on('disconnect', () => { /* … */ });
provider.disconnect();
```

(A complete, framework-free reference is `e2e/dapp/main.ts`.)

### 4.5 Error handling & popup requirements

```ts
import { TransportError, TransportRpcError, RPC_ERRORS } from '@appliedblockchain/giano-connector';

try {
  await provider.request({ method: 'eth_requestAccounts' });
} catch (err) {
  if (err instanceof TransportRpcError && err.code === 4001) {/* user rejected */}
  else if (err instanceof TransportError && err.code === 'POPUP_BLOCKED') {/* not a user gesture, or COOP */}
}
```

- **Call wallet methods from a user gesture** (a click handler). Safari blocks popups otherwise.
- **Do not send `Cross-Origin-Opener-Policy: same-origin` from the dApp** — it severs
  `window.opener` and the handshake times out. Use `same-origin-allow-popups` or no COOP header.
- User rejection → `TransportRpcError` code `4001`; blocked popup → `TransportError` `POPUP_BLOCKED`;
  lost session → `disconnect` event (reconnect via `eth_requestAccounts`).

---

## 5. Part C — Stand up the wallet stack on a new chain

The worked example below is Ethereum Sepolia, but every value is env-driven — point it at any EVM
chain by changing `CHAIN_ID` + `RPC_URL` + the addresses. The full runbook is
[`deploy/sepolia/README.md`](../deploy/sepolia/README.md).

### 5.1 Contracts

- **On a registry chain** (Base 8453, Base Sepolia 84532, or 381185): nothing to do — the addresses
  ship in `@appliedblockchain/giano-contracts` (`getGianoDeployment(chainId)`).
- **On any other chain:** deploy once. Locally:
  ```sh
  cp deploy/sepolia.env.example deploy/.env   # set DEPLOYER_PRIVATE_KEY etc.
  ./deploy/sepolia/print-funding.sh           # shows the EOAs to fund + balances + faucets
  ./deploy/sepolia/deploy-contracts.sh        # deploys factory + impl + paymaster + test-ERC20,
                                              # seeds the paymaster deposit, writes addresses back to .env
  ```
  In containers/CI, use the `giano-contracts-deployer` image (compose `profiles: [deploy]` or the
  Helm pre-install hook) with `RPC_URL`, `CHAIN_ID`, `DEPLOYER_PRIVATE_KEY`.
- **CREATE2 determinism:** `pnpm hh:deploy --strategy create2` (fixed salt) gives identical addresses
  across chains for identical bytecode — this is why 8453 and 84532 share a factory. The
  `deploy-contracts.sh` script uses plain CREATE (portable, no deterministic-deployer dependency), so
  its addresses differ per chain — always read them back from `deploy/.env`.
- **P-256 bootstrap:** if the chain lacks the RIP-7212 precompile *and* the FreshCryptoLib verifier,
  passkey validation will fail. Deploy the verifier with `packages/contracts/scripts/p256_deploy.ts`
  (it also installs the Arachnid CREATE2 factory if absent). Verify with `giano-doctor` (§6) — it
  probes support live rather than assuming.

### 5.2 Bundler

Run Alto with a funded executor. It signs and pays for every bundle on-chain (reimbursed by the
paymaster deposit, but must front the ETH). Env (`services/bundler/entrypoint.sh`):

- `ALTO_RPC_URL` (required), `ALTO_ENTRYPOINTS` (default canonical v0.7),
  `ALTO_EXECUTOR_PRIVATE_KEYS` (required, **funded**), `ALTO_UTILITY_PRIVATE_KEY`, `ALTO_SAFE_MODE`.
- `--safe-mode false` validates UserOps via `eth_call` simulation, so a **plain public RPC works**.
  Only enable safe mode with a `debug_traceCall`-capable RPC (Alchemy/QuickNode/your node).
- The image refuses to start with the well-known anvil key unless `GIANO_DEV_MODE=true`.

### 5.3 Postgres + migrations

External Postgres by default. Apply migrations with `RUN_MIGRATIONS=true` on wallet-api, or the
one-shot `node dist/migrate.js` (the Helm chart runs it as a pre-install/upgrade Job). Migrations are
backward-compatible across one minor version.

### 5.4 wallet-api environment

Full schema in `services/wallet-api/src/config.ts`. Required and notable vars:

| Var | Required | Notes |
| --- | --- | --- |
| `DATABASE_URL` | ✓ | Postgres DSN (secret) |
| `RP_ID` | ✓ | **irreversible** — passkeys bind to it; e.g. `wallet.yourapp.com` |
| `EXPECTED_ORIGINS` | ✓ | CSV; **every origin's host must equal `RP_ID` or be a subdomain** (validated at boot) |
| `CHAIN_ID`, `RPC_URL`, `BUNDLER_URL` | ✓ | chain wiring |
| `ENTRYPOINT_ADDRESS`, `FACTORY_ADDRESS` | conditional | default from the registry; **required when `CHAIN_ID` is not in the registry** |
| `OPEN_REGISTRATION` | — | `false` (default, production) ⇒ registration is admin-gated |
| `ADMIN_API_KEYS` | conditional | CSV bearer keys (secret); **required unless `OPEN_REGISTRATION=true`** |
| `USEROP_MAX_*`, `USEROP_ALLOWED_TARGETS`, `USEROP_ALLOWED_PAYMASTERS` | — | relay policy caps/allowlists (gas as integers, fees in wei) |
| `CORS_ORIGINS` | — | dApp origins that poll the public receipt endpoint cross-origin |
| `CHALLENGE_TTL_SECONDS`, `SESSION_TTL_SECONDS`, `CEREMONY_RATE_LIMIT_PER_MINUTE` | — | TTLs / rate limit |

### 5.5 wallet-web environment

wallet-web's nginx serves the SPA + `GET /config.json` and same-origin-proxies `/api` and
`/.well-known/webauthn` → wallet-api (and optionally `/rpc`, `/bundler` → your node/bundler to avoid
CORS). Env: `GIANO_CHAIN_ID`, `GIANO_RPC_URL`, `GIANO_BUNDLER_URL`, `GIANO_WALLET_API_UPSTREAM`,
`GIANO_RP_ID`, `GIANO_ALLOWED_DAPP_ORIGINS` (JSON array), `GIANO_FACTORY_ADDRESS` /
`GIANO_PAYMASTER_ADDRESS` (default from the registry), `GIANO_BRAND_NAME`.

- Give the wallet its **own TLS host** = `RP_ID`. WebAuthn requires a secure context.
- The browser reads chain state directly from `GIANO_RPC_URL`, so it must be CORS-enabled and safe to
  expose (keyless public endpoint, or the bundler proxied same-origin).

### 5.6 Gas sponsorship (paymaster)

Only a **testing** `PermissivePaymaster` ships (sponsors everything unconditionally — testing only).
For production, deploy and fund a `VerifyingPaymaster` with an off-chain policy signer and/or an
on-chain target allowlist (samples under `vendor/account-abstraction/contracts/samples/`). Set
`USEROP_ALLOWED_PAYMASTERS` on wallet-api so it only relays ops sponsored by your paymaster.

### 5.7 Reference stacks

- `deploy/docker-compose.reference.yml` — the client-project template (postgres + wallet-api +
  wallet-web from published images) with a fully commented env matrix.
- `deploy/helm/giano` — Helm chart: wallet-api (+ migrations hook), wallet-web, optional bundler,
  contracts-deployer pre-install Job, ingress. Secrets come from `secrets.existingSecret` (a k8s
  Secret with at least `DATABASE_URL`, `ADMIN_API_KEYS`, and `ALTO_EXECUTOR_PRIVATE_KEYS` if the
  bundler is enabled). `serviceMonitor.enabled=true` for Prometheus scraping.

---

## 6. Part D — Verify & operate (`giano-doctor`)

`giano-doctor` is a CLI (shipped in this repo) that verifies a chain's Giano deployment and inspects
individual wallets. It **probes the chain live** (contract code, deposits, P-256 support) and exits
non-zero on any critical failure, so it works as a pre-flight or CI gate.

> Invoke it with `pnpm run doctor` (not `pnpm doctor` — that hits pnpm's built-in command).

**Verify a chain's deployment:**

```sh
pnpm run doctor chain --rpc <url> --chain-id <id> \
  [--factory 0x..] [--paymaster 0x..] [--executor 0x..]
```
Checks: RPC reachable and chain id matches; EntryPoint v0.7, factory, and implementation have code;
paymaster deployed + its EntryPoint deposit balance (warns if low); executor native balance (if
given); and P-256 support (RIP-7212 precompile → FreshCryptoLib verifier → none). Addresses default
from flags → env (`FACTORY_ADDRESS`, `PAYMASTER_ADDRESS`, `ENTRYPOINT_ADDRESS`) → the contracts
registry for known chains. Example output:

```
Contracts
  ✓ EntryPoint v0.7 deployed: 0x0000000071727De22E5E9d8BAf0edAc6f37da032
  ✓ GianoSmartWalletFactory deployed: 0x26dCd29390eba3B22BcCbd2143989E5994Ac7050
  ✓ GianoSmartWallet implementation deployed: 0x15cC758f7D3188c2361f6141CEaa9Ab2792bea56
Passkey (P-256) verification support
  ✓ P-256 via RIP-7212 precompile: cheap on-chain verification (0x100)
doctor: all critical checks passed
```

**Inspect a wallet** — by address, or counterfactually from a passkey public key:

```sh
pnpm run doctor wallet --rpc <url> --chain-id <id> --address 0x..
pnpm run doctor wallet --rpc <url> --chain-id <id> --factory 0x.. --pubkey <x>,<y> [--nonce 0]
```
Reports the (counterfactual) address, whether it is deployed, its native balance, its EntryPoint
nonce, and — once deployed — its `MultiOwnable` owners (each classified as an ECDSA address or a
P-256 passkey).

**Other operational surfaces:**

- **Health:** wallet-api `GET /healthz` (liveness), `GET /readyz` (DB ping), `GET /v1/version`;
  wallet-web `GET /`; bundler `eth_supportedEntryPoints`.
- **UserOp status:** `GET /v1/userops/:hash` (authenticated, DB status + policy audit) and public
  `GET /v1/userops/:hash/receipt` (on-chain receipt — this is what the SDK polls).
- **Metrics:** wallet-api `GET /metrics` (Prometheus): `giano_userop_relayed_total{status}`,
  `giano_userop_policy_rejections_total{rule}`, `giano_ceremony_failures_total{kind}`,
  `giano_userop_relay_seconds`. Suggested alerts: policy-rejection spikes (probing), ceremony-failure
  spikes (broken RP config/attack), relay `failed` ratio, low bundler-executor balance. Full table:
  [`docs/SECRETS.md`](./SECRETS.md#monitoring).
- **Related Origin Requests (ROR):** share passkeys across multiple app origins under one `RP_ID` via
  `GET /.well-known/webauthn` and the admin ROR endpoints — see [`README-ROR.md`](../README-ROR.md).

---

## 7. Part E — Production checklist

- [ ] **Secrets** in a secret manager, referenced via Helm `secrets.existingSecret` — never inline.
      Deployer key is ephemeral (one-shot Job only).
- [ ] **`RP_ID` chosen deliberately** — it is irreversible; passkeys bind to it forever.
- [ ] **Registration closed** (`OPEN_REGISTRATION=false`) with `ADMIN_API_KEYS` set; your backend
      calls `/v1/webauthn/options` server-to-server.
- [ ] **UserOp policy** tuned: gas caps (`USEROP_MAX_*`), `USEROP_ALLOWED_TARGETS`,
      `USEROP_ALLOWED_PAYMASTERS` pinned to your own paymaster.
- [ ] **Origins locked down:** `EXPECTED_ORIGINS` and `GIANO_ALLOWED_DAPP_ORIGINS` to your real
      hosts; `CORS_ORIGINS` to just your dApp origins. dApp does **not** send `COOP: same-origin`.
- [ ] **TLS** on both the wallet host and the dApp host.
- [ ] **Bundler executor funded and monitored** (alert on low balance); paymaster deposit funded.
- [ ] **Validate the full create → sign → submit flow against your chosen bundler on the target
      chain** — self-hosted bundler compatibility on public networks should be confirmed per chain.
- [ ] **`giano-doctor chain` passes** against the production RPC.
- [ ] **Upgrade order** understood: wallet-api (with migrations) → wallet-web → dApp SDK; roll back in
      reverse; never run web/SDK newer than the wallet-api. See [`COMPATIBILITY.md`](../COMPATIBILITY.md).
- [ ] **Rotate** the committed demo bundler keys (repo-history task).

---

## 8. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `heap out of memory` on build | `NODE_OPTIONS='--max-old-space-size=16384' pnpm build` |
| Popup never opens / `POPUP_BLOCKED` | call wallet methods from a user gesture; remove `COOP: same-origin` from the dApp (use `same-origin-allow-popups`) |
| Handshake times out | dApp COOP severed `window.opener`; or the wallet origin isn't allow-listing the dApp origin (`GIANO_ALLOWED_DAPP_ORIGINS`) |
| wallet-api won't boot: `RP_ID … not valid for expected origin` | every `EXPECTED_ORIGINS` host must equal `RP_ID` or be a subdomain of it |
| wallet-api won't boot: `chain … not in the registry` | set `ENTRYPOINT_ADDRESS` and `FACTORY_ADDRESS` explicitly |
| `giano-doctor` reports P-256 unavailable | deploy the verifier with `scripts/p256_deploy.ts` (chain has no RIP-7212 and no FCL verifier) |
| Sponsored tx never lands | check `giano-doctor chain` — paymaster deposit or executor balance likely low; check `giano_userop_policy_rejections_total` and `GET /v1/userops/:hash` |
| `pnpm doctor` prints "Unknown option: recursive" | use `pnpm run doctor` — `doctor` is a pnpm built-in |

---

## 9. Reference index

| Doc | Covers |
| --- | --- |
| [`README.md`](../README.md) | project overview, local dev options (A/B/C), running the tests |
| [`docs/INTEGRATION.md`](./INTEGRATION.md) | concise ops runbook: DNS/TLS, proxy rules, per-container env, upgrade |
| [`docs/SECRETS.md`](./SECRETS.md) | authoritative secrets inventory + monitoring/metrics |
| [`COMPATIBILITY.md`](../COMPATIBILITY.md) | single-version policy, upgrade order, compatibility guarantees |
| [`GIANO-VS-COINBASE.md`](../GIANO-VS-COINBASE.md) | why self-host vs. the Coinbase stack: lock-in, cost, chains |
| [`docs/PRODUCT-STRATEGY.md`](./PRODUCT-STRATEGY.md) | modularity seams, the bring-your-own-UI contract, phased roadmap |
| [`docs/COST-MODEL.md`](./COST-MODEL.md) | infrastructure + gas costs of running Giano as a service, and breakeven |
| [`docs/MULTI-TENANCY-GAPS.md`](./MULTI-TENANCY-GAPS.md) | what is missing to serve many clients from one instance, with bring-your-own wallet UI |
| [`packages/connector/README.md`](../packages/connector/README.md) | full SDK API + 0.x → 1.x (embedded) migration |
| [`deploy/sepolia/README.md`](../deploy/sepolia/README.md) | end-to-end real-chain deploy runbook (any EVM chain) |
| [`README-ROR.md`](../README-ROR.md) | Related Origin Requests (cross-origin passkeys) |
