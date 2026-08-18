# Giano Developer Guide

**Everything you need to adopt Giano in a new project** — integrate a dApp, stand up the wallet
stack on any EVM chain, verify it on-chain, and run it in production. This is the entry point;
deeper reference material is linked at the end.

Giano is a self-hosted **passkey (WebAuthn / secp256r1) ERC-4337 smart-contract wallet**, forked
from the Coinbase Smart Wallet. The backend is **multi-tenant**: one wallet-api instance (one
Postgres, one bundler, one chain) serves one or many client projects. Every tenant owns its own
**wallet origin**, and that origin's host is the tenant's WebAuthn RP ID — the browser itself
refuses to surrender one tenant's passkeys to another's origin. A tenant's origin may serve
Giano's stock wallet-web UI **or a UI the tenant built itself** ("bring your own UI" — same
architecture, only the SPA's authorship differs; see
[§5.5b](#55b-bring-your-own-wallet-ui-per-tenant)). Whether you run a single-tenant stack for
your own project or one instance for many clients, the deployment shape is identical — the
tenants are just rows seeded from `TENANTS_SEED`. A dApp integrates only the thin
`@appliedblockchain/giano-connector` SDK plus its tenant's wallet URL; all wallet trust
(passkeys, signing, consent, bundler) lives on the wallet origin.

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
2. **The wallet origin** (`wallet.yourapp.com`) — the tenant-owned origin serving a wallet UI
   (Giano's stock wallet-web, or one you built), fronting the shared backend: wallet-api
   (+ Postgres) and an ERC-4337 bundler, all pointed at an EVM chain where the Giano contracts
   are deployed.

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

**Tenancy:** tenant ≡ wallet origin ≡ RP ID, one to one. wallet-api resolves the tenant of every
ceremony request from its `Origin` header (authoritative — WebAuthn independently verifies the
ceremony ran on that origin), of `/.well-known/webauthn` from the `Host` header, of bearer routes
from the session, and of admin routes from the per-tenant admin key. All tenants share the chain,
EntryPoint, factory and bundler; users, credentials, challenges, sessions, policy and quotas are
isolated per tenant, and cross-tenant use is both structurally impossible at the credential layer
(distinct RP IDs) and rejected + alerted server-side.

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
compose files or `values.yaml`. The table below is the inventory; the metrics that tell you when
one of them is failing are in §6.

| Secret | Held by | Purpose | Funded? |
| --- | --- | --- | --- |
| `DEPLOYER_PRIVATE_KEY` | contracts-deployer (one-shot) | deploys contracts + seeds the paymaster deposit on a new chain | **yes** — ~0.1 test ETH; ephemeral, never mount into long-running pods |
| `ALTO_EXECUTOR_PRIVATE_KEY(S)` | bundler | signs **and pays gas** for every bundle on-chain (reimbursed by the paymaster, but fronts the ETH) | **yes** — keep topped up (~0.05+); must differ from the deployer |
| `ALTO_UTILITY_PRIVATE_KEY` | bundler | Alto nonce/gas-price management | no — any throwaway key |
| `DATABASE_URL` | wallet-api, migrate job | Postgres DSN (credentials, sessions, audit) | n/a |
| tenant `adminKeys` (in `TENANTS_SEED`) | wallet-api | per-tenant server-to-server ceremony options + ROR admin (required unless the tenant sets `openRegistration: true`); stored sha256-hashed | n/a |
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
| **wallet-api** | `ghcr.io/appliedblockchain/giano-wallet-api` (Fastify) | 8080 | **yes** — multi-tenant: WebAuthn ceremonies, sessions, policied userop relay for every tenant |
| **wallet-web** | `ghcr.io/appliedblockchain/giano-wallet-web` (nginx + React) | 8080 | one **per tenant on the stock UI** — the passkey popup origin; each needs its own TLS host (= that tenant's irreversible RP ID). Tenants bringing their own UI deploy their own SPA instead (reference: `e2e/wallet-byo/`) |
| **ERC-4337 bundler** | `ghcr.io/appliedblockchain/giano-bundler` (Pimlico Alto) | 4337 | **yes** — needs a funded executor EOA; any ERC-4337 bundler works |
| **EVM RPC** | public or your own node | — | **yes** — a keyless public endpoint works with Alto `--safe-mode false` |
| **Deployed contracts** | factory + implementation (+ paymaster/test-ERC20 for demos) | — | **yes** — pre-deployed on chains 8453 / 84532 / 381185; deploy per-chain elsewhere |

---

## 3. Part A — Run the whole thing locally in 5 minutes

The E2E compose stack boots the **entire system** with contracts pre-baked into an instant-boot
anvil devnet — nothing to deploy by hand. It seeds **two tenants** against the one shared
backend, so it doubles as a working multi-tenancy demo: tenant `stock` serves Giano's stock
wallet-web UI, tenant `byo` serves an independently built ("bring your own") wallet UI.

```sh
pnpm install
docker compose -f deploy/docker-compose.e2e.yml up --build

# publish the stack under its names (once per boot — port 80 needs sudo)
sudo pnpm -F @appliedblockchain/giano-e2e portless:proxy
pnpm -F @appliedblockchain/giano-e2e portless:up
```

Nothing here is addressed by port. [portless](https://github.com/vercel-labs/portless) runs a
local proxy on port 80 that maps each name below to the loopback port behind it. The table of
names lives in `e2e/origins.mjs`, and everything else — the fixtures, the tenant seed in
`deploy/docker-compose.e2e.yml`, the Playwright suite — reads its origins from there, so there
is one place to change and nowhere for a stale port to hide. `portless:up` registers the
routes and refuses to return until they answer; `portless:down` removes them again.

| Service | URL | Notes |
| --- | --- | --- |
| devnet (anvil) | http://rpc.localhost | chain 31337, contracts pre-deployed |
| bundler (alto) | http://bundler.localhost | EntryPoint v0.7 |
| wallet-web (tenant `stock`) | http://wallet.localhost | Giano's stock wallet UI (open directly for the Settings view) |
| wallet-api | http://api.localhost | shared multi-tenant backend (also reached via each wallet origin's `/api` proxy) |

`*.localhost` resolves to `127.0.0.1` automatically. Run the sample thin-SDK dApp against
tenant `stock`:

```sh
pnpm --filter @appliedblockchain/giano-e2e dapp        # http://app.localhost
```

Open **http://app.localhost**, create a passkey wallet, connect, and send a sponsored
transaction.

To exercise the second tenant — the **BYO wallet UI** (`e2e/wallet-byo/`, a framework-free SPA
built only on `giano-wallet-core` + `giano-wallet-transport`, and the reference implementation
for tenants bringing their own UI):

```sh
pnpm --filter @appliedblockchain/giano-e2e wallet-byo                             # http://wallet-byo.localhost
DAPP_PORT=4401 WALLET_URL=http://wallet-byo.localhost \
  pnpm --filter @appliedblockchain/giano-e2e dapp                                 # http://app-byo.localhost
```

`DAPP_PORT` picks which loopback port the fixture listens on, and therefore which name serves
it: 4401 is the target of `app-byo.localhost` (see `e2e/origins.mjs`).

Open **http://app-byo.localhost** and repeat the flow — same backend, different wallet
origin, different UI, cryptographically separate passkeys. For a richer dApp on the `stock`
tenant (wallet basics + an ERC-20 panel), run the Chakra sample instead: `pnpm demo:dev` (also
`http://app.localhost`). Tear down with `docker compose -f deploy/docker-compose.e2e.yml down`
and `pnpm -F @appliedblockchain/giano-e2e portless:down`.

Confirm the deployment on-chain any time:

```sh
pnpm run doctor chain --rpc http://rpc.localhost --chain-id 31337 \
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
| `TENANTS_SEED` | ✓ (in practice) | JSON array of tenants, upserted by slug at boot. Per tenant: `walletOrigin` (its host is the **irreversible** RP ID), `rpName`, `expectedOrigins` (**every host must equal the rpId or be a subdomain** — validated on write), `allowedDappOrigins`, `corsOrigins` (dApp origins that poll the public receipt endpoint cross-origin), `openRegistration` (`false` ⇒ registration gated by the tenant's `adminKeys`), `adminKeys` (secrets; stored sha256-hashed), `policy` (per-tenant `USEROP_*` overrides) |
| `CHAIN_ID`, `RPC_URL`, `BUNDLER_URL` | ✓ | chain wiring (one chain for all tenants) |
| `ENTRYPOINT_ADDRESS`, `FACTORY_ADDRESS` | conditional | default from the registry; **required when `CHAIN_ID` is not in the registry** |
| `USEROP_MAX_*`, `USEROP_ALLOWED_TARGETS`, `USEROP_ALLOWED_PAYMASTERS`, `USEROP_RATE_LIMIT_PER_MINUTE` | — | relay policy **defaults** — each tenant's `policy` jsonb overrides per field (gas as integers, fees in wei) |
| `CHALLENGE_TTL_SECONDS`, `SESSION_TTL_SECONDS`, `CEREMONY_RATE_LIMIT_PER_MINUTE`, `METRICS_BEARER_TOKEN` | — | TTLs / rate limit / metrics auth |

**Onboarding a tenant** is declarative: append an entry to `TENANTS_SEED` and restart — the seed
upserts by `slug` and validates the RP/origin invariants before touching the database. `rpId` is
immutable per tenant (the seeder refuses to change it); everything else (origins, registration
mode, admin keys, policy) is updated in place. Removing an entry does **not** delete the tenant's
data. DNS/TLS for the tenant's wallet host is yours to provision (see
[`INTEGRATION.md` §1](./INTEGRATION.md#1-dns--tls) for the DNS, TLS and edge-route requirements —
one set per tenant, because the wallet host is that tenant's RP ID).

### 5.5 wallet-web environment

wallet-web's nginx serves the SPA + `GET /config.json` and same-origin-proxies `/api` and
`/.well-known/webauthn` → wallet-api (and optionally `/rpc`, `/bundler` → your node/bundler to avoid
CORS). Env: `GIANO_CHAIN_ID`, `GIANO_RPC_URL`, `GIANO_BUNDLER_URL`, `GIANO_WALLET_API_UPSTREAM`,
`GIANO_RP_ID`, `GIANO_ALLOWED_DAPP_ORIGINS` (JSON array), `GIANO_FACTORY_ADDRESS` /
`GIANO_PAYMASTER_ADDRESS` (default from the registry), `GIANO_BRAND_NAME`.

- Give each tenant's wallet its **own TLS host** — that host is the tenant's RP ID and must match
  the tenant's `walletOrigin` in `TENANTS_SEED`. WebAuthn requires a secure context.
- The browser reads chain state directly from `GIANO_RPC_URL`, so it must be CORS-enabled and safe to
  expose (keyless public endpoint, or the bundler proxied same-origin).
- **One wallet-web container per tenant** on the stock UI: `envsubst` renders each container's
  `/config.json`, CSP and dApp allowlist at boot, so per-tenant isolation needs no code — just
  per-tenant env.

### 5.5b Bring-your-own wallet UI (per tenant)

A tenant may serve its **own** SPA at its wallet origin instead of wallet-web — the RP ID doesn't
change, so existing passkeys keep working. A BYO UI builds on the same two packages wallet-web
uses (`@appliedblockchain/giano-wallet-core` for the provider + wallet-api injection,
`@appliedblockchain/giano-wallet-transport` for the popup host) and must reproduce:

- the runtime wiring — `createWalletApiInjection` → `createGianoProvider` (**keep real
  `estimateFeesPerGas`**; the 200-gwei fallback trips `AA31` on low-fee chains) → `TransportHost`
  with a **non-empty, fail-closed `allowedOrigins`**;
- the consent gate: `eth_requestAccounts` + every signing/tx method behind an explicit user
  approval screen that displays the pinned dApp origin, with the silent `giano_restoreAccount`
  session restore on fresh popups;
- the serving contract: same-origin `/api` (and `/.well-known/webauthn`) proxy to wallet-api that
  **forwards `Origin` untouched and preserves the browser's `Host`** (tenant resolution depends on
  both), `frame-ancestors 'none'`, popup-only, TLS.

The complete working reference is **`e2e/wallet-byo/`** (~400 lines, framework-free, exercised in
CI end-to-end), with the serving contract in its `serve.mjs`.

### 5.6 Gas sponsorship (paymaster)

Two paymasters ship, and which one a deployment uses is a deliberate choice rather than a default:

| | `PermissivePaymaster` | `GianoPaymaster` |
| --- | --- | --- |
| Purpose | Test fixture — keeps sponsored-path tests simple | Real sponsorship, rule-enforced, billed |
| Decides anything | No, approves everything | Yes, per tenant, per transaction |
| Whose money | Whoever funded it | The tenant's own segregated balance |
| Charges a fee | No | Yes, a fixed fee per operation |
| Where it runs | Local development, test runs | Every real deployment |
| Configuration needed | None | Balance, allowlist, cost cap |

The permissive one exists so that a test whose subject is a token transfer does not need a funded
balance and a configured allowlist. It is refused in production three ways: it compiles from a
source root the published artifacts exclude, the address registry keeps it in a different field
(`testPaymaster`, not `sponsorshipPaymaster`) so no consumer can pass one where the other is meant,
and both `wallet-api` and `wallet-web` refuse to start with it configured under a production build.

#### How production sponsorship works

A tenant funds **its own** gas balance. When a user is about to transact, `wallet-api` checks the
operation against that tenant's rules and available balance; if both pass it signs an authorisation
the paymaster contract verifies **on chain**. No signature, no sponsorship — so a client that skips
Giano's backend entirely still cannot obtain it. Each operation debits the tenant for the gas it
consumed, plus a fixed platform fee credited to Giano, plus an overhead allowance covering network
costs the contract cannot observe at settlement.

The full design is in [`PAYMASTER-REQUIREMENTS.md`](./PAYMASTER-REQUIREMENTS.md) and
[`PAYMASTER-SPECS.md`](./PAYMASTER-SPECS.md). What follows is the runbook.

#### Deploying it

```sh
# 1. Deploy the implementation, the deployer helper and the proxy (initialised in one transaction).
#    `roleAdmin` should be the TimelockController, not an operational key — see below.
cd packages/contracts
pnpm hh:deploy:paymaster --network <network> \
  --parameters '{"GianoPaymaster":{"roleAdmin":"0x<timelock>","defaultFeeWei":"100000000000000"}}'

# 2. Grant roles, authorise the signing key, stake, register and fund tenants.
#    On a real deployment every grant goes through the timelock; this script is for a devnet or a
#    first-run testnet, where one account legitimately holds ROLE_ADMIN.
RPC_URL=<url> DEPLOYER_PRIVATE_KEY=0x... pnpm provision:paymaster -- \
  --signer 0x<sponsorship-signer> \
  --stake-eth 1 --unstake-delay 86400 \
  --tenant <tenant-uuid>:<withdraw-address>:<slug>:<fund-eth>

# 3. Verify the whole topology before pointing anything at it.
pnpm run doctor chain --rpc <url> --chain-id <id> \
  --sponsorship-paymaster 0x... --tenants <uuid>,<uuid> \
  --role-admin 0x<timelock> --signers 0x<signer>

# 4. Prove the service and the contract agree about the authorisation format. Worth running after
#    every deploy, every implementation upgrade and every key rotation — a byte-offset or
#    field-order mismatch between them is invisible until a tenant has funded a balance.
RPC_URL=<url> SPONSORSHIP_PAYMASTER_ADDRESS=0x... PAYMASTER_TENANT_ID=<uuid> \
  SPONSORSHIP_SIGNER_KEY_REF=0x... \
  pnpm --filter @appliedblockchain/giano-wallet-api verify:authorisation
```

A deployment is **not complete** until the paymaster is staked and at least one tenant balance is
funded. An unstaked validating paymaster is rejected by bundlers, which surfaces as something that
looks like a client bug; `giano-doctor chain` fails the exit code on both conditions rather than
warning, so it can gate a rollout.

#### `wallet-api` configuration

| Variable | Purpose |
| --- | --- |
| `SPONSORSHIP_ENABLED` | Master switch. Off means the sponsorship routes 404 and nothing is signed |
| `SPONSORSHIP_PAYMASTER_ADDRESS` | The production paymaster; defaults from the registry for known chains |
| `GIANO_DEPLOYMENT_CLASS` | `development` \| `testnet` \| `production`. **Required, no default** — it is what gates the signer below. Not `NODE_ENV`: a testnet deployment runs as a production build, and testnet is where a local key is allowed |
| `SPONSORSHIP_SIGNER_KIND` | `hsm` \| `local` — **`local` is refused when `GIANO_DEPLOYMENT_CLASS=production`** |
| `SPONSORSHIP_SIGNER_KEY_REF` | The HSM key resource name, or (development and testnet only) a 32-byte hex key |
| `SPONSORSHIP_WALLET_MANAGEMENT_CAP_WEI` | Platform cap on one wallet-management operation. Wallet management is sponsored whatever a tenant's allowlist says, so this is the bound on the one spend path a tenant cannot close. Tenants may lower it for themselves, never raise it |
| `SPONSORSHIP_VALIDITY_SECONDS` | `validUntil` window. Minutes, not hours |
| `SPONSORSHIP_RESERVATION_TTL_SECONDS` | Must exceed the validity window |
| `SPONSORSHIP_RATE_LIMIT_PER_MINUTE` | Per tenant; its own budget so pre-flight traffic cannot hammer the signer |
| `SPONSORSHIP_EMERGENCY_STOP` | Stops issuance immediately, without a restart |
| `PAYMASTER_WATCHER_ENABLED`, `..._POLL_MS`, `..._CONFIRMATIONS` | Event ingestion and settlement |
| `PAYMASTER_RECONCILE_INTERVAL_MS` | How often the accounting invariant is checked |
| `PAYMASTER_LOW_BALANCE_DEFAULT_WEI` | Alert threshold for tenants that set none |

The fee, the overhead allowance, the penalty rate, the signer set, the pause state and tenant
registration are deliberately **not** here. They are on-chain state, changed through the contract's
roles — which is what makes them auditable by a tenant rather than something they have to take
Giano's word for.

`wallet-web` takes `GIANO_SPONSORSHIP_MODE` (`service` | `test-paymaster` | `off`) and
`GIANO_PAYMASTER_SERVICE_URL`. `GIANO_PAYMASTER_ADDRESS` keeps its old meaning: the permissive
paymaster, dev path only.

#### Who holds what (and why it is split)

The contract has **no owner and no superuser**. Each privileged action has its own role:

| Role | May do | Notably may **not** |
| --- | --- | --- |
| `SIGNER_ADMIN_ROLE` | Add and revoke sponsorship signing keys | Move any funds |
| `FEE_ADMIN_ROLE` | Set the fee and per-tenant overrides | Collect the fees it sets |
| `FEE_COLLECTOR_ROLE` | Withdraw accrued treasury, capped at what accrued | Change the rate; touch tenant balances |
| `STAKE_ADMIN_ROLE` | Add, unlock and withdraw the stake | Touch the deposit or any balance |
| `TENANT_ADMIN_ROLE` | Register tenants and their withdrawal addresses | Move a registered tenant's funds |
| `PARAM_ADMIN_ROLE` | Set the overhead allowance and limits | Move funds |
| `PAUSER_ROLE` | Halt new sponsorships | Move funds; alter configuration |
| `UPGRADER_ROLE` | Replace the implementation | — (see the custody note below) |
| `ROLE_ADMIN` | Grant and revoke every role above, including itself | — |

Role separation is only real if whoever administers roles cannot grant themselves the role they are
separated from. So `ROLE_ADMIN` is held by **one** address — an OpenZeppelin `TimelockController`
whose proposers are a Safe — and `DEFAULT_ADMIN_ROLE` is never granted at all. Every grant is then
queued publicly and executable only after the delay.

**Review this on-chain, periodically, not on paper.** `giano-doctor chain --role-admin <timelock>
--signers <keys>` asserts that `ROLE_ADMIN` and `UPGRADER_ROLE` are held by the timelock and by
nothing else, that nobody holds `DEFAULT_ADMIN_ROLE`, and that the live signer set is exactly what
you expect. A role separation that exists in a document and not on chain is worse than none,
because it is relied upon.

#### Routine operations

**Rotate the signing key** — no downtime, no redeployment. Both keys are valid in the middle:

```sh
# 1. Add the new key on chain (SIGNER_ADMIN_ROLE, through the timelock).
# 2. Point the service at the new key: SPONSORSHIP_SIGNER_KEY_REF=<new>, restart or roll.
# 3. Verify the new key is accepted, then revoke the old one.
pnpm --filter @appliedblockchain/giano-wallet-api verify:authorisation   # with the new key
# 4. removeSigner(<old>) — again through the timelock.
```

**Stop sponsorship immediately.** Two independent levers, and they stop different things:

| Lever | Stops | Does not stop |
| --- | --- | --- |
| `SPONSORSHIP_EMERGENCY_STOP=true` | This service issuing new authorisations | An authorisation already issued, or a leaked key |
| `pause()` on the contract (`PAUSER_ROLE`) | Every sponsorship, including from a leaked key | Tenant withdrawal — deliberately |

Reach for the config switch first (it is instant and needs no signature) and `pause()` when a key
may be compromised. Neither traps tenant funds: withdrawal stays open through both, because a pause
is for halting sponsorship and must never become a freeze.

**Change the fee.** `setDefaultFee` for the deployment, `setTenantFee` for one tenant, both
`FEE_ADMIN_ROLE`. The rate in force is pinned into each authorisation, so a change cannot alter what
an already-authorised operation charges — in either direction.

**Withdraw the treasury.** `withdrawFees(to, amount)`, `FEE_COLLECTOR_ROLE`, capped at what has
accrued. That cap is what keeps the withdrawal path away from tenant balances: they share one
EntryPoint deposit, so without it this function would reach customer money.

**The unstaking delay.** `unlockStake()` starts it and blocks new sponsorship acceptance by bundlers
once the stake is unlocked; `withdrawStake(to)` only works after the delay elapses. Plan a paymaster
retirement around it rather than discovering it.

**Clock synchronisation is a deployment requirement.** `validUntil` / `validAfter` are absolute
seconds compared against block timestamps. A signing host whose clock drifts issues authorisations
that are already expired or not yet valid, and the symptom is an unexplained `AA32`-shaped failure
that looks nothing like a clock problem. Run NTP and alert on drift.

#### Monitoring

| Metric | Alert on |
| --- | --- |
| `giano_paymaster_invariant_breach` | **1 — page immediately.** Claims exceed the deposit: this is an insolvency |
| `giano_paymaster_invariant_slack_wei` | Growing faster than the overhead model predicts — tenants are being overcharged |
| `giano_tenant_deficit_wei` | Any non-zero value: the pooled deposit absorbed a shortfall for one tenant |
| `giano_tenant_available_wei` | Below the tenant's threshold — tell the tenant *and* the operator |
| `giano_paymaster_reconciliation_divergence_wei` | Any positive value: an unexplained drawdown, the signature of a leaked signing key |
| `giano_sponsorship_decisions_total{outcome="refused"}` | A refusal-rate spike for one tenant, which usually means a rule change went wrong |
| `giano_sponsorship_signatures_total{key_id}` | Any signature from an unexpected `key_id`; signing stopping entirely |
| `giano_sponsorship_unavailable_total` | Signer, HSM or database failures — an outage, not a misconfiguration |
| `giano_paymaster_watcher_lag_blocks` | Watcher stalled: settlements queue and balances go stale |

The invariant is the one to understand: `Σ tenant balances + treasury ≤ deposit`. It is "at most"
deliberately — the overhead allowance over-charges slightly, so the ledger falls a little faster
than the deposit and the residue is unattributed slack. Slack is safe; a breach is not, because it
means one tenant's claim is payable only out of another's funds.

#### Custody: what Giano can and cannot do with tenant funds

State this to tenants plainly rather than letting the shorter version stand:

- **No role in the table above can move a tenant's balance** — individually or in combination. Only
  the tenant's own registered withdrawal address can, and it can do so even while the paymaster is
  paused.
- **The upgrade authority can.** An upgrade can replace the logic that enforces everything above,
  including the withdrawal restriction. This is a trust position, not a technical safeguard.
- **What constrains it:** `UPGRADER_ROLE` is held by the timelock, whose proposers are a Safe, so
  every upgrade is queued publicly and executable only after a published delay — long enough for a
  tenant that objects to withdraw its balance first. There is no bypass, including for changes
  presented as urgent.
- **A tenant that loses its withdrawal key strands that balance permanently**, because by design
  nobody else can move it. Rotation via `setTenantWithdrawAddress` (`TENANT_ADMIN_ROLE`) exists and
  should be used *before* a key is lost.

"Giano cannot take your funds" is therefore true of Giano's day-to-day operation and conditional on
the upgrade controls. Anything stronger would be a claim the architecture does not support.

#### Onboarding a tenant

1. Register the tenant in `TENANTS_SEED` with a **pinned `id`** — that UUID is what the paymaster
   keys the tenant's balance on, so a random one would leave every sponsorship refused as an unknown
   tenant.
2. `registerTenant(id, withdrawAddress, slug)` on chain (`TENANT_ADMIN_ROLE`). The withdrawal
   address is the tenant's, and only it can withdraw.
3. The tenant funds `depositFor(<id>)` on the paymaster. `GET /v1/admin/sponsorship/balance` returns
   the address and the exact call.
4. The tenant writes its rules through `PUT /v1/admin/sponsorship` with its own admin key. Until it
   does, it sponsors nothing — which is correct, and worth saying in the onboarding email so it does
   not read as "sponsorship is broken".
5. Verify: `giano-doctor chain --tenants <id>` and one real sponsored transaction.

### 5.7 Reference stacks

- `deploy/docker-compose.reference.yml` — the client-project template (postgres + wallet-api +
  wallet-web from published images) with a fully commented env matrix.
- `deploy/helm/giano` — Helm chart: wallet-api (+ migrations hook), wallet-web, optional bundler,
  contracts-deployer pre-install Job, ingress. Secrets come from `secrets.existingSecret` (a k8s
  Secret with at least `DATABASE_URL`, `TENANTS_SEED` (it carries tenant admin keys), and `ALTO_EXECUTOR_PRIVATE_KEYS` if the
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
  [--factory 0x..] [--sponsorship-paymaster 0x..] [--test-paymaster 0x..] \
  [--tenants <uuid,uuid>] [--role-admin 0x..] [--signers 0x..,0x..] [--executor 0x..]
```
Checks: RPC reachable and chain id matches; EntryPoint v0.7, factory, and implementation have code;
executor native balance (if given); and P-256 support (RIP-7212 precompile → FreshCryptoLib verifier
→ none).

For the **sponsorship paymaster** it additionally checks — failing the exit code, not warning —
that the proxy has code and its implementation matches the registry; that it is **staked** and its
deposit is above the low-water mark; that the accounting invariant holds and at least one listed
tenant is funded; that nobody holds `DEFAULT_ADMIN_ROLE` and that `ROLE_ADMIN` / `UPGRADER_ROLE` are
held by the expected timelock and nothing else; and that the live signer set is exactly the expected
keys. Pass `--tenants`, `--role-admin` and `--signers` to turn those from reports into assertions.
A permissive test paymaster found on a production chain is a failure.

Addresses default from flags → env (`FACTORY_ADDRESS`, `SPONSORSHIP_PAYMASTER_ADDRESS`,
`PAYMASTER_ADDRESS`, `ENTRYPOINT_ADDRESS`) → the contracts registry for known chains. Example
output:

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
- **Metrics:** wallet-api `GET /metrics` (Prometheus; bearer-gated when `METRICS_BEARER_TOKEN` is
  set — recommended, since per-tenant volumes are not public data). Every metric carries a
  `tenant` label (the slug): `giano_userop_relayed_total{status,tenant}`,
  `giano_userop_policy_rejections_total{rule,tenant}`, `giano_ceremony_failures_total{kind,tenant}`,
  `giano_userop_relay_seconds{tenant}`, and **`giano_cross_tenant_rejections_total{kind,tenant}`**
  (kind ∈ `credential|challenge|session`) — **alert on any increase**: it means RP resolution is
  broken or someone is probing across tenant boundaries. Other suggested alerts: policy-rejection
  spikes (probing), ceremony-failure spikes (broken RP config/attack), relay `failed` ratio, low
  bundler-executor balance.
- **Related Origin Requests (ROR):** share passkeys across multiple app origins under one tenant's
  RP ID via `GET /.well-known/webauthn` (Host-scoped — each wallet origin serves only its own
  tenant's document) and the tenant-scoped admin ROR endpoints — see
  [`README-ROR.md`](../README-ROR.md).

---

## 7. Part E — Production checklist

- [ ] **Secrets** in a secret manager, referenced via Helm `secrets.existingSecret` — never inline.
      Deployer key is ephemeral (one-shot Job only).
- [ ] **Each tenant's `walletOrigin` chosen deliberately** — its host is the RP ID, which is
      irreversible; passkeys bind to it forever.
- [ ] **Registration closed** (tenant `openRegistration: false`) with the tenant's `adminKeys`
      set; your backend calls `/v1/webauthn/options` server-to-server with the tenant's key.
- [ ] **UserOp policy** tuned: deployment defaults (`USEROP_MAX_*`, `USEROP_ALLOWED_TARGETS`,
      `USEROP_ALLOWED_PAYMASTERS`) plus per-tenant `policy` overrides; paymasters pinned per tenant.
- [ ] **Origins locked down:** each tenant's `expectedOrigins`, `allowedDappOrigins` /
      `GIANO_ALLOWED_DAPP_ORIGINS` and `corsOrigins` to its real hosts only. dApp does **not**
      send `COOP: same-origin`.
- [ ] **TLS** on both the wallet host and the dApp host.
- [ ] **Bundler executor funded and monitored** (alert on low balance); paymaster deposit funded.
- [ ] **`GIANO_DEPLOYMENT_CLASS=production`** set explicitly. It has no default on purpose: it is what
      refuses an environment-variable signing key, and a default that happened to be permissive is
      exactly how such a key reaches production.
- [ ] **Gas sponsorship** (if enabled): `SPONSORSHIP_SIGNER_KIND=hsm`, backed by an AWS HSM key through
      [`evm-hsm-signer`](https://github.com/appliedblockchain/evm-hsm-signer) — a local key is refused
      for a production deployment class, and this key authorises spending against customer funds.
- [ ] **`SPONSORSHIP_WALLET_MANAGEMENT_CAP_WEI` calibrated for this chain.** Wallet management is
      sponsored whatever a tenant lists, so this cap is what bounds it. Sized for a passkey addition
      at this chain's fee levels — too tight refuses account recovery, too loose leaves a tenant's one
      unclosable spend path unbounded.
- [ ] **`ROLE_ADMIN` and `UPGRADER_ROLE` held by the timelock and nothing else**, `DEFAULT_ADMIN_ROLE`
      held by nobody, verified on chain with `giano-doctor chain --role-admin`. Not on paper.
- [ ] **Paymaster staked** and at least one tenant balance funded — a deployment is not complete
      otherwise, and an unstaked validating paymaster fails in a way that looks like a client bug.
- [ ] **The overhead allowance calibrated for this chain** (`postOpGasAllowance`, `penaltyBps`),
      and the invariant slack watched afterwards: slack that grows too fast means tenants are being
      overcharged, and slack that shrinks means an unexplained drawdown.
- [ ] **`verify:authorisation` passes** against the deployed paymaster — after deploy, after every
      implementation upgrade and after every key rotation.
- [ ] **NTP on the signing hosts**, with drift alerting: a drifted clock issues authorisations that
      are already expired, and the symptom looks nothing like a clock problem.
- [ ] **The custody limits documented for tenants** — that no role can take their funds, that the
      upgrade authority can, and what constrains it. Tenants are trusting the upgrade process.
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
| wallet-api won't boot: `origin … is not valid for rpId` | every tenant `expectedOrigins` host must equal that tenant's rpId or be a subdomain of it (TENANTS_SEED) |
| ceremony calls return `403 unknown-tenant` | the request's `Origin` header matches no tenant's `walletOrigin`/`expectedOrigins` — check the seed |
| wallet-api won't boot: `chain … not in the registry` | set `ENTRYPOINT_ADDRESS` and `FACTORY_ADDRESS` explicitly |
| `giano-doctor` reports P-256 unavailable | deploy the verifier with `scripts/p256_deploy.ts` (chain has no RIP-7212 and no FCL verifier) |
| Sponsored tx never lands | check `giano-doctor chain` — paymaster deposit or executor balance likely low; check `giano_userop_policy_rejections_total` and `GET /v1/userops/:hash` |
| Wallet shows "this app does not cover fees for this contract" | the contract is not on that tenant's allowlist — `GET /v1/admin/sponsorship`, then `PUT` an updated `allowlist` |
| Every sponsorship refused as `sponsorship-disabled` | that tenant has no configuration, which is the correct default — it must `PUT /v1/admin/sponsorship` once |
| Every sponsorship refused as `insufficient-balance` on a funded tenant | the tenant's `TENANTS_SEED` `id` does not match the id it was registered under on chain, so the service is billing a tenant the contract has never heard of |
| Sponsorship refused as `tenant-in-deficit` | a settlement exceeded the balance; `depositFor` clears the deficit and unblocks the tenant. Investigate why — the reservation ledger should have prevented it |
| `AA34 signature error` on a sponsored op | the service and the contract disagree about the authorisation format, or the signing key is not in the on-chain signer set. Run `verify:authorisation` |
| `AA32 expired or not due` on a sponsored op | clock drift on the signing host, or a reservation TTL shorter than the validity window |
| Balances stay at zero after bring-up | the watcher is not running (`PAYMASTER_WATCHER_ENABLED`) — balances are reconciled from the contract on each pass |
| `giano_paymaster_invariant_breach 1` | **stop issuing sponsorships.** Claims exceed the deposit; this is an insolvency, not an accounting nit |
| `pnpm doctor` prints "Unknown option: recursive" | use `pnpm run doctor` — `doctor` is a pnpm built-in |

---

## 9. Reference index

| Doc | Covers |
| --- | --- |
| [`README.md`](../README.md) | project overview, local dev options (A/B/C), running the tests |
| [`INTEGRATION.md`](./INTEGRATION.md) | concise ops runbook: DNS/TLS, proxy rules, per-container env, upgrade |
| [`COMPATIBILITY.md`](../COMPATIBILITY.md) | single-version policy, upgrade order, compatibility guarantees |
| [`GIANO-VS-COINBASE.md`](../GIANO-VS-COINBASE.md) | why self-host vs. the Coinbase stack: lock-in, cost, chains |
| [`TRANSACTION-SUBMISSION-FLOW.md`](./TRANSACTION-SUBMISSION-FLOW.md) | one transfer traced end to end through the two-origin, multi-tenant stack |
| [`PAYMASTER-REQUIREMENTS.md`](./PAYMASTER-REQUIREMENTS.md) | gas sponsorship: what it must do and why the decisions were made |
| [`PAYMASTER-SPECS.md`](./PAYMASTER-SPECS.md) | gas sponsorship: the technical design — contract, service, ledger, watcher |
| [`packages/connector/README.md`](../packages/connector/README.md) | full SDK API + 0.x → 1.x (embedded) migration |
| [`deploy/sepolia/README.md`](../deploy/sepolia/README.md) | end-to-end real-chain deploy runbook (any EVM chain) |
| [`README-ROR.md`](../README-ROR.md) | Related Origin Requests (cross-origin passkeys) |
