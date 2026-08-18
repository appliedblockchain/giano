# Giano architecture — two tenants on one backend

One `giano-wallet-api` (+ one Postgres, one bundler, one chain) serves many tenants.
**Tenant ≡ wallet origin ≡ WebAuthn RP ID**, one to one. Tenant A runs Giano's stock
`wallet-web` UI; tenant B brings its own wallet SPA (reference: `e2e/wallet-byo/`). The
deployment shape is identical — only the SPA's authorship differs.

Numbered edges are the **client integration touch points**, tabulated below the diagram.

```mermaid
flowchart TB
    %% ─────────────────────────── TENANT A (stock wallet-web) ───────────────────────────
    subgraph TA["TENANT A  ·  slug 'stock'  ·  RP ID = wallet.a.example"]
        direction TB
        subgraph TA_APP["dApp origin — app.a.example"]
            A_UI["dApp UI<br/>(wagmi / RainbowKit / raw)"]
            A_SDK["<b>@appliedblockchain/giano-connector</b><br/>thin EIP-1193 provider<br/><i>no WebAuthn · no keys · no bundler URL</i>"]
        end
        subgraph TA_WALLET["Wallet origin — wallet.a.example  (popup only)"]
            A_EDGE["<b>giano-wallet-web</b> — nginx<br/>SPA + GET /config.json<br/>proxies /api · /.well-known/webauthn · /rpc · /bundler"]
            A_SPA["React wallet SPA<br/>giano-wallet-core + giano-wallet-transport<br/>consent screen (pinned dApp origin)"]
        end
        A_PK(["Passkey A — platform authenticator<br/>secp256r1, bound to wallet.a.example"])
        A_BE["Tenant A backend<br/>(holds tenant adminKeys)"]
    end

    %% ─────────────────────────── TENANT B (bring-your-own UI) ──────────────────────────
    subgraph TB_["TENANT B  ·  slug 'byo'  ·  RP ID = wallet.b.example"]
        direction TB
        subgraph TB_APP["dApp origin — app.b.example"]
            B_UI["dApp UI"]
            B_SDK["<b>@appliedblockchain/giano-connector</b><br/>thin EIP-1193 provider"]
        end
        subgraph TB_WALLET["Wallet origin — wallet.b.example  (popup only)"]
            B_EDGE["Tenant-owned edge / proxy<br/><i>must forward Origin untouched<br/>and preserve browser Host</i>"]
            B_SPA["<b>BYO</b> wallet SPA (tenant-authored)<br/>giano-wallet-core + giano-wallet-transport<br/>own consent screen"]
        end
        B_PK(["Passkey B — platform authenticator<br/>secp256r1, bound to wallet.b.example"])
        B_BE["Tenant B backend<br/>(holds tenant adminKeys)"]
    end

    %% ─────────────────────────── SHARED BACKEND ────────────────────────────
    subgraph BE["SHARED BACKEND  ·  one instance, all tenants"]
        direction TB
        SEED[/"TENANTS_SEED (env, declarative)<br/>walletOrigin · rpId · expectedOrigins<br/>allowedDappOrigins · corsOrigins<br/>openRegistration · adminKeys · policy"/]
        API["<b>giano-wallet-api</b> (Fastify) — holds no private key<br/>/v1/webauthn · /v1/credentials · /v1/userops · /v1/admin<br/>/.well-known/webauthn · /healthz /readyz /metrics (tenant-labelled)<br/><b>tenant resolved from:</b> Origin (ceremony) · Host (ROR)<br/>session (bearer) · admin key (admin)<br/>UserOp policy gate + audit"]
        PG[("Postgres 17 — every row tenant-scoped<br/>users · credentials · challenges<br/>sessions · userop log · ROR origins")]
        BUNDLER["<b>ERC-4337 bundler</b> (Pimlico Alto)<br/>funded executor EOA<br/>signs + fronts gas for bundles"]
        SEED -.->|"upsert by slug at boot<br/>(rpId immutable)"| API
        API <--> PG
    end

    %% ─────────────────────────── CHAIN ────────────────────────────
    subgraph CHAIN["EVM CHAIN  ·  shared by all tenants"]
        direction TB
        RPCN["EVM RPC node"]
        EP["<b>EntryPoint v0.7</b><br/>0x0000000071727De22E5E9d8BAf0edAc6f37da032"]
        FAC["<b>GianoSmartWalletFactory</b><br/>CREATE2 — getAddress(owners, nonce)<br/>same address before/after deploy"]
        IMPL["GianoSmartWallet implementation<br/>MultiOwnable + WebAuthn"]
        P256{{"P-256 verification<br/>RIP-7212 precompile (0x100)<br/>↳ else FreshCryptoLib verifier"}}
        PM["Paymaster<br/>(VerifyingPaymaster in prod;<br/>PermissivePaymaster for testing)"]
        WA["Tenant A user accounts<br/>GianoSmartWallet proxies<br/>owner = passkey A pubkey"]
        WB["Tenant B user accounts<br/>GianoSmartWallet proxies<br/>owner = passkey B pubkey"]
        EP --> PM
        EP --> WA
        EP --> WB
        FAC -->|"clones"| IMPL
        FAC -.->|"deploys on first op"| WA
        FAC -.->|"deploys on first op"| WB
        WA --> P256
        WB --> P256
    end

    %% ─────────────────────────── TOUCH POINTS ────────────────────────────
    A_UI --- A_SDK
    B_UI --- B_SDK
    A_SDK ==>|"① popup postMessage JSON-RPC<br/>origin-pinned, user gesture"| A_EDGE
    B_SDK ==>|"① popup postMessage JSON-RPC"| B_EDGE
    A_EDGE --- A_SPA
    B_EDGE --- B_SPA

    A_SDK -->|"② reads (eth_call, eth_chainId)<br/>answered dApp-side"| RPCN
    B_SDK -->|"② reads answered dApp-side"| RPCN
    A_SDK -.->|"③ GET /api/v1/userops/:hash/receipt<br/>(CORS ← tenant corsOrigins)"| A_EDGE
    B_SDK -.->|"③ receipt polling"| B_EDGE

    A_SPA <-->|"④ navigator.credentials<br/>create / get"| A_PK
    B_SPA <-->|"④ navigator.credentials"| B_PK

    A_EDGE ==>|"⑤ /api → wallet-api (same-origin)<br/>⑥ /.well-known/webauthn (ROR, Host-scoped)"| API
    B_EDGE ==>|"⑤ /api → wallet-api<br/>⑥ /.well-known/webauthn"| API
    A_EDGE -->|"⑦ /bundler → estimate + prepare UserOp"| BUNDLER
    B_EDGE -->|"⑦ /bundler → estimate + prepare UserOp"| BUNDLER
    A_EDGE -->|"/rpc"| RPCN
    B_EDGE -->|"/rpc"| RPCN

    A_BE -.->|"⑧ POST /v1/webauthn/options<br/>server-to-server, Bearer adminKey<br/>(when openRegistration: false)"| API
    B_BE -.->|"⑧ gated registration + ROR admin"| API

    API ==>|"⑨ policied relay of the<br/><b>signed</b> UserOp"| BUNDLER
    API -->|"read-only chain reads"| RPCN
    BUNDLER ==>|"⑩ handleOps bundle"| EP

    %% ─────────────────────────── STYLING ────────────────────────────
    classDef dapp fill:#dbeafe,stroke:#2563eb,color:#1e3a5f
    classDef wallet fill:#dcfce7,stroke:#16a34a,color:#14532d
    classDef backend fill:#fef3c7,stroke:#d97706,color:#713f12
    classDef chain fill:#ede9fe,stroke:#7c3aed,color:#3b0764
    classDef key fill:#fee2e2,stroke:#dc2626,color:#7f1d1d
    class A_UI,A_SDK,B_UI,B_SDK dapp
    class A_EDGE,A_SPA,B_EDGE,B_SPA wallet
    class API,PG,BUNDLER,SEED,A_BE,B_BE backend
    class RPCN,EP,FAC,IMPL,PM,WA,WB,P256 chain
    class A_PK,B_PK key
```

## Client integration touch points

| # | Touch point | Who implements it | Notes |
| --- | --- | --- | --- |
| ① | Popup postMessage transport (dApp ⇄ wallet origin) | `giano-connector` (dApp) ⇄ `giano-wallet-transport` (wallet) | Must be called from a user gesture. dApp must **not** send `COOP: same-origin`; wallet allow-lists dApp origins (`GIANO_ALLOWED_DAPP_ORIGINS` / tenant `allowedDappOrigins`), fail-closed on empty. |
| ② | Read path, dApp-side | dApp `transport` option (viem) | `eth_call`/`eth_chainId`/… never open the popup. |
| ③ | `GET /api/v1/userops/:hash/receipt` | `waitForUserOperationReceipt` in the SDK | Public endpoint, CORS-gated by the tenant's `corsOrigins`. **The dApp never needs a bundler URL.** |
| ④ | WebAuthn ceremony | wallet SPA only | Passkey is non-extractable and bound to the wallet host = tenant RP ID. |
| ⑤ | Same-origin `/api` proxy → wallet-api | wallet-web's nginx, or the BYO tenant's edge | `Origin` must be forwarded untouched — ceremony tenant resolution depends on it. |
| ⑥ | `GET /.well-known/webauthn` (Related Origin Requests) | same proxy | Resolved by **`Host`** — the browser's Host must be preserved. |
| ⑦ | `/bundler` (estimate + prepare UserOp) | wallet SPA via same-origin proxy | Wallet-side only. Keep a **real `estimateFeesPerGas`** — the 200-gwei fallback trips `AA31` on low-fee chains. |
| ⑧ | `POST /v1/webauthn/options` server-to-server | the tenant's own backend | Required when the tenant sets `openRegistration: false`; authenticates with that tenant's `adminKeys`. |
| ⑨ | Signed-UserOp relay | wallet-api | Policy gate (`USEROP_MAX_*`, allowed targets/paymasters, rate limit) + audit log; EntryPoint address is server-configured, never taken from the request. |
| ⑩ | `handleOps` | bundler executor EOA | Funded; reimbursed by the paymaster deposit. |

## Isolation vs. sharing

**Isolated per tenant:** wallet origin + TLS host, RP ID and therefore all passkeys
(cross-tenant credential use is structurally impossible in the browser, and rejected +
alerted server-side via `giano_cross_tenant_rejections_total`), wallet UI and branding,
users, credentials, challenges, sessions, dApp allow-lists, admin keys, UserOp policy
overrides, quotas, and every metric label.

**Shared:** the wallet-api process, Postgres instance, bundler + executor EOA, chain,
EntryPoint, factory, implementation and paymaster — so all tenants' smart accounts are
plain `GianoSmartWallet` clones from the one factory.

## The same diagram in the E2E stack

`deploy/docker-compose.e2e.yml` boots exactly this topology with two seeded tenants:

| Diagram element | E2E stack |
| --- | --- |
| Tenant A wallet origin (stock UI) | `wallet-web` container → http://wallet.localhost:8081 |
| Tenant A dApp | `pnpm --filter @appliedblockchain/giano-e2e dapp` → http://app.localhost:4400 |
| Tenant B wallet origin (BYO UI) | `e2e/wallet-byo/serve.mjs` (host-side proxy + SPA) → http://wallet-byo.localhost:8082 |
| Tenant B dApp | `DAPP_PORT=4401 WALLET_URL=http://wallet-byo.localhost:8082 … dapp` → http://app-byo.localhost:4401 |
| Shared wallet-api + Postgres | `wallet-api` + `postgres` containers, `TENANTS_SEED` = `[stock, byo]` |
| Bundler | `alto` container → http://localhost:4337 |
| Chain + contracts | `anvil` with pre-baked state → http://localhost:8545 (chain 31337); addresses in `e2e/devnet/addresses.json` |

Coverage: `e2e/tests/wallet-flow.spec.ts` (tenant A), `byo-wallet.spec.ts` (tenant B),
`tenant-isolation.spec.ts` (cross-tenant rejection).
