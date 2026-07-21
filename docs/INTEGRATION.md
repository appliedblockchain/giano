# Integrating Giano

Giano ships as versioned artifacts you deploy into **your own** stack — it is never
centrally hosted. A complete integration is:

1. A **wallet origin** (`wallet.yourapp.com`) served by `giano-wallet-web`, fronting
   `giano-wallet-api` (+ Postgres, + a bundler).
2. Your dApp depending only on the thin SDK `@appliedblockchain/giano-connector` and the
   wallet URL.

Your dApp bundle contains no WebAuthn, credential, signing or bundler code — all wallet
trust lives on the wallet origin.

## 1. DNS & TLS

- Give the wallet its own host: `wallet.yourapp.com`. This host is the WebAuthn
  **Relying Party ID (`RP_ID`)** and is **irreversible** — passkeys bind to it. Choose it
  before going to production.
- Terminate TLS at your ingress/proxy in front of `giano-wallet-web` (the container
  listens on `:8080`). WebAuthn requires a secure context.
- The dApp lives on a separate origin (`app.yourapp.com`); the two communicate only via
  the popup postMessage transport.

## 2. Proxy rules (handled by the wallet-web image)

`giano-wallet-web`'s nginx already:

- serves the SPA and `GET /config.json` (runtime config, injected at container start);
- proxies `/api/*` → `giano-wallet-api` (same-origin: no CORS, no third-party cookies);
- proxies `GET /.well-known/webauthn` → wallet-api (Related Origin Requests);
- optionally proxies `/rpc` and `/bundler` to a non-CORS node/bundler
  (`GIANO_RPC_UPSTREAM` / `GIANO_BUNDLER_UPSTREAM`);
- sets `frame-ancestors 'none'` + `X-Frame-Options: DENY` (popup-only) and a CSP whose
  `connect-src` includes your rpc/bundler.

### COOP caveat (dApp side)

Do **not** send `Cross-Origin-Opener-Policy: same-origin` from the dApp — it severs
`window.opener` and the wallet handshake times out. Use `same-origin-allow-popups` (or no
COOP header). Call `connect()` from a user gesture so the popup is not blocked.

## 3. Environment per container

- **wallet-api** — see `services/wallet-api/README.md` and
  `deploy/docker-compose.reference.yml` for the full env matrix. Key values: `DATABASE_URL`,
  `RP_ID`/`EXPECTED_ORIGINS`, `CHAIN_ID`/`RPC_URL`/`BUNDLER_URL`, `OPEN_REGISTRATION=false`
  + `ADMIN_API_KEYS`, userop policy caps, `CORS_ORIGINS` (your dApp origins, for the
  public receipt endpoint).
- **wallet-web** — `GIANO_CHAIN_ID`, `GIANO_RPC_URL`, `GIANO_BUNDLER_URL`,
  `GIANO_WALLET_API_UPSTREAM`, `GIANO_RP_ID`, `GIANO_ALLOWED_DAPP_ORIGINS` (JSON array),
  `GIANO_FACTORY_ADDRESS`/`GIANO_PAYMASTER_ADDRESS` (default from the contracts registry).
- **bundler** (optional in-stack) — `ALTO_RPC_URL`, `ALTO_EXECUTOR_PRIVATE_KEYS` (from a
  secret), `ALTO_SAFE_MODE=true`.

`ENTRYPOINT_ADDRESS`/`FACTORY_ADDRESS` default from
`@appliedblockchain/giano-contracts` for known chains; set them explicitly for others.

## 4. Database

External Postgres by default. Apply migrations either with `RUN_MIGRATIONS=true` on the
wallet-api, or the one-shot `node dist/migrate.js` (the Helm chart runs it as a
pre-install/upgrade hook Job). Migrations are backward-compatible across one minor.

## 5. Contracts

Use the published `giano-contracts` deployments for supported chains. To deploy to a new
chain, run the `giano-contracts-deployer` one-shot (compose `profiles: [deploy]` or the
Helm pre-install hook) with `RPC_URL`, `CHAIN_ID`, `DEPLOYER_PRIVATE_KEY` — it does a
CREATE2 deploy (identical addresses across chains for identical bytecode) and emits
`giano-addresses.<chainId>.json`.

## 6. Health checks

- wallet-api: `GET /healthz` (liveness), `GET /readyz` (DB ping), `GET /v1/version`.
- wallet-web: `GET /` (nginx).
- bundler: `eth_supportedEntryPoints`.

## 7. SDK snippet (dApp)

```ts
import { createGianoWalletProvider, createGianoConnector } from '@appliedblockchain/giano-connector';
import { baseSepolia } from 'wagmi/chains';

const provider = createGianoWalletProvider({ walletUrl: 'https://wallet.yourapp.com', chain: baseSepolia });
const connector = createGianoConnector({ provider });
// use `connector` with wagmi, or `giano({ provider })` with RainbowKit
```

See `packages/connector/README.md` for the full API and the 0.x → 1.x migration guide.

## 8. Upgrade runbook

All artifacts share one version (Changesets fixed mode). Upgrade order: **wallet-api
(with migrations) → wallet-web → dApp SDK**; roll back in reverse. Never run web/SDK newer
than the wallet-api. Full policy: `COMPATIBILITY.md`.

## Quick start (local)

```bash
# full local stack: devnet + bundler + wallet-api + wallet-web
docker compose -f deploy/docker-compose.dev.yml up --build
# or the pre-baked E2E stack (instant-boot devnet):
docker compose -f deploy/docker-compose.e2e.yml up --build
```
