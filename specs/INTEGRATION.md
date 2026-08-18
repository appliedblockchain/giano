# Integrating Giano

> This is the concise ops runbook. For a full, self-contained walkthrough (dApp SDK integration,
> new-chain stand-up, the `giano-doctor` verification CLI, and a production checklist) see
> [`DEVELOPER-GUIDE.md`](./DEVELOPER-GUIDE.md).

Giano ships as versioned artifacts deployed into a stack you (or your operator) run. The
backend is **multi-tenant**: one `giano-wallet-api` (+ Postgres + bundler) serves one or
many client projects, each as a tenant provisioned via `TENANTS_SEED`. A complete
integration is:

1. A **tenant-owned wallet origin** (`wallet.yourapp.com`) serving a wallet UI —
   `giano-wallet-web`, or a UI you built yourself (reference: `e2e/wallet-byo/`) —
   fronting the wallet-api.
2. Your dApp depending only on the thin SDK `@appliedblockchain/giano-connector` and the
   wallet URL.

Your dApp bundle contains no WebAuthn, credential, signing or bundler code — all wallet
trust lives on the wallet origin. Tenant isolation is anchored in the browser itself:
each tenant's wallet host is its own WebAuthn Relying Party, so passkeys cannot cross
tenants, and wallet-api tenant-scopes everything beneath that.

## 1. DNS & TLS

- Give each tenant's wallet its own host: `wallet.yourapp.com`. This host is the tenant's
  WebAuthn **Relying Party ID** and is **irreversible** — passkeys bind to it. Choose it
  before going to production; it must match the tenant's `walletOrigin` in `TENANTS_SEED`.
- Terminate TLS at your ingress/proxy in front of the wallet UI (the wallet-web container
  listens on `:8080`). WebAuthn requires a secure context.
- The dApp lives on a separate origin (`app.yourapp.com`); the two communicate only via
  the popup postMessage transport.
- Serving many tenants from one instance means one DNS record + TLS certificate + edge
  route **per tenant domain** — see `MULTI-TENANCY-GAPS.md` §4 for the custom-domain
  onboarding costs and limits.

## 2. Proxy rules (handled by the wallet-web image)

`giano-wallet-web`'s nginx already:

- serves the SPA and `GET /config.json` (runtime config, injected at container start);
- proxies `/api/*` → `giano-wallet-api` (same-origin: no CORS, no third-party cookies);
- proxies `GET /.well-known/webauthn` → wallet-api (Related Origin Requests);
- optionally proxies `/rpc` and `/bundler` to a non-CORS node/bundler
  (`GIANO_RPC_UPSTREAM` / `GIANO_BUNDLER_UPSTREAM`);
- sets `frame-ancestors 'none'` + `X-Frame-Options: DENY` (popup-only) and a CSP whose
  `connect-src` includes your rpc/bundler.

**Bring-your-own-UI tenants must reproduce this serving contract** in their own edge/proxy.
Two headers are load-bearing for tenant resolution: forward `Origin` untouched (ceremony
requests resolve their tenant by it) and preserve the browser's `Host` on
`/.well-known/webauthn` (resolved by Host). Reference proxy: `e2e/wallet-byo/serve.mjs`.

### COOP caveat (dApp side)

Do **not** send `Cross-Origin-Opener-Policy: same-origin` from the dApp — it severs
`window.opener` and the wallet handshake times out. Use `same-origin-allow-popups` (or no
COOP header). Call `connect()` from a user gesture so the popup is not blocked.

## 3. Environment per container

- **wallet-api** — see `services/wallet-api/README.md` and
  `deploy/docker-compose.reference.yml` for the full env matrix. Key values: `DATABASE_URL`,
  `CHAIN_ID`/`RPC_URL`/`BUNDLER_URL`, userop policy defaults, and `TENANTS_SEED` — a JSON
  array with one entry per tenant carrying its `walletOrigin` (host = RP ID), origins,
  `openRegistration`, `adminKeys` and `corsOrigins` (your dApp origins, for the public
  receipt endpoint).
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

## 6. Tenants

Tenant provisioning is declarative — no dashboard, no API. Append an entry to
`TENANTS_SEED` and restart wallet-api; entries upsert by `slug` and are validated before
touching the database (every `expectedOrigins` host must be at-or-under the tenant's
RP ID). The RP ID is immutable per tenant; origins, registration mode, admin keys and
policy update in place. Registration model per tenant: `openRegistration: true` for
demos, or `false` + the tenant's backend calling `POST /v1/webauthn/options`
server-to-server with one of its `adminKeys` bearers.

## 7. Health checks

- wallet-api: `GET /healthz` (liveness), `GET /readyz` (DB ping), `GET /v1/version`;
  `GET /metrics` (Prometheus, `tenant`-labelled; bearer-gated when `METRICS_BEARER_TOKEN`
  is set).
- wallet-web: `GET /` (nginx).
- bundler: `eth_supportedEntryPoints`.

## 8. SDK snippet (dApp)

```ts
import { createGianoWalletProvider, createGianoConnector } from '@appliedblockchain/giano-connector';
import { baseSepolia } from 'wagmi/chains';

const provider = createGianoWalletProvider({ walletUrl: 'https://wallet.yourapp.com', chain: baseSepolia });
const connector = createGianoConnector({ provider });
// use `connector` with wagmi, or `giano({ provider })` with RainbowKit
```

See `packages/connector/README.md` for the full API and the 0.x → 1.x migration guide.

## 9. Upgrade runbook

All artifacts share one version (Changesets fixed mode). Upgrade order: **wallet-api
(with migrations) → wallet-web → dApp SDK**; roll back in reverse. Never run web/SDK newer
than the wallet-api. Full policy: `COMPATIBILITY.md`.

## Quick start (local)

```bash
# pre-baked E2E stack (instant-boot devnet, contracts included) — seeds TWO tenants:
# "stock" (Giano's wallet-web at wallet.localhost:8081) and "byo" (bring-your-own UI,
# served host-side via `pnpm --filter @appliedblockchain/giano-e2e wallet-byo`)
docker compose -f deploy/docker-compose.e2e.yml up --build
# or the from-source dev stack (postgres + anvil + alto + wallet-api; run wallet-web
# separately with `pnpm --filter @appliedblockchain/giano-wallet-web dev`):
docker compose -f deploy/docker-compose.dev.yml up --build
```
