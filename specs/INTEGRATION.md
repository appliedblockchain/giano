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
  route **per tenant domain**, provisioned as part of onboarding that tenant. That cost is
  linear in tenants and unavoidable: the wallet host *is* the tenant's RP ID, so tenants
  cannot share one.

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

## 7. Gas sponsorship

Optional, and off unless `SPONSORSHIP_ENABLED=true`. When it is on, a tenant funds **its own** gas
balance and pays Giano a fixed fee per sponsored transaction. This section is the tenant-facing
contract; the operator runbook is in
[`DEVELOPER-GUIDE.md` §5.6](./DEVELOPER-GUIDE.md#56-gas-sponsorship-paymaster).

### 7.1 What a tenant has to do

1. **Be registered on the paymaster.** Giano does this at onboarding, against the tenant's own
   withdrawal address. Only that address can ever withdraw the balance.
2. **Fund the balance.** `GET /v1/admin/sponsorship/balance` with the tenant's admin key returns the
   paymaster address and the exact call (`depositFor(<tenantId>)`). A bare transfer to the paymaster
   is rejected — funds must be attributable to one tenant, and a plain transfer carries no tenant.
3. **Say what to sponsor.** `PUT /v1/admin/sponsorship`. Until this is written the tenant sponsors
   nothing; that is the intended default, not a fault.

```json
{
  "enabled": true,
  "maxCostPerTxWei": "500000000000000000",
  "allowlist": [
    { "contract": "0xYourToken", "functions": ["transfer(address,uint256)"] },
    { "contract": "0xYourGame", "functions": "all" }
  ],
  "lowBalanceThresholdWei": "1000000000000000000"
}
```

There is deliberately no way to express "any contract". `functions: "all"` covers allowing a
contract without enumerating its ABI. Function signatures are normalised to selectors on write, so
either form works. An invalid rule set is rejected with per-path messages and **not stored** — it is
never interpreted permissively.

**Wallet management is sponsored, and you do not configure it.** Transactions the wallet makes to
itself — adding or removing a passkey, recovery — are covered under platform policy and a platform
cost cap, with no entry in your allowlist. They are detected structurally (a call from the wallet to
itself) rather than by a list of function names, so a self-administration function added to the
wallet later cannot slip out of that treatment.

This is deliberate, and it protects your users from your own configuration: adding a passkey on a
new device is exactly when a user holds no native token and has no way to obtain one, so a recovery
path that depended on you having listed something would break for the users who need it most.

You can adjust it in two ways, and neither is required:

```json
"walletManagement": { "enabled": true, "maxCostPerTxWei": "100000000000000000" }
```

`maxCostPerTxWei` here may only **lower** the platform cap — a higher value is rejected on write, not
silently clamped. `"enabled": false` switches sponsorship of wallet management off for your tenant
entirely; think carefully before using it, because your users then cannot add a passkey to a new
device without holding native token themselves.

### 7.2 The interface a bring-your-own wallet uses

`POST /v1/paymaster` speaks [ERC-7677](https://eips.ethereum.org/EIPS/eip-7677) — JSON-RPC 2.0 with
`pm_getPaymasterStubData` and `pm_getPaymasterData` — so standard wallet tooling works unmodified.
It is reached through the tenant's own edge, same-origin under `/api`, and needs no onboarding
change:

```ts
const paymaster = createErc7677PaymasterClient({
  url: '/api/v1/paymaster',
  chainId,
  getSessionToken: () => localStorage.getItem('giano:session-token'),
});
const bundler = createBundlerClient({ chain, transport, paymaster });
```

Requests carry the wallet session bearer. The tenant is taken from the session, never from the
request — so a session cannot be used to spend another tenant's balance — and the sender must be
that session's own wallet.

**Refusals are expected outcomes, not errors.** Each carries a stable `error.data.reason` your UI
should key off (never the message, which may be reworded):

| `reason` | Means | Retry? |
| --- | --- | --- |
| `sponsorship-disabled` | Off for this tenant | no |
| `no-sponsorship-config` | No rules configured, or they no longer validate | no |
| `contract-not-allowed` | The target is not allow-listed | no |
| `function-not-allowed` | The contract is allowed, this function is not | no |
| `wallet-management-not-sponsored` | A self-call, and you have set `walletManagement.enabled: false` | no |
| `cost-exceeds-cap` | Above the per-transaction cap | when fees fall |
| `insufficient-balance` | The tenant has no available balance | after funding |
| `tenant-in-deficit` | An overdraw must be settled first | after funding |
| `not-your-wallet` | The sender is not this session's wallet | no |
| `chain-or-entrypoint-mismatch` | Wrong chain or EntryPoint | no |
| `temporarily-unavailable` | The service could not be reached | **yes** |

`temporarily-unavailable` is separate from every rule refusal on purpose: the sponsorship service is
on the critical path for transacting, and an outage must not be mistaken for a misconfiguration.

**Your wallet UI must check before it offers approval.** Call `checkSponsorship` (the same request,
with a refusal returned as a value) when the review screen mounts, and render no approve button
until it answers. A user must never be asked for a fingerprint or a face scan for a transaction that
cannot be paid for. `e2e/wallet-byo/` is the working reference.

### 7.3 What a transaction costs, and how to reconcile it

Each sponsored transaction debits the tenant for three things, kept separate so they can be audited:

| Component | What it is | Where it goes |
| --- | --- | --- |
| Gas | What the network charged | Reimburses the paymaster's deposit |
| Fee | Giano's fixed platform fee, pinned at authorisation | Giano's treasury |
| Overhead | Network costs the contract cannot observe at settlement — the accounting step's own gas, and the network's penalty on over-estimated gas limits | Nobody: it leaves the ledger, mirroring money that left the deposit |

The fee in force is **pinned into each authorisation**, so a rate change cannot alter what an
already-authorised transaction charges. The fee is charged whether the transaction succeeds or
reverts — a reverted transaction still consumed real gas and still consumed the service.

The overhead is a deliberate slight over-charge, because under-charging would let the ledger promise
more than the deposit holds. Giano monitors the residue and treats unexpected growth as a
mis-calibration to be corrected, not as revenue.

Three read endpoints, all tenant-scoped by the admin key, all derived from on-chain events and all
carrying the block height they were computed at, so the figures can be reproduced independently:

| Endpoint | Returns |
| --- | --- |
| `GET /v1/admin/sponsorship/balance` | Balance, outstanding reservations, available, deficit, the fee in force, and where to fund |
| `GET /v1/admin/sponsorship/spend` | Every settled transaction with gas, fee and overhead separately, each traceable to a `Sponsored` event |
| `GET /v1/admin/sponsorship/decisions` | Every decision, refusals included, with the rule-by-rule results — this is what answers "why did my user see a refusal?" |

### 7.4 Custody: the honest limits

- The balance is **the tenant's money**, held in a contract, not a credit balance with Giano.
- **Only the tenant's registered withdrawal address can withdraw it.** No Giano role can move it —
  not individually and not in combination — and withdrawal keeps working even while the paymaster is
  paused, because a pause must halt sponsorship without trapping funds.
- **The upgrade authority is the exception.** An upgrade can replace the logic that enforces all of
  the above. That is a trust position rather than a technical safeguard. It is constrained by process:
  the upgrade role is held by a timelock whose proposers are a multi-party account, so every upgrade
  is queued publicly and executable only after a published delay — long enough to withdraw first if
  you object. There is no bypass, including for changes presented as urgent.
- **Losing the withdrawal key strands the balance permanently**, because by design nobody else can
  move it. Rotation exists and should be used before a key is lost, not after.

So "Giano cannot take your funds" is true of Giano's day-to-day operation and conditional on the
upgrade controls. We would rather say that than let the shorter version stand.

## 8. Health checks

- wallet-api: `GET /healthz` (liveness), `GET /readyz` (DB ping, and the sponsorship signer when
  sponsorship is enabled — a deployment that cannot sponsor does not report itself ready),
  `GET /v1/version`;
  `GET /metrics` (Prometheus, `tenant`-labelled; bearer-gated when `METRICS_BEARER_TOKEN`
  is set).
- wallet-web: `GET /` (nginx).
- bundler: `eth_supportedEntryPoints`.

## 9. SDK snippet (dApp)

```ts
import { createGianoWalletProvider, createGianoConnector } from '@appliedblockchain/giano-connector';
import { baseSepolia } from 'wagmi/chains';

const provider = createGianoWalletProvider({ walletUrl: 'https://wallet.yourapp.com', chain: baseSepolia });
const connector = createGianoConnector({ provider });
// use `connector` with wagmi, or `giano({ provider })` with RainbowKit
```

See `packages/connector/README.md` for the full API and the 0.x → 1.x migration guide.

## 10. Upgrade runbook

All artifacts share one version (Changesets fixed mode). Upgrade order: **wallet-api
(with migrations) → wallet-web → dApp SDK**; roll back in reverse. Never run web/SDK newer
than the wallet-api. Full policy: `COMPATIBILITY.md`.

## Quick start (local)

```bash
# pre-baked E2E stack (instant-boot devnet, contracts included) — seeds TWO tenants:
# "stock" (Giano's wallet-web at wallet.localhost) and "byo" (bring-your-own UI,
# served host-side via `pnpm --filter @appliedblockchain/giano-e2e wallet-byo`).
# --profile portless adds the relay that lets those addresses omit a port; the names
# themselves come from `pnpm -F @appliedblockchain/giano-e2e portless:up` (see e2e/README.md).
docker compose --profile portless -f deploy/docker-compose.e2e.yml up --build
# or the from-source dev stack (postgres + anvil + alto + wallet-api; run wallet-web
# separately with `pnpm --filter @appliedblockchain/giano-wallet-web dev`):
docker compose -f deploy/docker-compose.dev.yml up --build
```
