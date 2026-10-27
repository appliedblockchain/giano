# giano-wallet-api

Backend service for Giano passkey smart wallets: server-side WebAuthn ceremonies
(@simplewebauthn), PostgreSQL-backed credentials and sessions, and a policy-enforcing
ERC-4337 user-operation relay. Distributed as `ghcr.io/appliedblockchain/giano-wallet-api`.

**Multi-tenant**: one wallet-api instance (one Postgres, one bundler, one chain) serves many
client projects. Every tenant owns its wallet origin, and that origin's host is the tenant's
WebAuthn RP ID — 1:1 (`specs/DEVELOPER-GUIDE.md` §1). The origin may serve Giano's stock
wallet-web UI or a UI the tenant built itself; both are the same architecture. Tenants are
created and managed only by Giano's platform admins at runtime, through `/v1/platform/*` (the paymaster
console's Platform area; only where the environment has a console host) — no redeploy. The
platform admins are rows too, in the `platform_admins` table, and add and remove each other the same way. The
service boots fine with no tenants. `TENANTS_SEED` is retired and no longer read.

**Init step.** `node dist/init.js` (`src/init.ts`) runs to completion before the API everywhere — an
`init` service in every compose file, an init container on AWS — and the API runs with
`RUN_MIGRATIONS=false`. It applies migrations; writes the environment's bootstrap platform admins
(`src/environments.ts`) **only into an empty `platform_admins` table**; and, on local compose stacks only,
creates the `TENANT_FIXTURES` tenants (insert-only). Anywhere else it refuses `TENANT_FIXTURES`
(`specs/PLATFORM-ADMIN-SPECS.md` §4.1, §9).

## Security model

- **Tenant ≡ wallet origin ≡ RP ID.** Ceremony requests resolve their tenant from the
  `Origin` header — authoritative because WebAuthn independently verifies the ceremony ran on
  that origin (`clientDataJSON.origin` must match the tenant's `expectedOrigins`). The
  browser itself refuses to surrender one tenant's passkey to another's origin, and the
  server tenant-scopes every lookup on top of that; cross-tenant rejections are alertable
  (`giano_cross_tenant_rejections_total`).
- **Identity always comes from the session.** No endpoint accepts a user id in the URL or an
  unauthenticated body (the old demo's storage API accepted any `userId` — that model is gone).
  Sessions are opaque 32-byte bearer tokens; only their sha256 hash is stored. A session is
  scoped to its tenant and rejected on any other tenant's origin.
- **Challenges are single-use and tenant-bound**, consumed atomically (`UPDATE … WHERE
  consumed_at IS NULL AND expires_at > now() RETURNING *`), so replay loses even under
  concurrency — and a challenge issued for one tenant cannot be redeemed on another.
- **The EntryPoint is never taken from a request.** The relay computes the userop hash itself
  against the configured EntryPoint/chain and submits only to the configured bundler.
- **Every relayed op passes a policy pipeline** — sender must match the session credential's
  wallet, gas/fee caps, optional target allowlist (decoded from `execute`/`executeBatch`
  calldata), optional paymaster allowlist — and every rule's verdict is persisted as an audit
  row, accepted or rejected. The `USEROP_*` env values are deployment defaults; each tenant's
  `policy` jsonb overrides them per field, and each tenant has its own relay rate limit.
- **Registration is closed by default** (per-tenant `openRegistration: false`): the client
  project's backend requests ceremony options server-to-server with one of the TENANT'S OWN
  `adminKeys` bearers (stored sha256-hashed), binding wallet registration to its own
  authentication. Admin keys resolve to their tenant — no key can touch another tenant's data.

## API

Committed OpenAPI document: [`openapi/openapi.json`](openapi/openapi.json) (drift-checked in CI;
Swagger UI at `/docs` outside production).

| Endpoint | Auth / tenant resolution | Purpose |
| --- | --- | --- |
| `POST /v1/webauthn/options` | `Origin` → tenant; tenant admin key when registration closed | challenge + known credential ids for a user |
| `POST /v1/webauthn/registration/verify` | `Origin` → tenant (consumes tenant-bound challenge) | verify attestation, derive P-256 key, compute counterfactual wallet, issue session |
| `POST /v1/webauthn/authentication/verify` | `Origin` → tenant (consumes tenant-bound challenge) | verify assertion, issue session |
| `GET /v1/me`, `/v1/me/credentials`, `/v1/me/credentials/:id/public-key` | session (tenant-scoped) | current identity/credentials |
| `POST /v1/sessions/logout` | session | revoke session |
| `POST /v1/userops` | session; per-tenant policy + rate limit | policy-checked relay to the bundler |
| `POST /v1/bundler/:chainId` | session; per-tenant rate limits | JSON-RPC bundler facade for wallet origins: `eth_sendUserOperation` through the same pipeline as `/v1/userops`, `eth_estimateUserOperationGas` bound to the session wallet, receipts forwarded, `eth_chainId`/`eth_supportedEntryPoints` answered locally — so no bundler is ever browser-reachable |
| `POST /v1/rpc/:chainId` | `Origin` → tenant; per-tenant rate limit | JSON-RPC read relay to the chain node (allowlisted `eth_*` reads only) — so a wallet origin needs no node URL and a keyed provider URL never reaches a browser |
| `GET /v1/userops/:hash` | session (tenant-scoped) | relay log/status incl. policy audit |
| `GET /v1/userops/:hash/receipt` | public (deliberately tenant-free) | read-only receipt proxy (thin-SDK receipt waiting) |
| `GET /.well-known/webauthn` | `Host` → tenant | that tenant's Related Origin Requests document |
| `GET/POST/DELETE /v1/admin/ror-origins` | tenant admin key | manage the key's tenant's ROR origins |
| `POST /v1/platform/auth/challenge`, `/verify`, `/logout` | none / platform admin session; any `Origin` refused | platform admin sign-in with a wallet (EIP-4361): a server-issued message, exchanged once for a `gps_` session |
| `GET/POST /v1/platform/tenants`, `GET/PATCH/DELETE /v1/platform/tenants/:slug`, `…/suspend`, `…/resume`, `…/admin-keys`, `…/history` | platform admin session; any `Origin` refused | runtime tenant CRUD and lifecycle (active → suspended → deleted tombstone), generated admin keys, history |
| `GET/POST /v1/platform/admins`, `DELETE /v1/platform/admins/:id`, `GET /v1/platform/admins/history` | platform admin session; any `Origin` refused | the platform admins: list, add (can sign in at once), remove (revokes their sessions; `409 self-removal` / `409 last-admin`), and the append-only change history |
| `GET /healthz`, `GET /readyz` | public | liveness / readiness (DB ping) |
| `GET /metrics` | open, or bearer when `METRICS_BEARER_TOKEN` set | Prometheus metrics, `tenant`-labelled |

The wallet address bound to a credential is computed by calling the factory's on-chain
`getAddress(owners, nonce)` — the same source of truth the connector uses, so client- and
server-side derivation cannot drift.

## Configuration

All configuration is via environment variables, zod-validated at boot (see `src/config.ts` for
the authoritative schema and `deploy/docker-compose.reference.yml` for a fully commented
example). Highlights:

| Variable | Notes |
| --- | --- |
| `DATABASE_URL` | required |
| `GIANO_ENVIRONMENT` | required: `dev`, `stg`, `prd`, `reference`, `e2e`, `local-infra`, `local-dev`, `local-sepolia` or `test`. Selects the entry in `src/environments.ts`: the console host every platform admin sign-in message names (`siweDomain`/`siweUri`, changed only by a release, never stored), the init step's bootstrap platform admins, and whether this is a local stack. An environment with no console host registers no platform route |
| `RUN_MIGRATIONS` | `true` = apply `migrations/*.sql` before listening. `false` in every compose file and on AWS, where the init step runs them (also: `node dist/migrate.js` one-shot) |
| `TENANT_FIXTURES` | **read only by the init step (`node dist/init.js`), only on a local-stack environment, never by the API**; init refuses to start if it is set anywhere else (which no longer reads the retired `TENANTS_SEED` either). JSON array of tenants, each created if its slug is missing and otherwise left untouched. Per tenant: `slug`, `id?` (pinned, for a tenant pre-registered on a devnet paymaster), `walletOrigin`, `rpId?` (defaults to and must equal the walletOrigin host — **irreversible per tenant**), `rpName`, `expectedOrigins?`, `allowedDappOrigins?`, `corsOrigins?`, `openRegistration?`, `adminKeys?` (plaintext in, stored sha256-hashed), `policy?` (partial `USEROP_*` overrides, bigints as decimal strings, plus `relayRateLimitPerMinute`), `branding?` |
| `GIANO_CHAINS` + `BUNDLER_BASE_URL` | the chains served: the backend chain document (`packages/contracts/chains.ts`) giano-bundler reads too; each chain submits to `<BUNDLER_BASE_URL>/<chainId>` unless its `walletApi.bundlerUrl` names another bundler |
| `CHAIN_ID` / `RPC_URL` / `BUNDLER_URL` | single-chain shorthand, mutually exclusive with `GIANO_CHAINS`; `BUNDLER_URL` is the exact endpoint |
| `ENTRYPOINT_ADDRESS` / `FACTORY_ADDRESS` | default from the `@appliedblockchain/giano-contracts` registry for `CHAIN_ID` |
| `USEROP_MAX_CALL_GAS`, `USEROP_MAX_VERIFICATION_GAS`, `USEROP_MAX_FEE_PER_GAS`, `USEROP_MAX_PRIORITY_FEE_PER_GAS`, `USEROP_ALLOWED_TARGETS`, `USEROP_ALLOWED_PAYMASTERS`, `USEROP_RATE_LIMIT_PER_MINUTE` | relay policy **defaults** (tenant `policy` overrides per field) |
| `CHALLENGE_TTL_SECONDS` / `SESSION_TTL_SECONDS` / `CEREMONY_RATE_LIMIT_PER_MINUTE` / `METRICS_BEARER_TOKEN` | tuning / observability |
| `PLATFORM_CHALLENGE_TTL_SECONDS` / `PLATFORM_SESSION_TTL_SECONDS` / `PLATFORM_RATE_LIMIT_PER_MINUTE` | sign-in nonce lifetime (300), absolute platform admin session lifetime (1800), per-session and per-address limit (60) |
| `PLATFORM_RPC_RATE_LIMIT_PER_MINUTE` / `PLATFORM_RPC_MAX_LOG_BLOCKS` | the platform chain read relay (`/v1/platform/rpc/:chainId`): forwarded reads per session per minute (1200, a budget separate from the one above), and the widest `eth_getLogs` range it forwards (10000; at least 9000, the paymaster SDK's log window) |
| `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS` | delete refuses a ledger further than this behind the chain head (50); must exceed `PAYMASTER_WATCHER_CONFIRMATIONS` |

CORS is per-tenant (`corsOrigins`) and fail-closed; there is no global CORS allowlist.

## Development

```bash
pnpm dev            # tsx watch (needs DATABASE_URL etc. in env)
pnpm test           # vitest + testcontainers (needs Docker)
pnpm typecheck
pnpm openapi        # regenerate openapi/openapi.json (CI checks drift)
pnpm migrate        # apply migrations to DATABASE_URL
```

The integration tests exercise real WebAuthn ceremonies end-to-end using generated P-256 keys
and hand-encoded CBOR attestations — no browser needed.

## Platform admin sign-in from a script

For acceptance on a deployment, with a throwaway EOA a platform admin has added in the console's
Admins tab (remove it afterwards):

```sh
PLATFORM_ADMIN_PRIVATE_KEY=0x… pnpm -s --filter @appliedblockchain/giano-wallet-api platform:login --api https://api.dev.giano.appliedblockchain.dev
```

It prints only the session token on stdout. A real platform admin signs in through the console with
their own wallet.

## Docker

Build from the **repo root** (bundles the workspace `giano-contracts` dep, no registry auth):

```bash
docker build -f services/wallet-api/Dockerfile -t ghcr.io/appliedblockchain/giano-wallet-api .
```

- `deploy/docker-compose.reference.yml` — what client projects copy (postgres + wallet-api).
- `deploy/docker-compose.dev.yml` — local stack incl. anvil + giano-bundler.
