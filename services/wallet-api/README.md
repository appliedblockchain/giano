# giano-wallet-api

Backend service for Giano passkey smart wallets: server-side WebAuthn ceremonies
(@simplewebauthn), PostgreSQL-backed credentials and sessions, and a policy-enforcing
ERC-4337 user-operation relay. Distributed as `ghcr.io/appliedblockchain/giano-wallet-api`;
every client project deploys it in its own stack (Giano is never centrally hosted).

## Security model

- **Identity always comes from the session.** No endpoint accepts a user id in the URL or an
  unauthenticated body (the old demo's storage API accepted any `userId` — that model is gone).
  Sessions are opaque 32-byte bearer tokens; only their sha256 hash is stored.
- **Challenges are single-use**, consumed atomically (`UPDATE … WHERE consumed_at IS NULL AND
  expires_at > now() RETURNING *`), so replay loses even under concurrency.
- **The EntryPoint is never taken from a request.** The relay computes the userop hash itself
  against the configured EntryPoint/chain and submits only to the configured bundler.
- **Every relayed op passes a policy pipeline** — sender must match the session credential's
  wallet, gas/fee caps, optional target allowlist (decoded from `execute`/`executeBatch`
  calldata), optional paymaster allowlist — and every rule's verdict is persisted as an audit
  row, accepted or rejected.
- **Registration is closed by default** (`OPEN_REGISTRATION=false`): the client project's
  backend requests ceremony options server-to-server with an `ADMIN_API_KEYS` bearer, binding
  wallet registration to its own authentication.

## API

Committed OpenAPI document: [`openapi/openapi.json`](openapi/openapi.json) (drift-checked in CI;
Swagger UI at `/docs` outside production).

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /v1/webauthn/options` | admin key (or open) | challenge + known credential ids for a user |
| `POST /v1/webauthn/registration/verify` | — (consumes challenge) | verify attestation, derive P-256 key, compute counterfactual wallet, issue session |
| `POST /v1/webauthn/authentication/verify` | — (consumes challenge) | verify assertion, issue session |
| `GET /v1/me`, `/v1/me/credentials`, `/v1/me/credentials/:id/public-key` | session | current identity/credentials |
| `POST /v1/sessions/logout` | session | revoke session |
| `POST /v1/userops` | session | policy-checked relay to the bundler |
| `GET /v1/userops/:hash` | session | relay log/status incl. policy audit |
| `GET /v1/userops/:hash/receipt` | public | read-only receipt proxy (thin-SDK receipt waiting) |
| `GET /.well-known/webauthn` | public | Related Origin Requests document (DB-backed) |
| `GET/POST/DELETE /v1/admin/ror-origins` | admin key | manage ROR origins |
| `GET /healthz`, `GET /readyz` | public | liveness / readiness (DB ping) |

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
| `RUN_MIGRATIONS` | `true` = apply `migrations/*.sql` before listening (also: `node dist/migrate.js` one-shot) |
| `RP_ID` / `RP_NAME` / `EXPECTED_ORIGINS` | WebAuthn relying party — **RP_ID is irreversible per deployment** |
| `CHAIN_ID` / `RPC_URL` / `BUNDLER_URL` | chain wiring |
| `ENTRYPOINT_ADDRESS` / `FACTORY_ADDRESS` | default from the `@appliedblockchain/giano-contracts` registry for `CHAIN_ID` |
| `OPEN_REGISTRATION` / `ADMIN_API_KEYS` | auth model (see above) |
| `USEROP_MAX_CALL_GAS`, `USEROP_MAX_VERIFICATION_GAS`, `USEROP_MAX_FEE_PER_GAS`, `USEROP_MAX_PRIORITY_FEE_PER_GAS`, `USEROP_ALLOWED_TARGETS`, `USEROP_ALLOWED_PAYMASTERS` | relay policy |
| `CHALLENGE_TTL_SECONDS` / `SESSION_TTL_SECONDS` / `CORS_ORIGINS` / `CEREMONY_RATE_LIMIT_PER_MINUTE` | tuning |

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

## Docker

Build from the **repo root** (bundles the workspace `giano-contracts` dep, no registry auth):

```bash
docker build -f services/wallet-api/Dockerfile -t ghcr.io/appliedblockchain/giano-wallet-api .
```

- `deploy/docker-compose.reference.yml` — what client projects copy (postgres + wallet-api).
- `deploy/docker-compose.dev.yml` — local stack incl. anvil + alto.
