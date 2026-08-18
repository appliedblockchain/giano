# Giano secrets & monitoring

Giano is deployed by each client project into its own stack. This is the authoritative
list of secrets, who holds them, and how they are monitored.

## Trust boundary

**No private key or session secret ever reaches `giano-wallet-web` or the dApp.** The
browser only ever holds passkey credentials (in the platform authenticator, never
extractable) and an opaque session bearer token. All server secrets live in the
`giano-wallet-api` / `giano-bundler` / deployer environments only.

## Secrets inventory

| Secret | Held by | Purpose | Rotation |
| --- | --- | --- | --- |
| `DATABASE_URL` | wallet-api, migrate job | Postgres DSN (credentials/sessions/audit) | on credential policy; app tolerates reconnect |
| tenant `adminKeys` (in `TENANTS_SEED`) | wallet-api | per-tenant server-to-server ceremony-options + ROR admin; stored sha256-hashed | rotate by adding a new key to the tenant's seed entry, draining, removing the old (re-seed = restart) |
| `ALTO_EXECUTOR_PRIVATE_KEYS` | bundler | signs bundle transactions on-chain (funded EOA) | rotate by funding a new EOA and swapping; keep gas topped up |
| `ALTO_UTILITY_PRIVATE_KEY` | bundler | alto utility ops | as above |
| `DEPLOYER_PRIVATE_KEY` | contracts-deployer job | one-shot CREATE2 deploy | ephemeral; never mount into long-running pods |
| session bearer tokens | issued to browsers | authenticate `/v1/*` | short TTL (`SESSION_TTL_SECONDS`), revocable, only sha256 hash stored |

Store these in your platform's secret manager and reference them via the Helm
`secrets.existingSecret` (a k8s `Secret`) — never inline in `values.yaml` or compose files.

### Immediate rotation task (repo history)

The demo `.env-*` files under `services/custom-example` contain **Coinbase Developer
Platform bundler API keys committed to git history**. Treat them as public and rotate
them. Real deployments supply bundler URLs via untracked env only.

## Monitoring

`giano-wallet-api` exposes Prometheus metrics at `GET /metrics`:

| Metric | Type | Meaning |
| --- | --- | --- |
| `giano_userop_relayed_total{status}` | counter | relayed userops by outcome (submitted/rejected/failed) |
| `giano_userop_policy_rejections_total{rule}` | counter | policy rejections by rule (sender-binding, gas caps, allowlists) |
| `giano_ceremony_failures_total{kind}` | counter | WebAuthn verification failures (registration/authentication) |
| `giano_userop_relay_seconds` | histogram | relay endpoint latency |
| `process_*`, `nodejs_*` | default | runtime health |

- Enable scraping with the Helm `serviceMonitor.enabled=true` (Prometheus Operator).
- The bundler (alto) exposes its own metrics; scrape per alto's documentation.
- Structured pino logs carry per-request detail and the full policy audit trail; every
  policy rejection is also a `userop_log` row for forensic queries.

Suggested alerts: sustained `policy_rejections` spike (probing), `ceremony_failures`
spike (broken RP config or attack), relay `failed` ratio, bundler executor balance low.
