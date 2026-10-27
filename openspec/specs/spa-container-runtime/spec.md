# spa-container-runtime Specification

## Purpose

The start-up and serving contract of the static single-page-application images (`giano-wallet-web`,
`giano-paymaster-admin`, `giano-example`). This contract must survive their move to a hardened nginx runtime. One image
serves every deployment: configuration is injected at start from `GIANO_*` variables, the bundle is served with
security headers, and same-origin proxies keep upstream URLs and keys out of the browser.

## Requirements

### Requirement: Start-up configuration from the environment
At start, each SPA image SHALL render its browser configuration and its nginx server configuration from `GIANO_*`
environment variables. It SHALL accept the same variable names, defaults, mutual exclusions and fail-fast errors that
its image accepted before this change:
- wallet-web renders `/config.json`. It accepts `GIANO_CHAINS` or `GIANO_CHAIN_ID`, and requires
  `GIANO_WALLET_API_UPSTREAM`.
- paymaster-admin renders `/config.json`. It accepts `GIANO_DEPLOYMENTS` or `GIANO_CHAIN_ID` + `GIANO_RPC_URL`, and
  publishes only the allow-listed descriptor fields.
- giano-example renders `/config.js`, according to the `demo-deployment` capability.

A missing required variable, or a combination that is not allowed, SHALL stop the container with a non-zero exit and a
message that names the variable. Rendered configuration SHALL be served with `Cache-Control: no-store`.

#### Scenario: Parity with the previous entrypoint
- **WHEN** an SPA image starts with each environment fixture that the e2e stack, the compose files and the Helm chart
  use today
- **THEN** the rendered browser configuration is semantically equal (as JSON, or as the JS object for giano-example)
  to the one the previous image produced for the same environment, and the rendered nginx configuration has the same
  CSP, proxy locations and resolver

#### Scenario: Mutually exclusive inputs
- **WHEN** wallet-web starts with both `GIANO_CHAINS` and `GIANO_CHAIN_ID` set
- **THEN** it exits non-zero naming both variables, and serves nothing

#### Scenario: Malformed JSON input
- **WHEN** paymaster-admin or giano-example starts with a `GIANO_DEPLOYMENTS` or `GIANO_CHAINS` value that is not valid
  JSON
- **THEN** it exits non-zero with a message naming the variable

### Requirement: Security headers on every response
Every response SHALL carry the same `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options` and
`Referrer-Policy` values that the image sent before this change. The CSP `connect-src` SHALL be derived from
configuration in the same way as before.

#### Scenario: Header parity
- **WHEN** `/`, an `/assets/*` file, the rendered configuration file and a deep SPA route are each requested
- **THEN** each response carries the four headers with values identical to the previous image for the same environment

### Requirement: Static serving, SPA fallback and caching
Each image SHALL listen on port `8080`. It SHALL serve the built bundle with `Cache-Control: public, max-age=31536000,
immutable` under `/assets/`, and SHALL fall back to `index.html` with status 200 for an unknown path that is not a
file.

#### Scenario: Deep link
- **WHEN** a browser requests `/some/client/route`
- **THEN** the server returns `index.html` with status 200

### Requirement: Same-origin proxies keep their behaviour
Each image SHALL keep its proxy paths:
- wallet-web proxies `/api/*` (prefix stripped) and `/.well-known/webauthn` to `GIANO_WALLET_API_UPSTREAM`. It
  re-resolves the upstream host name at most 10 seconds apart, through the container's IPv4 nameserver.
- paymaster-admin, when `GIANO_WALLET_API_UPSTREAM` is set, renders no `/rpc/*` location whatever
  `GIANO_RPC_PROXY` says. It publishes each deployment's `rpcUrl` in `/config.json` as
  `/api/v1/platform/rpc/<chainId>`, and its nginx configuration contains no deployment's original `rpcUrl`.
- paymaster-admin, when `GIANO_WALLET_API_UPSTREAM` is unset, proxies `/rpc/<chainId>` to each absolute `rpcUrl`
  unless `GIANO_RPC_PROXY=false`. Those locations refuse a request body over 16 KiB with `413`, and limit the
  requests they forward, across all clients together, to `GIANO_RPC_PROXY_RATE` (default 20 per second, with a
  burst of twice that), refusing the excess with `429`.
- giano-example proxies `/rpc/<chainId>` to each `GIANO_RPC_UPSTREAM_<chainId>`.

Upstream URLs and keys SHALL NOT appear in rendered browser configuration or in response headers.

#### Scenario: Upstream address changes
- **WHEN** the IP address behind `GIANO_WALLET_API_UPSTREAM` changes while wallet-web is running
- **THEN** `/api/*` requests reach the new address within 10 seconds, with no container restart

#### Scenario: Keyed RPC stays server-side
- **WHEN** paymaster-admin runs standalone and proxies a keyed `rpcUrl`
- **THEN** `/config.json` shows only `/rpc/<chainId>` and the key appears in no response the browser receives

#### Scenario: Hosted console has no open RPC proxy
- **WHEN** paymaster-admin starts with `GIANO_WALLET_API_UPSTREAM` set and a keyed absolute `rpcUrl`
- **THEN** `/config.json` shows `/api/v1/platform/rpc/<chainId>`, a POST to `/rpc/<chainId>` is answered by nginx
  itself (`405`, as for any static path) rather than proxied, and the keyed URL appears nowhere in the rendered nginx
  configuration

#### Scenario: Standalone proxy limits
- **WHEN** a standalone paymaster-admin receives a 20 KiB POST on `/rpc/<chainId>`, or a burst of requests above its
  configured rate
- **THEN** the oversized request gets 413, the excess gets 429, and neither reaches the upstream

### Requirement: Clean stop
On the container's stop signal, nginx SHALL stop serving and exit before the orchestrator's stop timeout. The start
script SHALL `exec` nginx, so that nginx receives the signal as PID 1.

#### Scenario: ECS stop
- **WHEN** ECS stops a running SPA container
- **THEN** the process exits on its own before the stop timeout, and ECS does not send `SIGKILL`
