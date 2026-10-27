## MODIFIED Requirements

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
