## Why

The paymaster console (`services/paymaster-admin`) is published on the public ALB with no access control, and its nginx proxies each chain's keyed provider URL at `/rpc/<chainId>` with no method filter, size limit, rate limit or auth (G10, production readiness report item A3). Anyone on the internet gets a one-click reconnaissance view of the tenant roster, and can spend the same QuickNode quota the production API depends on. The platform-admin wallet sign-in (SIWE, `requirePlatformAdmin`) that shipped with H5 already proves who is a Giano operator, so the fix reuses it instead of adding a second identity system.

## What Changes

- **New wallet-api route `POST /v1/platform/rpc/:chainId`**: a JSON-RPC read relay behind `requirePlatformAdmin` (bearer platform admin session, `Origin` refused). It shares the read-method allowlist and node call with the tenant relay in `routes/rpc-relay.ts`. It adds a per-session rate limit, a small request-body limit, and a block-range cap on `eth_getLogs`, so even a signed-in platform admin cannot use it as a general-purpose RPC endpoint.
- **The console reads the chain only through that route when the platform API is configured.** With `GIANO_WALLET_API_UPSTREAM` set, the container renders no `/rpc/*` locations. Each deployment's `rpcUrl` in `/config.json` becomes `/api/v1/platform/rpc/<chainId>`, and the keyed URL never reaches nginx or the browser.
- **BREAKING (console UX):** where the platform API is configured, the whole console, the Paymaster tabs included, needs a platform admin sign-in before it shows any chain data. The existing in-memory session from the Platform area is lifted to cover both areas. Reads now need a connected wallet, and a reload asks for one signature.
- **Standalone console (no `GIANO_WALLET_API_UPSTREAM`)** keeps its nginx `/rpc/<chainId>` proxy, now with `limit_req` and a small `client_max_body_size`. The README states that in this mode the console must sit behind the operator's own SSO or VPN, because the proxy has no method allowlist and spends the keyed URL's quota for whoever can reach it.
- **Security headers on every console response** (R5): the server-level headers are inherited by `/config.json`, `/assets/`, `/api/` and `/rpc/` locations instead of being dropped by their own `add_header`.
- **Docs:** the console README and `specs/INFRASTRUCTURE.md` describe the hosted access model, the standalone requirement and the accepted deviation below.

**Accepted deviation from G10 R1.** The static UI shell (`index.html`, `/assets/*`) and `/config.json` stay publicly reachable. The bundle is already public (the repo is MIT), and `/config.json` names only chain names, chain ids and paymaster addresses, which are all on chain. An anonymous visitor gets a sign-in screen, no tenant data and no route to the RPC quota. Hiding the shell would need auth in front of the whole host, for example ALB OIDC, which can be added later without touching the console.

**Non-goals.** G3 (the tenant `/v1/rpc` relay's own open-proxy shape), G9 (timelock/Safe propose mode for writes), ALB OIDC or WAF in Terraform, and wallet-web's identical header gap (report item X3).

## Capabilities

### New Capabilities
- `platform-chain-reads`: wallet-api's authenticated JSON-RPC read relay for platform admins. Covers who may call it, the allowed methods, size, rate and log-range limits, and how failures are reported.

### Modified Capabilities
- `platform-console-access`: the console needs a platform admin session for every chain read, not only for the Platform area, and its session covers both areas.
- `spa-container-runtime`: paymaster-admin renders no `/rpc/*` proxy when the platform API is configured. In standalone mode the proxy is rate- and size-limited.

## Impact

- **wallet-api:** a new route module next to `routes/rpc-relay.ts`, with the shared relay core factored out. New config `PLATFORM_RPC_RATE_LIMIT_PER_MINUTE` and `PLATFORM_RPC_MAX_LOG_BLOCKS`, metrics labels, and OpenAPI. Registered only where the platform tier is (environments with a `siweDomain`).
- **paymaster-admin:** `docker/entrypoint.sh` and `docker/nginx.conf.template` (proxy selection, `add_header_inherit merge`, `limit_req`). In `src/`: `App.tsx`, `lib/chain.ts`, `lib/platform-session.ts`, `hooks/usePaymaster.ts`, and the sign-in view now gates the Paymaster area.
- **e2e:** `paymaster-admin.spec.ts` must sign in before reading, plus new cases for the gated relay and the headers. `platform-console.spec.ts` and `platform-admin.spec.ts` are rechecked.
- **Infra:** no Terraform change. The hosted console already sets `GIANO_WALLET_API_UPSTREAM`, so it switches to gated reads on deploy. The console's QuickNode spend moves into wallet-api's process.
- **Operators:** must have their address in `platform_admins` to read anything in the hosted console. Role-holders who are not platform admins lose read access there.
