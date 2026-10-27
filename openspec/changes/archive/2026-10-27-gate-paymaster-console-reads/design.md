## Context

See proposal.md for the motivation. These parts of the current state shape the approach:

- **Platform admin auth already exists end to end.** wallet-api's `requirePlatformAdmin` (`plugins/auth.ts`) refuses any `Origin`, resolves a `gps_` bearer token to a row in `platform_admins`, and decorates `request.platformAdmin` with its `sessionId`. The console's `PlatformSessionProvider` (`lib/platform-session.ts`) holds that token in React state. It is mounted in `App.tsx` only around the Platform area, keyed on `deploymentKey(deployment)`. The platform tier is registered only where `ENVIRONMENTS[...].siweDomain` is set: dev, stg, prd, e2e and local-infra.
- **The tenant relay already carries the allowlist we need.** `routes/rpc-relay.ts` has `READ_METHODS`, answers `eth_chainId` from configuration, maps node errors through `NodeRpcError`, and keeps a per-tenant one-minute window. It covers every method the console and `paymaster-sdk` call: `eth_call`, `eth_getCode`, `eth_blockNumber`, `eth_getLogs`, `eth_getTransactionReceipt`, `eth_getTransactionByHash` and `eth_getBlockByNumber`. The console uses no `watch*`/`eth_newFilter`.
- **The SDK's log reads are bounded already.** `paymaster-sdk/src/log-window.ts` always queries numeric `fromBlock`/`toBlock` over at most `DEFAULT_LOG_WINDOW = 9_000n` blocks.
- **The console reads through a viem `http()` transport** built from `deployment.rpcUrl` (`lib/chain.ts` `createReadClient`, memoised per deployment in `hooks/usePaymaster.ts`). viem is 2.31.6.
- **The container runs DHI nginx 1.29.8.** It has `limit_req` and `add_header_inherit` (verified), and no `njs`. The entrypoint may use only `sh`, `envsubst` and `jq`.
- **Hosted dev/stg/prd and the e2e stack set `GIANO_WALLET_API_UPSTREAM` for the console.** The local-infra compose stack does not, so it stays a standalone console. Neither the Helm chart nor the reference compose ships the console.

## Goals / Non-Goals

**Goals:**
- One relay core in wallet-api serves both the tenant relay and the platform relay. The allowlist, node-error mapping and `eth_chainId` handling are written once.
- The console's session layer stays exactly as merged: in memory, ending on reload, account/chain change, deployment switch, sign-out or 401. It just wraps more of the app.
- The standalone console keeps working with no new dependency.

**Non-Goals:**
- Changing the tenant relay's limits or allowlist (G3).
- Persisting the session across reloads, or renewing it.
- Making on-chain role holders who are not platform admins able to read the hosted console.

## Decisions

### D1. Reuse SIWE platform admin sessions as the console's access control
The sign-in, the session store, the `platform_admins` table and `requirePlatformAdmin` already exist and are tested. The console gates reads on them instead of adding ALB OIDC or a cookie with nginx `auth_request`.

**Alternatives:**
- **ALB `authenticate-oidc`** hides the shell too, but it is AWS-only (R4), needs an IdP client and Terraform, and leaves R2 unsolved.
- **An HttpOnly cookie with `auth_request`** contradicts the merged in-memory session rule, makes `SameSite` the only protection against forged requests (the `/api` proxy strips `Origin`), and still needs the wallet-api relay for R2.

The user chose this option, accepting a public shell; the deviation is recorded in the proposal.

### D2. Extract the relay core from `routes/rpc-relay.ts`
Move the allowlist, `eth_chainId`, the node call and the error mapping into `services/rpc-read-relay.ts`, as `createReadRelay({ limitPerMinute, guard?, count })`. It exposes `handle({ body, chain, key, log })`. The tenant route calls it with `key = tenant.id`, its current limit and the current `rpcRelay` counter, so its behaviour and metrics stay unchanged. The platform route (`routes/platform-rpc.ts`) calls it with `key = platformAdmin.sessionId`, `PLATFORM_RPC_RATE_LIMIT_PER_MINUTE`, the log-range guard and a new `platformRpcRelay` counter labelled `method`, `chain` and `outcome`.

**Alternative:** have the console call the tenant relay `/v1/rpc` with a platform session. That route is tenant-bound by `Origin`, and platform routes refuse `Origin`, so the two can't be combined without weakening one of them.

### D3. Platform route shape
`POST /v1/platform/rpc/:chainId` is registered inside the platform tier block in `app.ts`, next to `platformTenantRoutes`. Its hooks are `onRequest: requirePlatformAdmin`, then `preHandler: requireChain`. `bodyLimit: 16384` makes Fastify answer 413 before parsing. The body schema is the existing single-object `jsonRpcRequestSchema`, so a batch array fails validation with 400. It has no `@fastify/rate-limit` config (the plugin is `global: false`), so the only limit is the relay core's per-session window, kept apart from the management routes' budget, as the spec requires. The single-chain `/v1/rpc` affordance is not mirrored: the console always knows its chain id.

### D4. `eth_getLogs` guard (platform relay only)
The guard accepts a filter with a `blockHash`, or with hex `fromBlock` and `toBlock` and a span of at most `PLATFORM_RPC_MAX_LOG_BLOCKS` (default 10 000, above the SDK's 9 000 window). Block tags (`latest`, `earliest`, `pending`, …) are refused because the span can't be bounded without a head lookup. Anything else gets `-32602` with the limit in the message. `loadConfig` refuses a value below 9 000 so a misconfiguration can't silently break the History tab.

### D5. Rate-limit default
`PLATFORM_RPC_RATE_LIMIT_PER_MINUTE` defaults to 1 200 (20/s per session). A console refresh fans out per tenant at a 15 s interval, and the History tab pages logs on demand. Task 1.6 measured 22 relay calls per Overview refresh on the e2e roster (stable across runs), so about 88 a minute at the 15 s interval. The default is about 13× that, above the 4× bar. Platform admins number in single digits, so the whole-deployment ceiling is bounded by the admin count.

### D6. Console: one session around both areas
`PlatformSessionProvider` moves up in `App.tsx` to wrap both areas, still keyed on `deploymentKey(deployment)`, so a deployment switch still remounts it and ends the session. When `platformApi` is true:
- the Paymaster area renders `platform/SignIn.tsx` until there is a session;
- `usePaymaster` takes the token and builds its read client only once a token exists;
- on session end, the provider remounts the Paymaster subtree, which drops the cached overview and stops polling.

When `platformApi` is false, nothing about the Paymaster area changes. The 404 "platform API disabled" state moves from `PlatformArea` up to the shared sign-in view.

### D7. Console read transport
`createReadClient(deployment, auth?)` builds `http(deployment.rpcUrl, { fetchOptions: { headers: { authorization: `Bearer <token>` } }, onFetchResponse })`. A `401` response calls the session's `expire()`, which ends the session the same way a 401 on a platform call does. viem 2.31.6 has no `fetchFn` option, but `onFetchResponse` sees every response, and viem doesn't retry a 401. `usePaymaster` keys the client on the token and takes `"required"` while signed out, which builds no client at all. The URL comes from `/config.json` (D8), so the console doesn't hard-code the relay path. Its only rule is "attach the token when `platformApi` is true".

### D8. Entrypoint: choose the read path by upstream
In `docker/entrypoint.sh`:
- **`GIANO_WALLET_API_UPSTREAM` set:** after the field allowlist, rewrite every deployment's `rpcUrl` to `/api/v1/platform/rpc/<chainId>`, render no `/rpc/*` location, and ignore `GIANO_RPC_PROXY`. `connect-src` derives to `'self'`. The existing `/api/` location carries the call. Its `proxy_set_header Origin ""` is what lets `requirePlatformAdmin` accept it.
- **Upstream unset:** behaviour as today, plus a `limit_req_zone` rendered at file scope in `nginx.conf.template`, keyed on a constant so the limit is global, and inside each generated `/rpc/<chainId>` location `limit_req zone=giano_rpc burst=<2×rate> nodelay; limit_req_status 429; client_max_body_size 16k;`. `GIANO_RPC_PROXY_RATE` (default `20r/s`) sets the rate, and the entrypoint validates its form.

**Alternatives:**
- An `njs` allowlist in nginx: `njs` is not in DHI.
- A sidecar: a new image and a new process for something wallet-api already does.

### D9. Headers on every response (R5)
Add `add_header_inherit merge;` at server level in the console's `nginx.conf.template`. Every `location` that sets its own `add_header` (`/config.json`, `/assets/`, `/api/`, and the standalone `/rpc/`) then keeps the four server-level security headers. This is already required by `spa-container-runtime`'s "Security headers on every response" and is currently broken for the console. Copying the headers into each location is the fallback, but it duplicates the CSP in five places.

## Risks / Trade-offs

- **[Console unusable when wallet-api is down]** In hosted mode reads depend on wallet-api → acceptable: the Platform area already does, and the old path depended on the same QuickNode endpoint wallet-api uses.
- **[Role holders who are not platform admins lose read access to the hosted console]** → before deploy, check `platform_admins` on dev/stg/prd against the people who use the console (task 6.2). Adding one is a console action for any existing platform admin.
- **[A sign-in per reload and every 30 minutes, even to read]** → accepted trade-off of the in-memory session (D1, D6). If it hurts in practice, `PLATFORM_SESSION_TTL_SECONDS` is per-environment config.
- **[Rate limit too low for a big roster]** → measured before setting the default (D5). Over-limit answers are JSON-RPC errors that the console shows like any other read failure, not a sign-out.
- **[Wallet add-network uses `rpcUrl` when `walletRpcUrl` is unset]** In hosted mode that is now an authenticated path a wallet can't use → no regression (it was already a same-origin path MetaMask refuses). The README recommends setting `walletRpcUrl`.
- **[Standalone proxy still has no method allowlist]** → documented as needing the operator's own SSO or VPN (R4). The rate and size limits cap the damage.
- **[Deploy ordering]** A new console against an old wallet-api gets 404 from the relay and shows "platform API disabled" → both images ship from the same `image_tag` in one apply. Rollback is the previous tag for both.

## Migration Plan

1. Merge with both images built from the same commit. Terraform needs no change, because `svc-paymaster-admin` already sets `GIANO_WALLET_API_UPSTREAM`.
2. Before applying to dev, confirm `platform_admins` on dev lists every console user (task 6.2).
3. Apply to dev and check: the anonymous page shows sign-in only, `curl -X POST https://paymaster.<apex>/rpc/<id>` returns the SPA fallback, `/api/v1/platform/rpc/<id>` returns 401 without a token, and `/config.json` and `/assets/*` carry the four headers.
4. Rollback: redeploy the previous `image_tag` for both services. No data migration exists to undo.
