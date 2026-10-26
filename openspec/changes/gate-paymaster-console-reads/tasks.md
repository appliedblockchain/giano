## 1. wallet-api: shared relay core and platform read relay

- [x] 1.1 Extract the allowlist, `eth_chainId` handling, node call, `NodeRpcError` mapping and per-key one-minute window from `routes/rpc-relay.ts` into `services/rpc-read-relay.ts` (`createReadRelay`, design D2). Rewire `/v1/rpc` and `/v1/rpc/:chainId` onto it, and confirm the existing tenant relay tests pass unchanged.
- [x] 1.2 Add `PLATFORM_RPC_RATE_LIMIT_PER_MINUTE` (default 1200) and `PLATFORM_RPC_MAX_LOG_BLOCKS` (default 10000; `loadConfig` refuses values below 9000) to `config.ts`, with doc comments, and to `.env.example` / config docs where the other `PLATFORM_*` variables are listed.
- [x] 1.3 Add the `eth_getLogs` guard to the relay core: `blockHash`, or hex `fromBlock`/`toBlock` with span ≤ the limit; anything else gets `-32602` naming the limit (D4).
- [x] 1.4 Add `routes/platform-rpc.ts`: `POST /v1/platform/rpc/:chainId` with `onRequest: requirePlatformAdmin`, `preHandler: requireChain`, `bodyLimit: 16384`, the single-object JSON-RPC schema, the relay core keyed on `platformAdmin.sessionId`, and a new `platformRpcRelay` counter (method, chain, outcome). Register it inside the platform-tier block in `app.ts` (D3).
- [x] 1.5 Add `test/platform-rpc.test.ts` covering every scenario in `specs/platform-chain-reads/spec.md`: session/Origin/tenant-key refusals, the 404 when the platform tier is off, unserved chain, `-32601` for write/debug/trace, 400 for a batch, 413 for a 20 KiB body, the log-range guard both ways, the per-session limit and its separation from the tenant-management budget, node error passthrough, `-32023` with no URL leaked.
- [x] 1.6 Measure the chain reads per Overview refresh against the e2e roster (count `platformRpcRelay` increments over one refresh). Confirm the 1200/min default is at least 4× that, or raise it and update D5.
- [x] 1.7 Regenerate `openapi/openapi.json` with the new route under the `platform` tag and `platformSession` security, and run the wallet-api suite and typecheck.

## 2. paymaster-admin container

- [x] 2.1 In `docker/entrypoint.sh`, when `GIANO_WALLET_API_UPSTREAM` is set, rewrite every deployment's `rpcUrl` to `/api/v1/platform/rpc/<chainId>` after the field allowlist, render no `/rpc/*` locations, and ignore `GIANO_RPC_PROXY`. Comment why, in the file's existing style (D8).
- [x] 2.2 For standalone mode, render a file-scope `limit_req_zone` (constant key, rate from `GIANO_RPC_PROXY_RATE`, default `20r/s`, form validated with `sh` only), and inside each generated `/rpc/<chainId>` location `limit_req … burst=<2×> nodelay`, `limit_req_status 429` and `client_max_body_size 16k`.
- [x] 2.3 Add `add_header_inherit merge;` at server level in `docker/nginx.conf.template` and update the template's comments (D9).
- [x] 2.4 Build the image and check both modes by hand: rendered `default.conf` and `/config.json` with and without the upstream (no keyed URL anywhere in hosted mode), `curl -I` on `/`, `/config.json`, `/assets/<file>` and `/api/…` showing all four security headers, and in standalone mode a 413 for a 20 KiB POST and 429s under a burst on `/rpc/<id>`.

## 3. paymaster-admin SPA

- [x] 3.1 Move `PlatformSessionProvider` in `App.tsx` up to wrap both areas, still keyed on `deploymentKey(deployment)`. Area switches must not remount it (D6).
- [x] 3.2 Lift the sign-in view (and its "platform API disabled" 404 state) so that when `platformApi` is true the Paymaster area shows it until a session exists. After sign-in the console stays on the current area.
- [x] 3.3 Change `createReadClient(deployment, token?)` in `lib/chain.ts` to attach `Authorization: Bearer` and use `onFetchResponse` so a 401 ends the session (D7). Have `usePaymaster` build the client only once a token exists and drop its cached data and polling when the session ends.
- [x] 3.4 Leave `platformApi: false` untouched: Paymaster tabs read through `rpcUrl` with no wallet and no sign-in.
- [x] 3.5 Typecheck, lint (Biome) and build the console.

## 4. e2e

- [x] 4.1 Update `e2e/tests/paymaster-admin.spec.ts` to sign in as the console's injected anvil account 0 (`admin-console`) before each read-dependent test.
- [x] 4.2 Add cases: an anonymous visit shows sign-in only and makes no `/api/v1/platform/rpc` call; a signed-in Overview's reads all go to `/api/v1/platform/rpc/<chainId>` with a bearer token; switching areas keeps the session; a POST to `/rpc/<chainId>` on the hosted console is answered 405 by nginx, not proxied; `/config.json` and an `/assets/*` file carry the four security headers.
- [x] 4.3 Re-run `platform-console.spec.ts` and `platform-admin.spec.ts` and fix anything the lifted session changed, then run the full e2e suite.

## 5. Docs

- [x] 5.1 Console README: the hosted access model (platform admin sign-in gates every read, the shell is public on purpose and why), the standalone mode's need for the operator's own SSO or VPN, what `GIANO_RPC_PROXY` exposes, `GIANO_RPC_PROXY_RATE`, and why to set `walletRpcUrl`.
- [x] 5.2 `specs/INFRASTRUCTURE.md` and `specs/PLATFORM-ADMIN-SPECS.md`: the new route, the two new wallet-api variables, the console no longer proxying `/rpc` when the upstream is set, and that console access means a `platform_admins` row.

## 6. Ship

- [x] 6.1 Run `openspec validate gate-paymaster-console-reads --strict` and fix any findings.
- [ ] 6.2 List `platform_admins` on dev (and stg/prd where they exist) and compare it with the people who use the console. Report the gaps to the user before deploying, and don't add anyone without their say-so.
- [ ] 6.3 Open the PR on `fix/g10-console-access` with the accepted R1 deviation and the non-goals (G3, G9, ALB OIDC, wallet-web X3) stated in the description.
