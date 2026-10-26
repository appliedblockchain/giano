## Context

The behaviour is in this change's `specs/`, and the motivation is in proposal.md. The console section of the technical spec is `specs/OPERATOR-ADMIN-SPECS.md` §11, revised 2026-10-21. The operator API it drives was shipped by `operator-tenant-lifecycle` and is described in `services/wallet-api/openapi/openapi.json`.

These facts about the console shape the approach:
- **Stack.** `services/paymaster-admin` is a Vite + React 19 + Chakra UI v3 SPA. It reads the chain through `@appliedblockchain/giano-paymaster-sdk` and writes through an injected wallet (`ConnectedWallet.walletClient`). It has no backend and no unit-test runner; it is covered by `typecheck`, `build` and `e2e/tests/paymaster-admin.spec.ts`.
- **Config.** `/config.json` is rendered at boot by `docker/entrypoint.sh`, which runs on the DHI nginx runtime and has only `sh`, `envsubst` and `jq`. The nginx template has per-chain `/rpc/<chainId>` locations with literal upstreams. Its comment says a variable `proxy_pass` "would need a resolver this image cannot assume".
- **Resolver precedent.** `wallet-web` solved the resolver problem: its entrypoint reads the first IPv4 nameserver from `/etc/resolv.conf`, and its template uses `resolver ${GIANO_RESOLVER}`, `set $giano_wallet_api ${GIANO_WALLET_API_UPSTREAM}` and a regex `/api/` location.
- **Reloads.** `App.tsx` reloads on `accountsChanged` and `chainChanged`, except while the console itself is driving a switch. `selectDeployment` drops the wallet.
- **Roster and roles.** `usePaymaster` returns `overview.tenants` (`TenantView`: `id` as bytes16, `uuid`, `status`, `enabled`) and `myRoles` for the connected wallet. `TenantsPanel` already performs `registerTenant` and `setTenantEnabled` through `useWrite`.
- **Test wallet.** The e2e wallet injected by `paymaster-admin.spec.ts` forwards any method it does not handle to anvil through `/rpc/<chainId>`, and anvil answers `personal_sign` for its unlocked accounts. On the devnet, anvil account 0 holds every paymaster role.

## Goals / Non-Goals

**Goals:**
- Give the operator API a UI with no new backend and no new dependency.
- Make the Paymaster side unchanged where `GIANO_WALLET_API_UPSTREAM` is unset.
- Make one registry view the place where the backend and on-chain views of a tenant meet.

**Non-Goals:**
- Any `wallet-api` change.
- The Chains tab.
- Sponsorship rule editing.
- Code generation from OpenAPI.
- A unit-test runner for the console.

## Decisions

**C1 — The `/api` location is rendered by the entrypoint, only when the upstream is set.** The entrypoint ports `wallet-web`'s resolv.conf loop as is. Where the template today has `${GIANO_RPC_LOCATIONS}`, it gains `${GIANO_API_LOCATION}`. That holds either an empty string or the rendered block:
- `resolver …`;
- `set $giano_wallet_api …`;
- `location ~ ^/api/(?<giano_api_path>.*)$` with `proxy_pass $giano_wallet_api/$giano_api_path$is_args$args`;
- `proxy_set_header Origin ""`, and `Host $proxy_host`.

`config.json.template` gains `"operatorApi": ${GIANO_OPERATOR_API}`, which renders as `true` or `false`.
*Rejected:* a static block in the template guarded by a variable. nginx cannot leave out a location conditionally, and a resolver line with an empty address would fail when the config loads.

**C2 — A thin hand-written client, `src/lib/operator-api.ts`.** It holds typed functions per route, a single `request()` that adds the bearer token and maps responses to typed results (`ok`, or `{ status, error, message, …detail }`), and an `OperatorUnauthorized` error raised on `401`. Types mirror `openapi.json` by hand (OPERATOR-ADMIN-SPECS §11.1). *Rejected:* openapi-typescript, which would be new tooling for 14 routes.

**C3 — The session is a React context, `src/lib/operator-session.ts`.** An `OperatorSessionProvider` holds `{ token, operator, expiresAt }` in state, and nothing else.
- `useOperator()` gives `signIn(wallet, chainId)`, `signOut()` and a `call(fn)` wrapper that clears the session on `OperatorUnauthorized`.
- `App.tsx` renders the provider keyed on the deployment, so a deployment switch remounts it and the session is gone. That is the same idiom as dropping the wallet.
- The existing `accountsChanged` and `chainChanged` reload already clears it.
- An expiry timer clears it at `expiresAt`.

*Rejected:* `sessionStorage`. It survives reloads, which the spec forbids, and it is readable by any script on the origin.

**C4 — Sign-in signs exactly what the server returned.** `walletClient.signMessage({ account: wallet.address, message })`, which is `personal_sign` on the raw string. A user rejection (`isUserRejection`) returns to the view quietly. A `401` from verify shows "not on this deployment's operator list". A `404` from challenge shows "operator API disabled on this deployment".

**C5 — The area switch is a segmented control in the header, shown only when `operatorApi` is true.**
- Paymaster renders today's `Tabs` untouched.
- Operator renders `<OperatorArea>`: the sign-in view without a session, otherwise the Tenants tab and an operator badge with *Sign out*.
- The selected area lives in component state and is not remembered, so a reload lands on Paymaster.

The paymaster overview still loads in the Operator area, because the on-chain column needs `overview.tenants` and `myRoles` from `usePaymaster`.

**C6 — The join is computed in the tab.** The tab builds `Map<uuid, TenantView>` from `overview.tenants` for the selected deployment, then labels each registry row from it. Roster entries absent from the registry list form the "on-chain only" group. The registry list is fetched with `?status=` for the filter. The on-chain column updates when the console's existing polling refreshes the overview. The registry list refreshes after every operator action and on the header's refresh button.

**C7 — One dialog per flow, built from the existing Chakra `Dialog` pattern in `TenantsPanel`.**
- **Create.** Origins are entered one per line. Sending the body unchanged keeps the API the only validator. Issues are mapped from the JSON-pointer `path` of the `400` body to fields.
- **Edit.** Policy and branding are JSON text areas. They are parsed in the browser only to say "not valid JSON"; the shape is still checked by the API.
- **Suspend.** The follow-up step reuses `useWrite` with `client.setTenantEnabled(uuid, false)`.
- **Create's register step.** Reuses `client.registerTenant(uuid, withdrawAddress, slug)` and asks for the withdraw address, the way the existing register dialog does.
- **Delete.** A typed-slug guard.
- **Issue key.** Shows the generated key once.

**C8 — The drawer reads detail and history lazily, and the only cache is component state.** Detail is reloaded after every action on that tenant. History is paged with `before` and appended.

**C9 — The e2e spec shares the injected wallet.** `installWallet` moves from `paymaster-admin.spec.ts` to `e2e/tests/console-wallet.ts`, and both specs import it. The e2e compose stack adds anvil account 0 to `OPERATOR_ADDRESSES` as `ops-console`, keeping `ops-e2e`. It gives `paymaster-admin` `GIANO_WALLET_API_UPSTREAM: http://wallet-api:8080` (the value `wallet-web` uses) and `depends_on: wallet-api: service_healthy`, and changes the comment that says the console needs no `wallet-api`.

## Risks / Trade-offs

- **[The proxy's resolver line differs per platform]** → It is read from `/etc/resolv.conf` as in `wallet-web`, and it is only rendered when the upstream is set. A console without the variable keeps today's config byte for byte. That is checked by a container smoke run with and without the variable.
- **[An operator loses the session on a chain switch or deployment switch]** → Accepted (OPERATOR-ADMIN-SPECS §4.6). Signing in again costs one signature.
- **[An action half-completes when the API succeeds and the on-chain follow-up fails or is declined]** → By design. The follow-up is offered, not required, and the registry's on-chain column shows the true state either way.
- **[The registry and the roster refresh on different schedules]** → Refresh re-reads both. The column carries the overview's last-updated time.
- **[A test-only key in e2e]** → Anvil account 0's key is already public and is used only on the devnet stack.
- **[The console bundle grows]** → It adds only components; there are no new dependencies.

## Migration Plan

1. Ship the image with no new variable set. Every existing deployment renders the same nginx config and `operatorApi: false`, and looks unchanged.
2. To enable on a deployment, devops sets `GIANO_WALLET_API_UPSTREAM` on the `paymaster-admin` task (O-3). `wallet-api` must have `OPERATOR_ADDRESSES` and `OPERATOR_SIWE_DOMAIN`, and the domain must equal the console's host.
3. Rollback: unset the variable, or deploy the previous image. Nothing persists in the console.
