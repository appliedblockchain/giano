## 1. Proxy and runtime config

- [x] 1.1 In `services/paymaster-admin/docker/entrypoint.sh`, port `wallet-web`'s `/etc/resolv.conf` nameserver loop. When `GIANO_WALLET_API_UPSTREAM` is set, render `GIANO_API_LOCATION`:
  - `resolver`;
  - `set $giano_wallet_api`;
  - the regex `/api/` location with `proxy_set_header Origin ""` and `Host $proxy_host`.

  Otherwise render it empty. Export `GIANO_OPERATOR_API` as `true` or `false`, and add both variables to the `envsubst` lists. Use `sh`, `envsubst` and `jq` only (design C1).
- [x] 1.2 Add `${GIANO_API_LOCATION}` to `docker/nginx.conf.template`, next to `${GIANO_RPC_LOCATIONS}`, and correct its comment about resolvers. Add `"operatorApi": ${GIANO_OPERATOR_API}` to `docker/config.json.template`.
- [x] 1.3 Smoke the image both ways with `docker run`:
  - without the variable, the rendered `default.conf` has the same directives as today's (only the comment from 1.2 differs) and `config.json` has `operatorApi: false`;
  - with it, `/api/healthz` reaches a stub upstream and the upstream sees no `Origin` header.
- [x] 1.4 Add `operatorApi` to `src/config.ts`, as a boolean that is false when absent, with its doc comment.

## 2. Client and session

- [x] 2.1 Write `src/lib/operator-api.ts`: hand-written types for the operator routes the console uses, a `request()` that adds the bearer and returns typed results or `{ status, error, message, …detail }`, and `OperatorUnauthorized` on `401` (design C2).
- [x] 2.2 Write `src/lib/operator-session.ts`: `OperatorSessionProvider` and `useOperator()` with `signIn(wallet, chainId)` (challenge, `walletClient.signMessage`, verify), `signOut()` (logout, then forget), `call()` (clears on `OperatorUnauthorized`), and an expiry timer. Memory only (design C3, C4).

## 3. Area switch and sign-in

- [x] 3.1 In `src/App.tsx`, add the Paymaster | Operator switch to the header, shown only when `operatorApi` is true. Wrap the Operator area in `OperatorSessionProvider`, keyed on the deployment, so a switch drops the session. Leave the Paymaster tabs untouched (design C5).
- [x] 3.2 Write `src/operator/OperatorArea.tsx` and `src/operator/SignIn.tsx`:
  - the sign-in view: connect if needed, then sign; quiet on a user rejection; "not on this deployment's operator list" on `401`; "operator API disabled" on `404`;
  - once signed in, the operator badge with id, address, expiry and *Sign out*.

## 4. Tenants tab

- [x] 4.1 Write `src/operator/TenantsTab.tsx`:
  - the registry table (slug, id, status, owner, wallet origin, users), with a filter that includes deleted tenants;
  - the on-chain column joined from `overview.tenants` by uuid;
  - the "on-chain only" group;
  - refresh (design C6).
- [x] 4.2 Write `src/operator/TenantDrawer.tsx`:
  - fields, state, owner and version;
  - keys without material;
  - counts and last user-operation time;
  - the ledger;
  - history paged with `before`;
  - the actions allowed by state and owner, per the spec table;
  - the seed-managed note (design C8).
- [x] 4.3 Write `src/operator/CreateTenantDialog.tsx`:
  - the form, with origins one per line;
  - `400` issues mapped to fields by path, and `409` explained;
  - the keys shown once, with copy controls;
  - the optional *Register on <chain>* step through `client.registerTenant`, gated on `TENANT_ADMIN_ROLE`;
  - the wallet-origin and sponsorship notes.
- [x] 4.4 Write `src/operator/EditTenantDialog.tsx`: mutable fields prefilled, identity fields read-only, policy and branding as JSON text areas, `If-Match`, and on `412` reload while keeping the operator's input.
- [x] 4.5 Write `src/operator/LifecycleDialogs.tsx`:
  - suspend with a required reason, then offer `setTenantEnabled(false)`;
  - resume, then offer `setTenantEnabled(true)`;
  - delete with the typed slug and the `409` figures;
  - adopt, explaining `still-seeded`;
  - issue key (shown once) and revoke key (confirm, explaining `last-admin-key`).

  On-chain steps are gated on `TENANT_ADMIN_ROLE`, and never roll back the API action.
- [x] 4.6 Run `pnpm --filter @appliedblockchain/giano-paymaster-admin typecheck` and `build`, both clean.

## 5. E2E

- [x] 5.1 Move `installWallet` and its helpers from `e2e/tests/paymaster-admin.spec.ts` into `e2e/tests/console-wallet.ts`, and import them from both specs; `paymaster-admin.spec.ts` still passes.
- [x] 5.2 Update `deploy/docker-compose.e2e.yml`:
  - `wallet-api` lists anvil account 0 as `ops-console`, next to `ops-e2e`;
  - `paymaster-admin` gains `GIANO_WALLET_API_UPSTREAM: http://wallet-api:8080` and `depends_on: wallet-api: service_healthy`, and its "needs neither wallet-api" comment is updated.
- [x] 5.3 Write `e2e/tests/operator-console.spec.ts`:
  - connect with the injected wallet, then *Sign in with wallet*;
  - `stock` and `byo` show as active, seed-managed and *registered · enabled*;
  - create a fresh-slug tenant, see its keys once, then *not registered*;
  - suspend it, then delete it by typing the slug;
  - reload and land on sign-in, with nothing in browser storage.
- [x] 5.4 Run the full e2e suite on a rebuilt stack and record the results.

## 6. Docs and wrap-up

- [x] 6.1 Update the docs:
  - `services/paymaster-admin/README.md`: `GIANO_WALLET_API_UPSTREAM` and the Operator area;
  - `specs/INFRASTRUCTURE.md` R31: the console proxies `/api` (O-6);
  - `specs/OPERATOR-ADMIN-SPECS.md` §13: tick D6, tenant half.
- [x] 6.2 Hand the user the local walkthrough at `http://paymaster.localhost`, then commit and open the PR on request.
