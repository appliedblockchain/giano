## Why

PR 1 (`operator-tenant-lifecycle`) gave `wallet-api` an operator tier: tenants can be created, edited, suspended and deleted at runtime through `/v1/operator/*`. The only way to use it today is curl and a signing script. H5 asks for an admin application, and an operator needs to see in one place both the backend registry and the paymaster's on-chain roster. Those two are joined on tenant id, and neither can show the other.

This is PR 2 of H5 (`specs/OPERATOR-ADMIN-SPECS.md` §1.1, D6), covering the tenant half of the console's Operator area. The Chains tab (D5) is a separate card (H-k).

## What Changes

- **Same-origin `/api` proxy in `paymaster-admin`.** The nginx image gains a regex `/api/` location that forwards to `wallet-api` and removes the browser's `Origin`. It is rendered only when `GIANO_WALLET_API_UPSTREAM` is set, and uses a resolver read from `/etc/resolv.conf`, the way `wallet-web` does it. The entrypoint stays within `sh`, `envsubst` and `jq`.
- **`config.json` gains `operatorApi: boolean`.** It is true exactly when the upstream is configured. When it is false, the Operator area is not shown at all.
- **A top-level Paymaster | Operator switch in the console.** The Paymaster side keeps every existing tab unchanged.
- **Operator sign-in.** "Sign in with wallet" uses the wallet the console already connects. It fetches the server-written EIP-4361 message, has the wallet `personal_sign` it, and exchanges the signature for an operator session.
  - The session is held in React state only.
  - A `401`, an account or chain change, a deployment switch or a reload sends the operator back to sign-in.
  - Logout ends the session.
- **Tenants tab.** A registry table showing slug, id, status, owner, wallet origin and user count. For the selected chain it also shows the on-chain status from the paymaster roster, joined by tenant id: *registered · enabled*, *registered · disabled* or *not registered*. A separate group lists on-chain tenants that have no registry row.
- **Tenant drawer.** Fields, admin keys (no key material), ledger position and paginated history.
- **Actions, each mapped to one operator route.** Create, edit, suspend, resume, delete, issue and revoke keys, and adopt:
  - Create shows the generated admin keys once. It then offers an optional on-chain *Register on <chain>* step, and says that serving the wallet origin and setting up sponsorship are still to do.
  - Edit sends `If-Match` and reloads on `412`.
  - Suspend requires a reason. It then offers `setTenantEnabled(false)` on the selected chain; resume offers the reverse.
  - Delete requires typing the slug and shows the per-chain figures returned by a `409`.
  - The on-chain steps need `TENANT_ADMIN_ROLE` and are disabled without it.
- **E2E smoke test.** The two-tenant stack lists anvil account 0 as an operator and gives the console `GIANO_WALLET_API_UPSTREAM`. A Playwright spec signs in with the injected test wallet, checks the registry and its on-chain column, then creates, suspends and deletes a tenant through the UI.
- **No change to `wallet-api`.** Behaviour, routes and OpenAPI stay as PR 1 shipped them.

## Capabilities

### New Capabilities
- `operator-console-access`: how the console reaches the operator API and who may use it. Covers the `/api` proxy and its `Origin` stripping, the `operatorApi` switch, wallet sign-in, session lifetime in the page, and how sign-out and `401` behave.
- `operator-console-tenants`: what an operator sees and can do in the Tenants tab. Covers the registry joined to the on-chain roster, the tenant drawer, and the create, edit, lifecycle, key and adopt flows, including the optional on-chain follow-up steps and how refused writes are shown.

### Modified Capabilities
None. `openspec/specs/` has no console capability. The prose specs are updated in the tasks.

## Impact

- **Code (`services/paymaster-admin`)**:
  - `docker/nginx.conf.template`, `docker/entrypoint.sh`, `docker/config.json.template`
  - `src/config.ts`: `operatorApi`
  - `src/App.tsx`: the area switch, plus clearing the session on a deployment switch
  - new `src/lib/operator-api.ts` and `src/lib/operator-session.ts`
  - new `src/operator/` components
- **Deploy**: `deploy/docker-compose.e2e.yml`
  - `paymaster-admin` gains `GIANO_WALLET_API_UPSTREAM` and depends on `wallet-api`.
  - `wallet-api` lists anvil account 0 as a second operator.
  - Other stacks are unchanged: without the variable, the console looks exactly as it does today.
- **E2E**: new `e2e/tests/operator-console.spec.ts`. It reuses the injected wallet from `paymaster-admin.spec.ts`, moved into a shared helper.
- **Dependencies**: none new.
- **Docs**:
  - `services/paymaster-admin/README.md`: the new variable and the Operator area
  - `specs/INFRASTRUCTURE.md` R31: the console now does proxy `/api` (O-6)
  - `specs/OPERATOR-ADMIN-SPECS.md` §13: tick D6, tenant half
- **Devops (O-3)**: `GIANO_WALLET_API_UPSTREAM` on the `paymaster-admin` task is the only new variable. `/v1/operator/*` reaches `wallet-api` through the console, so the restriction on `api.*` is unchanged.
- **Out of scope**:
  - the Chains tab (D5);
  - editing sponsorship rules, which belong to the tenant's own admin key;
  - serving a new tenant's wallet origin (O-5);
  - renaming the console (O-4).
