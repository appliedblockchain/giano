## Decisions

**E1. The environment is code, keyed by one variable.** `GIANO_ENVIRONMENT` is the only deployment identity the image can't know by itself. On AWS it equals the Terraform workspace. Everything derived from it lives in `src/environments.ts`, so changing a domain is a reviewed release. The sign-in domain is never stored: editing it from the console would sign everyone out, including the operator who changed it. `GIANO_DEPLOYMENT_CLASS` stays, because it is a class (development/testnet/production) and dev and staging would share one.

**E2. Bootstrap writes only into an empty table.** It writes once per database, recorded as `bootstrap` by `bootstrap:<environment>`. Afterwards the list belongs to the operators, and a release that changes `bootstrapOperators` has no effect on a database that already has an operator. This also gives a way back if a database ends up with no operators: the next deploy re-seeds it.

**E3. An init container, not the app, prepares the database.** wallet-api never migrates or seeds. `dist/init.js` runs in its own container before the API: an ECS init container with `condition SUCCESS`, and a compose `init` service with `service_completed_successfully`. It runs on every task start, so each step is idempotent and serialised by advisory locks (migrations, operator writes and tenant writes each have their own).

**E4. Tenant fixtures fold into init, gated by the map.** Only environments marked `localStack` accept `TENANT_FIXTURES`. Elsewhere init refuses before touching the database, so no live configuration can create a tenant.

**E5. Guards.** All operator writes take one advisory lock. Removing yourself and removing the last operator are both refused; the second is unreachable through the API while the first holds, and stays as defence in depth. Removal revokes open sessions, and the session guard re-reads the table on every request.

**E6. `reference` has no console.** A client-run deployment has no operator domain of Giano's, so no operator routes are registered. Giving a reference deployment operators means adding its environment to the map.

## Risks

- **H-b reversed**: whoever can write the database can mint an operator. This is accepted for runtime manageability, and mitigated as described in the proposal.
- **`/v1/operator/*` is always registered wherever a domain is set.** O-3's ask to restrict it at the public `api.*` listener is still open.
