## Why

Ticket G11 (report item A4) asks for a tenant lifecycle that spans wallet-api and the paymaster. Most of it landed with the platform admin work (H5, #125 → #148 → #150 → #149, and the A1 stack #207 → #210):

- tenants have a lifecycle (`active`, `suspended`, `deleted`), and only an active tenant resolves, for ceremonies, relays, sponsorship, RPC and admin keys (`tenant-lifecycle`);
- platform admins are a tier of their own, in the database, with every write recorded in `tenant_history` and `platform_admin_history` (`platform-admin-management`, `tenant-administration`);
- wallet-api, the console and `giano-doctor` report drift between the registry, the ledger and each paymaster, with a metric (`tenant-chain-drift`).

Three gaps remain:

1. **A tenant that cannot be sponsored on chain is still authorised.** wallet-api reserves and signs a paymaster authorisation for a tenant whose paymaster record is disabled. The paymaster then reverts with `TenantDisabled`, the user sees a bundler error, and the reservation is held until it expires. A tenant with sponsorship switched on that nobody has registered on chain yet is refused as `insufficient-balance` ("this app has run out of fee credit"), which sends its team to fund a tenant that does not exist on chain.
2. **A tenant waiting for its on-chain registration is visible only in the console.** Drift deliberately does not count it ("a step not yet taken"), so `GET /v1/platform/drift`, the metrics and `giano-doctor` do not show it.
3. **Offboarding is not written down.** The pieces exist (suspend, on-chain disable, the tenant's own `withdrawTenant`, tombstone delete), but no runbook states the order, what happens to each kind of data, or what users keep.

## What Changes

- **Sponsorship checks the tenant's paymaster record.** Each sponsorship decision reads the tenant's record from the paymaster, as it already reads its fee. When the tenant has sponsorship switched on but is not registered, or is disabled, on that chain, wallet-api refuses before it reserves or signs. The reason is `sponsorship-disabled`, which every wallet already handles. The decision log records it under a new rule, `paymaster-tenant`, with a detail that says which.
- **Drift lists the tenants waiting for registration.** Each chain's drift result gains `unregistered`: active tenants that have sponsorship switched on for that chain and are not registered on its paymaster. It is not drift. wallet-api exports it as `giano_paymaster_unregistered_tenants{chain}`, and `giano-doctor` warns on it.
- **Offboarding runbook.** `docs/TENANT-OFFBOARDING-RUNBOOK.md` covers the procedure, what is kept and what is removed, and what users keep.

**Non-goals.**
- A `pending-chain` lifecycle status. Registration is per chain, and a tenant may sponsor on one chain and not another, so one status on the tenant row cannot say it. The per-chain state is read from the paymaster, which is its authority.
- wallet-api proposing `registerTenant` or `setTenantEnabled` itself. It holds no `TENANT_ADMIN_ROLE` key, by design (`specs/PLATFORM-ADMIN-SPECS.md` §1.3). The console's guided steps stay the way these calls are made.
- An alert on the drift and unregistered gauges. Datadog does not scrape wallet-api's `/metrics` today, so the alert needs an infra change first. Follow-up.
- Erasure of a deleted tenant's users, credentials and logs. That is a retention policy decision (ticket G34 covers database retention). The runbook states what is kept today.
- A `tenant-enabled-on-chain` precondition on delete. Drift already reports a deleted tenant that is still enabled.

## Capabilities

### New Capabilities
- `tenant-chain-readiness`: wallet-api refuses to sponsor for a tenant its paymaster cannot sponsor, and says why.

### Modified Capabilities
- `tenant-chain-drift`: drift lists the active tenants waiting for registration on each chain, as a list, a metric and a doctor warning.
- `tenant-lifecycle`: offboarding is a written procedure.

## Impact

- **wallet-api:** `services/sponsorship-service.ts` (the `paymaster-tenant` check), `services/drift.ts` and `routes/platform-drift.ts` (`unregistered`), `plugins/metrics.ts` and `index.ts` (the gauge), tests. No migration.
- **contracts (repository script only):** `scripts/doctor-drift.ts` warns on `unregistered`. Not part of the published package, so the changeset is empty.
- **Docs:** `docs/TENANT-OFFBOARDING-RUNBOOK.md`, links from `specs/PLATFORM-ADMIN-SPECS.md`.
- **Console:** unchanged. Its Tenants tab already reads each tenant's registration from the chain and offers *Register on chain*.
- **Overlaps:** G6 (userop policy) edits `userop-policy.ts` and `mergePolicy`. This change touches neither.
