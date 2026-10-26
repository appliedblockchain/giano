## Context

Before this change, two writers owned tenants: the boot seed and the platform admins. `managed_by` recorded which one owned a tenant, and adopt moved a tenant from the seed to the platform admins. With the console's Platform area in place, the seed is the only reason those rules exist.

## Decisions

**R1. The API never creates a tenant.** Fixtures are a separate entry point (`dist/tenant-fixtures.js`), not an env-gated boot step of the API. A boot step would put tenant creation back behind a variable that a live task definition could carry by mistake. A separate command can't run unless someone runs it.

**R2. Fixtures only insert.** A slug that already exists is skipped, including a deleted one. Once created, a fixture tenant is an ordinary platform admin tenant, so a restart never reverts a console edit. `down -v` is what restores the committed values. This matches the stance of the sponsorship and tx-mapping provisioners: nothing local re-imposes state a tenant or platform admin owns.

**R3. Fixtures write directly rather than through the platform API.** The e2e devnet paymaster is pre-registered against fixed tenant ids, and the provisioners and the e2e suite authenticate with fixed admin keys. The platform API generates keys server-side (H-i), so it can't reproduce them. Fixtures still go through the same field schema, the same invariants and the same origin-claim check under the tenant-write lock.

**R4. The retirement is a boot step in the app, not a SQL migration.** It writes a history entry per tenant through the same `appendTenantHistory` every write uses, and it can warn about a leftover `TENANTS_SEED`. Being app code, it can be deleted in the follow-up change, while an applied SQL migration stays forever. It reuses the existing `adopt` history action, so the database needs no new CHECK value.

**R5. `managed_by` stays for one release.** The retirement reads it, and writes keep setting `'operator'`. The follow-up change drops it once every deployment has booted this release.

## Risks

- **Live environments have no platform admins configured yet.** Existing tenants keep working, but nobody can change them until devops sets `OPERATOR_ADDRESSES` / `OPERATOR_SIWE_DOMAIN` and the console upstream.
- **`ADMIN_API_KEY` in run-task overrides is visible in the ECS task description.** Mitigation: issue a key for the run and revoke it afterwards (documented in Terraform and the compose mirror).
- **A pre-tenancy `default` row** (0002's `migrated.invalid` sentinel) that nobody claimed is handed to the platform admins like any other. Only the old seed could claim it, so a platform admin suspends and deletes it if it exists.
