## Why

Tenants are now administered by Giano's platform admins in the paymaster console's Platform area (`platform-tenant-lifecycle`, `platform-console`). `TENANTS_SEED` is a second writer that the platform tier has to work around. Its tenants are read-only to platform admins, it can take a platform-admin-managed tenant over at boot, and the adopt flow only exists to move a tenant out of it. A live deployment should boot with no tenants and get every tenant from its platform admins. Only local stacks need ready-made test tenants.

## What Changes

- **BREAKING** `wallet-api` no longer reads `TENANTS_SEED`. If the variable is still set, wallet-api logs a warning and ignores it. The service boots with zero tenants and only logs that none are active.
- **One-time migration at boot.** Every tenant still marked `managed_by = 'seed'` is handed to the platform admins: `managed_by = 'operator'`, version + 1, and an `adopt` history entry by `system:tenants-seed-retirement`. Fields, admin keys and lifecycle state are kept. Once no such row is left the step does nothing. It and the `managed_by` column are removed in a follow-up cleanup change.
- **Removed** the seed upsert and takeover, the seed-managed write restrictions (`409 seed-managed`), `POST /v1/platform/tenants/:slug/adopt` (`409 still-seeded`), and `managedBy` in platform API responses. In the console: the Adopt dialog, the owner badge and the "Managed by" column.
- **Local tenant fixtures.** A separate one-shot command, `node dist/tenant-fixtures.js` (`TENANT_FIXTURES`), applies migrations and creates the listed tenants that don't exist yet. It accepts pinned ids and plaintext admin keys. The dev, e2e, loopback and Sepolia-demo compose files run it before wallet-api. Live deployments never do.
- **`provision-sponsorship`** takes the tenant's admin key as `ADMIN_API_KEY` instead of reading it from the seed. Terraform no longer injects the `tenants-seed` secret into any task.

## Capabilities

### New Capabilities
- `local-tenant-fixtures`: how a local stack gets its test tenants without the API ever creating one.

### Modified Capabilities
- `tenant-lifecycle`: tenants have one owner, the platform admins. The seed coexistence rules are replaced by the one-time retirement.
- `tenant-administration`: no seed-managed restrictions and no adopt. History actors are now platform admins, fixtures and the retirement.
- `platform-console-tenants`: no owner column, no seed note and no adopt flow.

## Impact

- **Code**: `services/wallet-api` (config, boot, tenants, tenant-admin, platform routes, OpenAPI, new `tenant-fixtures` and `tenants-seed-retirement`, tsup entry), `services/paymaster-admin` (Platform area).
- **Deploy**: every compose file under `deploy/`, `infra/iac/ecs_services.tf` and `infra/iac/ecs_tasks_oneshot.tf`.
- **Rollout**: deploy as usual. The first boot hands the existing tenants to the platform admins. Tenants can then only be changed once `OPERATOR_ADDRESSES` and `OPERATOR_SIWE_DOMAIN` are set on wallet-api and the console has `GIANO_WALLET_API_UPSTREAM`. The `tenants-seed` ASM/1Password entry becomes unused, and devops can delete it after rollout.
- **Follow-up**: remove `tenants-seed-retirement.ts` and its tests, and drop `tenants.managed_by` in a migration.
