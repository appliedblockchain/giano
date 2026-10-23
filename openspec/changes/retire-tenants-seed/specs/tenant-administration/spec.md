## ADDED Requirements

### Requirement: Seed-managed tenants are handed to the platform admins once
At boot, before it serves traffic, `wallet-api` SHALL make every tenant marked seed-managed platform-admin-managed. It SHALL keep the tenant's fields, admin keys and lifecycle state, increment its version, and append an `adopt` history entry by `system:tenants-seed-retirement`. When `TENANTS_SEED` is set, `wallet-api` SHALL log a warning that it is no longer read and SHALL NOT act on it. Replicas booting concurrently SHALL adopt each tenant exactly once.

#### Scenario: First boot after the upgrade
- **WHEN** a database written by an earlier version holds seed-managed tenants `example` and `byoui`, and the new version boots
- **THEN** both are platform-admin-managed, accept platform admin updates, and each has one `adopt` history entry by `system:tenants-seed-retirement`

#### Scenario: Later boots
- **WHEN** no seed-managed tenant is left
- **THEN** the boot step writes nothing

#### Scenario: Leftover variable
- **WHEN** `TENANTS_SEED` is still set on a deployment
- **THEN** a warning is logged and no tenant is created or changed from it

## REMOVED Requirements

### Requirement: Seed-managed tenants are read-only to platform admins except suspend and resume
**Reason**: No tenant is seed-managed after the boot step above. `POST …/adopt`, `409 seed-managed` and `409 still-seeded` are gone.
**Migration**: None needed. Every write is allowed on every tenant, subject to its lifecycle state.
