## REMOVED Requirements

### Requirement: Seed-managed tenants are read-only to platform admins except suspend and resume
**Reason**: No tenant is seed-managed after the boot step above. `POST …/adopt`, `409 seed-managed` and `409 still-seeded` are gone.
**Migration**: None needed. Every write is allowed on every tenant, subject to its lifecycle state.
