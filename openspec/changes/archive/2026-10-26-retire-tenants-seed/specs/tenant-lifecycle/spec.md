## MODIFIED Requirements

### Requirement: Tenants have a lifecycle
Every tenant SHALL be in exactly one state: `active`, `suspended` or `deleted`. The only transitions SHALL be these:
- creation, by a platform admin or, on a local stack, by the tenant fixtures, which yields `active`;
- `active → suspended`, through `POST …/suspend` with a required `{ reason }`;
- `suspended → active`, through `POST …/resume`;
- `suspended → deleted`, through `DELETE …`.

`deleted` SHALL be terminal. Any other transition SHALL return `409 invalid-transition`. Transitions SHALL be serialised per tenant, so that two concurrent identical transitions yield one success and one `409`. Existing tenants SHALL be `active` after migration.

#### Scenario: Concurrent suspends
- **WHEN** two platform admins suspend the same active tenant at once
- **THEN** one receives 200 and the other receives 409 `invalid-transition`

#### Scenario: Resume an active tenant
- **WHEN** a platform admin resumes a tenant that is active
- **THEN** the response is 409 `invalid-transition`

## REMOVED Requirements

### Requirement: The seed and platform admins own tenants exclusively
**Reason**: `TENANTS_SEED` is retired. Tenants have a single owner, the platform admins.
**Migration**: None needed. Every tenant is platform-admin-managed.
