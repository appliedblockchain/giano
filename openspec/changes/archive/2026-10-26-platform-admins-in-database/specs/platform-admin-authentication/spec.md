## MODIFIED Requirements

### Requirement: Platform admin routes accept only platform admin sessions
Every `/v1/platform/*` route except challenge and verify SHALL require a bearer platform admin session. The session must be unrevoked and unexpired, and its address must still belong to a row in the `platform_admins` table. The request SHALL be attributed to the platform admin id that table currently gives that address. A tenant admin key SHALL never authorise a platform route, and a platform admin session SHALL never authorise a `/v1/admin/*` route.

#### Scenario: Tenant admin key on a platform route
- **WHEN** a valid tenant admin key is presented to `GET /v1/platform/tenants`
- **THEN** the response is 401

#### Scenario: Platform admin session on a tenant admin route
- **WHEN** a valid platform admin session token is presented to a `/v1/admin/*` route
- **THEN** the response is 401

#### Scenario: Platform admin removed
- **WHEN** a platform admin is removed and a session issued to them before the removal is presented
- **THEN** the response is 401, with no restart needed

#### Scenario: Expired session
- **WHEN** a session is presented after `expiresAt`
- **THEN** the response is 401

## REMOVED Requirements

### Requirement: Platform admins are configured, never stored
**Reason**: Platform admins are rows in the `platform_admins` table, managed by platform admins (see `platform-admin-management`). The sign-in domain comes from the environment map (see `deployment-init`).
**Migration**: Each environment's bootstrap platform admins are written into its empty table by the init step. `OPERATOR_ADDRESSES` and `OPERATOR_SIWE_*` are no longer read.
