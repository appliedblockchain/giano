## MODIFIED Requirements

### Requirement: Operator routes accept only operator sessions
Every `/v1/operator/*` route except challenge and verify SHALL require a bearer operator session. The session must be unrevoked and unexpired, and its address must still belong to a row in the `operators` table. The request SHALL be attributed to the operator id that table currently gives that address. A tenant admin key SHALL never authorise an operator route, and an operator session SHALL never authorise a `/v1/admin/*` route.

#### Scenario: Tenant admin key on an operator route
- **WHEN** a valid tenant admin key is presented to `GET /v1/operator/tenants`
- **THEN** the response is 401

#### Scenario: Operator session on a tenant admin route
- **WHEN** a valid operator session token is presented to a `/v1/admin/*` route
- **THEN** the response is 401

#### Scenario: Operator removed
- **WHEN** an operator is removed and a session issued to them before the removal is presented
- **THEN** the response is 401, with no restart needed

#### Scenario: Expired session
- **WHEN** a session is presented after `expiresAt`
- **THEN** the response is 401

## REMOVED Requirements

### Requirement: Operators are configured, never stored
**Reason**: Operators are rows in the `operators` table, managed by operators (see `operator-management`). The sign-in domain comes from the environment map (see `deployment-init`).
**Migration**: Each environment's bootstrap operators are written into its empty table by the init step. `OPERATOR_ADDRESSES` and `OPERATOR_SIWE_*` are no longer read.
