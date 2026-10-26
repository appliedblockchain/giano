# tenant-lifecycle Specification

## Purpose

Defines the states a tenant moves through (active, suspended, deleted) and what each state means for every way a request is attributed to a tenant. It also covers how platform-admin-managed tenants coexist with the boot seed, so a runtime change takes effect on the next request without ever reviving or recycling a tenant by accident.

## Requirements

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

### Requirement: Only active tenants resolve
A tenant that is not active SHALL behave as an unknown tenant everywhere a request is attributed to a tenant. The existing unknown-tenant responses SHALL apply, with no response that reveals the tenant exists:
- an `Origin`-resolved ceremony or relay call returns `403 unknown-tenant`;
- a `Host`-resolved `/.well-known/webauthn` or transaction-mappings read returns `404`;
- its admin key returns `401` on `/v1/admin/*`;
- its CORS origins receive no CORS grant from that tenant.

A user session whose tenant is not active SHALL return `401`, whether or not the request carries an `Origin`. Each change of state SHALL be in force on the next request on every replica, with no restart and no cache.

#### Scenario: Suspended tenant everywhere
- **WHEN** tenant `byo` is suspended
- **THEN**
  - a WebAuthn options call with Origin `app-byo.localhost` returns 403;
  - `/.well-known/webauthn` with `byo`'s Host returns 404;
  - `byo`'s admin key returns 401;
  - an existing `byo` user session returns 401, both with and without an Origin header;
  - tenant `stock` is unaffected throughout.

#### Scenario: Resume restores live sessions
- **WHEN** a suspended tenant is resumed and a user session issued before the suspension, and not yet expired, is presented
- **THEN** the session is accepted

#### Scenario: Background accounting continues
- **WHEN** a suspended tenant's sponsored operation settles on-chain
- **THEN** the paymaster watcher records the settlement and updates the tenant's ledger as for an active tenant

### Requirement: Delete is a tombstone with preconditions
Deleting a tenant SHALL keep its row with status `deleted`. Its slug, id, wallet origin and RP ID SHALL never be reusable. Delete SHALL succeed only when all of these hold:
- the tenant is suspended; otherwise `409 tenant-not-suspended`;
- it is platform-admin-managed; otherwise `409 seed-managed`;
- on every chain its ledger balance and deficit are zero, with a chain that has no ledger row counting as zero; otherwise `409 tenant-has-funds`, with per-chain figures and the block they were read at;
- it has no sponsorship reservation that is reserved and not yet expired; otherwise `409 tenant-has-reservations`;
- on every sponsoring chain the ledger is within `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS` of the chain head, and the head can be read; otherwise `409 ledger-stale`.

A successful delete SHALL return `204`. In the same transaction it SHALL remove the tenant's user sessions, open challenges, pending additions and admin keys. Users, credentials and operation logs SHALL be kept. Boot SHALL refuse a `TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS` that is not greater than `PAYMASTER_WATCHER_CONFIRMATIONS`.

#### Scenario: Delete an active tenant
- **WHEN** a platform admin deletes an active tenant
- **THEN** the response is 409 `tenant-not-suspended`

#### Scenario: Funds attached
- **WHEN** a suspended tenant has a non-zero ledger balance on one chain
- **THEN** the response is 409 `tenant-has-funds` with that chain's balance, deficit and block

#### Scenario: Expired reservation never swept
- **WHEN** a suspended tenant's only reservation is still marked reserved but is past its expiry, because no watcher swept it
- **THEN** the reservation does not block the delete

#### Scenario: No watcher running
- **WHEN** a deployment sponsors on a chain whose ledger has never been synced
- **THEN** delete returns 409 `ledger-stale`

#### Scenario: Never sponsored
- **WHEN** a suspended platform-admin-managed tenant has no ledger rows on any chain and the deployment does not sponsor
- **THEN** delete returns 204

#### Scenario: After delete
- **WHEN** a tenant has been deleted
- **THEN**
  - its user sessions and admin keys no longer exist, and its operation logs are intact;
  - it appears only under `?status=deleted`;
  - a later create reusing its slug, id, wallet origin or RP ID is refused.
