## Purpose

Defines who the platform admins are once they are stored in the database: how a deployment gets its first platform admins, how platform admins change the list, and the guards that keep a deployment administrable.

## ADDED Requirements

### Requirement: Bootstrap platform admins are written only into an empty table
The init step SHALL write the environment's bootstrap platform admins, each with a `platform_admin_history` entry `bootstrap` by `bootstrap:<environment>`, only when the `platform_admins` table has no row. Otherwise it SHALL write nothing. Concurrent runs SHALL write each platform admin once.

#### Scenario: First deploy
- **WHEN** init runs for `dev` against a database with no platform admins
- **THEN** `giovanni` is a platform admin, added by `bootstrap:dev`

#### Scenario: Later deploys
- **WHEN** init runs against a database with any platform admin, even after a release changed the bootstrap list
- **THEN** the platform admins are unchanged

### Requirement: Platform admins manage platform admins
A signed-in platform admin SHALL list platform admins with `GET /v1/platform/admins`, add one with `POST /v1/platform/admins { id, address }`, remove one with `DELETE /v1/platform/admins/:id`, and read the changes with `GET /v1/platform/admins/history`. An added platform admin SHALL be able to sign in at once. A duplicate id or address SHALL return `409 conflict` naming the field.

#### Scenario: Add
- **WHEN** a platform admin adds `{ id: "ops-new", address }`
- **THEN** the response is 201, the new platform admin can sign in, and history has an `add` entry by the adding platform admin

### Requirement: The deployment always keeps a platform admin
Removing yourself SHALL return `409 self-removal`. Removing the last platform admin SHALL return `409 last-admin`. A removal SHALL revoke the removed platform admin's open sessions and SHALL be recorded as `remove`.

#### Scenario: Self-removal
- **WHEN** a platform admin tries to remove their own row
- **THEN** the response is 409 `self-removal`, and they remain a platform admin

#### Scenario: Removal ends sessions
- **WHEN** a platform admin removes another who is signed in
- **THEN** the removed platform admin's next request returns 401
