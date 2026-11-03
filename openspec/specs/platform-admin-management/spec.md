# platform-admin-management Specification

## Purpose

Defines who the platform admins are once they are stored in the database: how a deployment gets its first platform admins, how platform admins change the list, and the guards that keep a deployment administrable.

## Requirements

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

### Requirement: Platform admins see sign-ins and sessions
`GET /v1/platform/admins` SHALL return, for each platform admin, the time of their last sign-in, or `null`, and the number of their sessions that are neither expired nor revoked.

`GET /v1/platform/admins/:id/sessions` SHALL return that admin's sessions from the last 30 days, newest first, each with:
- when it started and when it ends;
- whether it was revoked, and when;
- the chain it was signed for;
- the user agent recorded at sign-in, for the caller's own sessions only;
- whether it is the session making the request.

Another admin's sessions SHALL be returned with the user agent set to `null`: a platform admin sees when another signed in, not where from. The IP address SHALL NOT be returned: behind the console's proxy it is the proxy's address, which would read as the admin's own beside a stolen session. It SHALL never return a session token or its hash.

`DELETE /v1/platform/admins/:id/sessions/:sessionId` SHALL end one of the caller's own open sessions; one already ended or expired SHALL stay as it is, and the request SHALL still succeed. Ending another admin's session SHALL return 403; removing the admin is the way to end all of them. Sessions SHALL be matched to an admin by the address that signed in.

#### Scenario: Last sign-in
- **WHEN** `ops-diogo` signed in yesterday and has no open session
- **THEN** their entry shows yesterday's sign-in and 0 active sessions

#### Scenario: Another admin's sessions are listed without where from
- **WHEN** a platform admin lists another admin's sessions
- **THEN** each session shows when it started, ended and was revoked, and its chain, with the user agent `null` and no IP address

#### Scenario: End your own other session
- **WHEN** a platform admin ends another of their own open sessions
- **THEN** that session's next request returns 401, and the caller's current session continues

#### Scenario: Ending another admin's session
- **WHEN** a platform admin tries to end a session belonging to another admin
- **THEN** the response is 403 and the session continues
