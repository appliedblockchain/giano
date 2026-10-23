## Purpose

Defines who the operators are once they are stored in the database: how a deployment gets its first operators, how operators change the list, and the guards that keep a deployment administrable.

## ADDED Requirements

### Requirement: Bootstrap operators are written only into an empty table
The init step SHALL write the environment's bootstrap operators, each with an `operator_history` entry `bootstrap` by `bootstrap:<environment>`, only when the `operators` table has no row. Otherwise it SHALL write nothing. Concurrent runs SHALL write each operator once.

#### Scenario: First deploy
- **WHEN** init runs for `dev` against a database with no operators
- **THEN** `giovanni` is an operator, added by `bootstrap:dev`

#### Scenario: Later deploys
- **WHEN** init runs against a database with any operator, even after a release changed the bootstrap list
- **THEN** the operators are unchanged

### Requirement: Operators manage operators
A signed-in operator SHALL list operators with `GET /v1/operator/operators`, add one with `POST /v1/operator/operators { id, address }`, remove one with `DELETE /v1/operator/operators/:id`, and read the changes with `GET /v1/operator/operators/history`. An added operator SHALL be able to sign in at once. A duplicate id or address SHALL return `409 conflict` naming the field.

#### Scenario: Add
- **WHEN** an operator adds `{ id: "ops-new", address }`
- **THEN** the response is 201, the new operator can sign in, and history has an `add` entry by the adding operator

### Requirement: The deployment always keeps an operator
Removing yourself SHALL return `409 self-removal`. Removing the last operator SHALL return `409 last-operator`. A removal SHALL revoke the removed operator's open sessions and SHALL be recorded as `remove`.

#### Scenario: Self-removal
- **WHEN** an operator tries to remove their own row
- **THEN** the response is 409 `self-removal`, and they remain an operator

#### Scenario: Removal ends sessions
- **WHEN** an operator removes another who is signed in
- **THEN** the removed operator's next request returns 401
