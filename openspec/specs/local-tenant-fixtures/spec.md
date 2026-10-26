# local-tenant-fixtures Specification

## Purpose

Defines how a local stack (dev, e2e, loopback, Sepolia demo) gets its test tenants, given that `wallet-api` itself never creates a tenant.

## Requirements

### Requirement: wallet-api never creates a tenant on its own
`wallet-api` SHALL NOT create a tenant from configuration. It SHALL boot and serve with zero tenants, refusing tenant-scoped requests until a platform admin creates one.

#### Scenario: Empty live deployment
- **WHEN** `wallet-api` boots against a database with no tenants
- **THEN** it starts, logs that no tenant is active, and `/healthz` answers

### Requirement: Local stacks create fixture tenants with a separate one-shot
A local stack SHALL create its test tenants by running `node dist/tenant-fixtures.js` before `wallet-api` starts. It reads `TENANT_FIXTURES`, a JSON array of tenants that MAY pin `id` and carry plaintext `adminKeys`, and applies pending migrations first. It SHALL exit non-zero on any refused entry.

#### Scenario: Fresh database
- **WHEN** the e2e stack comes up on an empty volume
- **THEN** `stock` and `byo` exist with their pinned ids and fixed admin keys before `wallet-api` starts, each with one `create` history entry by `fixture`

### Requirement: Fixtures are validated like every tenant write and only ever create
Every fixture SHALL pass the same field schema, invariants and origin-claim check as any tenant write. A fixture whose slug does not exist SHALL be created as a platform-admin-managed tenant. A slug that exists, a deleted one included, SHALL be left unchanged.

#### Scenario: Restart after a console edit
- **WHEN** a platform admin renames fixture tenant `stock` in the console and the stack restarts
- **THEN** `stock` keeps the platform admin's name and gets no new history entry

#### Scenario: Conflicting origin
- **WHEN** a fixture claims an origin another tenant already holds
- **THEN** the command exits non-zero naming the origin and the other tenant, and `wallet-api` does not start
