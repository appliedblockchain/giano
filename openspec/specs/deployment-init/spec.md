# deployment-init Specification

## Purpose

Defines what a deployment is (its environment entry) and what must be true of its database before the API serves (the init step).

## Requirements

### Requirement: The environment is selected by GIANO_ENVIRONMENT from a map in code
wallet-api and the init step SHALL require `GIANO_ENVIRONMENT` to name an entry in `src/environments.ts`, and SHALL refuse to start otherwise. The platform admin sign-in domain and URI SHALL come from that entry and SHALL NOT be stored in the database. An entry without a sign-in domain SHALL register no platform route.

#### Scenario: Unknown environment
- **WHEN** `GIANO_ENVIRONMENT=staging` is set and the map has no `staging` entry
- **THEN** wallet-api and init refuse to start, listing the known names

#### Scenario: Sign-in domain
- **WHEN** wallet-api runs with `GIANO_ENVIRONMENT=dev`
- **THEN** every platform admin sign-in message names `paymaster.dev.giano.appliedblockchain.dev`

### Requirement: An init step prepares the database before the API starts
Every deployment SHALL run `node dist/init.js` to completion before wallet-api starts, and wallet-api SHALL wait for it to succeed. The init step SHALL apply migrations and then bootstrap platform admins. It SHALL load `TENANT_FIXTURES` only for an environment marked as a local stack, and SHALL refuse with a non-zero exit, before connecting to the database, anywhere else. wallet-api SHALL NOT seed platform admins or tenants itself.

#### Scenario: Fixtures on a live environment
- **WHEN** init runs with `GIANO_ENVIRONMENT=dev` and `TENANT_FIXTURES` set
- **THEN** it exits non-zero naming the environment, and the API does not start

#### Scenario: Repeated init
- **WHEN** init runs again on a prepared database
- **THEN** it applies nothing and writes nothing
