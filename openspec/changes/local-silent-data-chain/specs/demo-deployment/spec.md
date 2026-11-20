# Spec Delta

## MODIFIED Requirements

### Requirement: Local development parity
`pnpm dev` SHALL run the demo against the local stack with the same `GIANO_*` names read from a `.env` file, and the
demo SHALL be reachable under its own portless names distinct from the e2e fixture's.
Every local demo instance, `stock` and `byo`, in `pnpm dev` and in the infrastructure stack, SHALL list the local
Silent Data chain (31339) through its gateway, with that chain's `privateToken` set.

#### Scenario: Demo and fixture side by side
- **WHEN** the e2e fixture and the demo run at the same time
- **THEN** they listen on different ports and different `*.localhost` names, and the Playwright suite still drives the
  fixture

#### Scenario: Silent Data chain listed locally
- **WHEN** the `stock` or the `byo` demo instance starts against a local stack
- **THEN** the chain selector offers "Devnet SD (Silent Data)", and selecting it shows the private token section

#### Scenario: Only the Silent Data chain names a private token
- **WHEN** the user selects Devnet A or Devnet B in a local demo instance
- **THEN** the private token section is not shown
