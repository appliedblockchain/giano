## ADDED Requirements

### Requirement: wallet-api detects drift between its records and each paymaster
For each chain that sponsors, wallet-api SHALL compare its registry and ledger with the paymaster, and SHALL report each of these as drift:
- a tenant on the paymaster's roster with no registry row;
- a registry tenant that is active, registered on chain, and disabled there; or suspended or deleted, and enabled there;
- a registry tenant the paymaster holds a balance or deficit for, with no ledger row;
- a ledger balance or deficit that differs from the paymaster's, once the watcher has synced past the block the paymaster was read at;
- a withdrawal address in the ledger that differs from the paymaster's.

An active registry tenant not yet registered on a chain SHALL NOT be drift: it is a step not yet taken. A ledger row the watcher has never synced SHALL be reported as not compared, not as drift.

#### Scenario: Funded before its registry row
- **WHEN** a tenant was funded on chain before its registry row existed, so the ledger has no row for it
- **THEN** drift is reported for that tenant, naming what the chain holds

#### Scenario: Suspended tenant still enabled
- **WHEN** a tenant is suspended in the registry and still enabled on Base Sepolia
- **THEN** drift is reported for that tenant and chain, naming both states

#### Scenario: Watcher behind
- **WHEN** the ledger differs from the chain only because the watcher has not reached the block that changed it
- **THEN** no drift is reported

### Requirement: Drift is readable by platform admins, by metrics and by giano-doctor
`GET /v1/platform/drift` SHALL require a platform admin session and SHALL return the current drift per chain, with when it was checked. A stored result older than two reconcile intervals SHALL NOT be served as current, and a chain whose drift cannot be computed SHALL be an error for that chain alone. wallet-api SHALL expose the number of drifted tenants per chain as a metric, apart from the tenants with no registry row. `giano-doctor` SHALL offer a check that reads the same comparison and fails on drift in this deployment's records; a tenant with no registry row, an old result and tenants not compared SHALL warn.

#### Scenario: Shared paymaster
- **WHEN** another deployment's tenants are on the same paymaster
- **THEN** they are reported as tenants with no registry row, the drift metric does not count them, and the doctor warns rather than fails

#### Scenario: No drift
- **WHEN** every chain's records agree
- **THEN** the endpoint returns an empty list per chain, the metric is 0, and the doctor check passes
