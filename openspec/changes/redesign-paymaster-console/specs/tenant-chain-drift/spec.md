## ADDED Requirements

### Requirement: wallet-api detects drift between its records and each paymaster
For each chain that sponsors, wallet-api SHALL compare its registry and ledger with the paymaster, and SHALL report each of these as drift:
- a tenant on the paymaster's roster with no registry row;
- a registry tenant that is active, registered on chain, and disabled there; or suspended or deleted, and enabled there;
- a ledger balance or deficit that differs from the paymaster's, once the watcher has synced past the block the paymaster was read at;
- a withdrawal address in the ledger that differs from the paymaster's.

An active registry tenant not yet registered on a chain SHALL NOT be drift: it is a step not yet taken.

#### Scenario: Suspended tenant still enabled
- **WHEN** a tenant is suspended in the registry and still enabled on Base Sepolia
- **THEN** drift is reported for that tenant and chain, naming both states

#### Scenario: Watcher behind
- **WHEN** the ledger differs from the chain only because the watcher has not reached the block that changed it
- **THEN** no drift is reported

### Requirement: Drift is readable by platform admins, by metrics and by giano-doctor
`GET /v1/platform/drift` SHALL require a platform admin session and SHALL return the current drift per chain, with when it was checked. wallet-api SHALL expose the number of drifted tenants per chain as a metric. `giano-doctor` SHALL offer a check that reads the same comparison and fails on any drift.

#### Scenario: No drift
- **WHEN** every chain's records agree
- **THEN** the endpoint returns an empty list per chain, the metric is 0, and the doctor check passes
