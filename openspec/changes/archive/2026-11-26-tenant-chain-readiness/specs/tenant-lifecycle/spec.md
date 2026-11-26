## ADDED Requirements

### Requirement: Offboarding is a written procedure
The repository SHALL hold an offboarding runbook, `docs/TENANT-OFFBOARDING-RUNBOOK.md`. It SHALL give the order of the steps: suspend, disable on every chain where the tenant is registered, the tenant's own `withdrawTenant` to its withdrawal address, a drift check, and delete. It SHALL say that a tenant cannot be de-registered on chain.

#### Scenario: A platform admin offboards a funded tenant
- **WHEN** a platform admin follows the runbook for a tenant with a balance on one chain
- **THEN** the runbook has them suspend the tenant, disable it on chain, ask the tenant to withdraw, confirm the ledger shows zero, and only then delete

### Requirement: The runbook states what happens to data and to users
For each kind of tenant data (the tenant row, admin keys, users, credentials, user sessions, challenges, pending additions, sponsorship configuration, ledger, operation and decision logs, tenant history, application logs), the runbook SHALL say whether delete keeps or removes it. It SHALL say that users' wallets are self-custodial and outlive the tenant, and SHALL list the decisions still open.

#### Scenario: A user of an offboarded tenant
- **WHEN** a reader asks what a deleted tenant's users keep
- **THEN** the runbook says their wallets and funds stay theirs, their passkeys still sign for the wallet, and they lose the tenant's ceremonies, relay and sponsorship
