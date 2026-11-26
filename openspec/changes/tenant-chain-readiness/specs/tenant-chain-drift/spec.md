## ADDED Requirements

### Requirement: Tenants waiting for registration are listed beside drift
Each chain's drift result SHALL carry `unregistered`: every active registry tenant whose sponsorship configuration for that chain is switched on and which is not registered on that chain's paymaster, each with its id and slug. It SHALL NOT be drift, and SHALL NOT count toward the drift metric.

#### Scenario: Created and configured, not registered
- **WHEN** a platform admin creates a tenant, its admin switches sponsorship on for Base Sepolia, and nobody has called `registerTenant` there
- **THEN** Base Sepolia's drift result lists the tenant under `unregistered`, and its entries do not include it

#### Scenario: No sponsorship on that chain
- **WHEN** an active tenant has no sponsorship configuration for a chain and is not registered there
- **THEN** it is not listed under `unregistered` for that chain

#### Scenario: Suspended tenant
- **WHEN** a suspended tenant with sponsorship switched on is not registered on a chain
- **THEN** it is not listed under `unregistered`

### Requirement: Unregistered tenants are a metric and a doctor warning
wallet-api SHALL expose the number of unregistered tenants per chain as `giano_paymaster_unregistered_tenants`, from the watcher's last drift pass, and SHALL remove the series when that pass no longer stands, as for the drift metric. `giano-doctor` SHALL warn on each chain with unregistered tenants, naming them, SHALL NOT fail on them, and SHALL accept a drift result without the field.

#### Scenario: One tenant waiting
- **WHEN** one tenant is unregistered on Base Sepolia and nothing else differs
- **THEN** the unregistered gauge for Base Sepolia is 1, the drift gauge is 0, and the doctor warns and still reports no drift
