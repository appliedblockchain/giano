# test-erc20-registry Specification

## Purpose

Giano's test ERC-20 exists at one deterministic address on every chain Giano supports for testing, so a demo or a
tenant can be configured with a single default token address everywhere.

## Requirements

### Requirement: Deterministic deployment on every supported testnet
The test ERC-20 SHALL be deployed with the CREATE2 strategy and Giano's fixed salt on every chain listed for testing
(local devnets, Base Sepolia, Ethereum Sepolia), yielding the same address on each. Anyone SHALL be able to mint it to
their own account.

#### Scenario: Address equality
- **WHEN** the deployment journals for two supported testnets are compared
- **THEN** the test ERC-20 address is identical

#### Scenario: Public mint
- **WHEN** a smart account calls `mint(amount)`
- **THEN** its balance increases by `amount`

### Requirement: Registry publication
The contracts package's address registry SHALL expose the test ERC-20 address per chain so operators can configure the
demo's default token from a single source, and the address SHALL be excluded from any production chain entry.

#### Scenario: Registry lookup
- **WHEN** an operator reads the registry entry for a supported testnet
- **THEN** it includes the test ERC-20 address

#### Scenario: Production chain
- **WHEN** an operator reads the registry entry for a production chain
- **THEN** no test ERC-20 address is present
