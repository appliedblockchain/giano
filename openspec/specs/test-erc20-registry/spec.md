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

### Requirement: Private test token
A private test token SHALL exist on each chain listed for testing whose RPC enforces private reads. It keeps the ERC-20 interface, but only the holder can read a balance, and its transfer and approval events are visible only to the parties. Anyone SHALL be able to mint it to their own account. It SHALL be deployed under a fixed test label, so it has one address per network class.

#### Scenario: Holder reads its balance
- **WHEN** a smart account that holds the token reads its own balance with a request signed for that account
- **THEN** the read returns the balance

#### Scenario: Another account reads the balance
- **WHEN** any account other than the holder calls `balanceOf(holder)`
- **THEN** the call reverts with the token's unauthorised-balance-access error

#### Scenario: Public mint
- **WHEN** a smart account calls `mint(amount)` on the private test token
- **THEN** its balance, read by itself, increases by `amount`

#### Scenario: Same address across chains of a class
- **WHEN** the deployment records of two testnets that carry the private test token are compared
- **THEN** the token's address is identical

### Requirement: Private test token in the registry
The contracts package's address registry SHALL expose the private test token's address for each chain that carries it, and SHALL exclude it from every production chain entry.

#### Scenario: Registry lookup on a Silent Data testnet
- **WHEN** an operator reads the registry entry for a testnet that carries the private test token
- **THEN** the entry includes the private test token's address

#### Scenario: Production chain
- **WHEN** an operator reads the registry entry for a production chain
- **THEN** the entry has no private test token address
