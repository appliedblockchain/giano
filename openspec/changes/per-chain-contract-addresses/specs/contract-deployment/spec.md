## ADDED Requirements

### Requirement: Each chain profile declares a network class
Every chain profile SHALL declare its network class: `mainnet` or `testnet`. Local chains (31337, 31338) are the class
`local` implicitly and have no profile.

#### Scenario: Profile without a class
- **WHEN** a chain profile has no `network` field, or an unknown value
- **THEN** the profile is rejected, and the error lists the accepted classes

### Requirement: One canonical deployer per network class
The deploy configuration SHALL name one canonical deployer address per class. The mainnet and testnet deployers SHALL
be different addresses. While a class's deployer is unset, the deploy tooling SHALL refuse to sign for any chain in
that class, and SHALL still allow a read-only plan.

#### Scenario: Unset mainnet deployer
- **WHEN** an operator runs a deployment for a mainnet profile while the mainnet deployer is unset
- **THEN** the run prints its plan, sends nothing and exits non-zero, saying that the mainnet canonical deployer is
  not configured

#### Scenario: Same address for both classes
- **WHEN** the configuration sets the mainnet and testnet deployers to the same address
- **THEN** the deploy tooling refuses to load the configuration

### Requirement: Local chains use a fixed local deployer
Local chains SHALL impersonate a fixed placeholder deployer that never changes. Setting or changing the testnet or
mainnet deployer SHALL NOT change any local-chain address.

#### Scenario: Setting a real deployer leaves the devnet alone
- **WHEN** the testnet or mainnet deployer address is changed
- **THEN** the local chains' contract addresses and the committed devnet state are unchanged

### Requirement: Expected addresses are deterministic per class
For each contract, the expected address on a chain SHALL be the CREATE3 address of the chain's class deployer and the
contract's fixed label, so every chain in a class shares one set of expected addresses. A deployment run SHALL print,
for every contract, the expected address, the address it will use, and whether that is a deviation.

#### Scenario: Default mainnet plan
- **WHEN** an operator plans a deployment for a mainnet profile with no overrides
- **THEN** every planned address is the CREATE3 address of the mainnet deployer and the contract's label, and none is
  marked as a deviation

### Requirement: Profiles can override contract addresses
A chain profile MAY override the address of individual contracts. An overridden contract SHALL be verified at the
override address, not deployed: it must already hold release code that passes the registry's verification. Contracts
that depend on it SHALL use the override address.

#### Scenario: Overridden paymaster
- **WHEN** a profile overrides the paymaster proxy address and that address holds release paymaster code
- **THEN** the run deploys the other missing contracts at their deterministic addresses, and records the paymaster at
  the override address as a deviation

#### Scenario: Override with no code
- **WHEN** a profile overrides an address that has no code, or code that matches no release
- **THEN** the run refuses before signing, and names the contract and the address

### Requirement: Mainnet deployment expects the canonical deployer and deterministic addresses
For a mainnet profile, the deploy tooling SHALL expect a signing key whose address is the mainnet canonical deployer,
and deterministic addresses for every contract. Any of the following is a deviation:
- a contract override;
- a signing key whose address is not the mainnet canonical deployer;
- an existing contract found at an address other than the expected one.

A key that is not the canonical deployer's SHALL deploy at its own CREATE3 addresses, never at the canonical ones.

#### Scenario: Canonical mainnet run
- **WHEN** a mainnet run signs with the mainnet canonical deployer's key and the profile has no overrides
- **THEN** no deviation is reported, and the usual exact-text deployment confirmation is the only prompt

#### Scenario: Different key on mainnet
- **WHEN** a mainnet run is given a signing key whose address is not the mainnet canonical deployer
- **THEN** the run reports a deviation for every contract the key would deploy, showing its addresses beside the
  canonical ones

### Requirement: Mainnet deviations need explicit confirmation
Before signing a mainnet deployment that has any deviation, the deploy tooling SHALL do three things. It SHALL print a
warning naming each deviation, with the expected and actual address or signer. It SHALL state that addresses on this
chain will differ from the other mainnets, permanently. It SHALL then require an exact confirmation phrase that names
the chain. Non-interactive runs SHALL refuse a mainnet deployment that deviates.

#### Scenario: Interactive deviation
- **WHEN** an interactive mainnet run has an override
- **THEN** it signs nothing until the operator types the deviation phrase for that chain

#### Scenario: Non-interactive deviation
- **WHEN** a non-interactive mainnet run has any deviation
- **THEN** it exits non-zero without signing, and lists the deviations

### Requirement: Testnet deviations are reported, not gated
For a testnet profile, the deploy tooling SHALL show deviations in the plan and the record. It SHALL require no
confirmation beyond the usual deployment confirmation.

#### Scenario: Testnet override
- **WHEN** a testnet profile overrides a contract address
- **THEN** the plan and the record show the deviation, and no extra confirmation is required

### Requirement: The deployment record states how each address was obtained
Each deployment record SHALL hold:
- the chain id and network class;
- the signing deployer;
- per contract: its label, address, expected address, release, code hash, and deploying transaction when deployed in
  that run;
- whether each address is deterministic;
- every deviation the operator confirmed.

Records for non-local chains SHALL be committed.

#### Scenario: Record after a confirmed deviation
- **WHEN** a mainnet run completes after the operator confirmed an overridden paymaster
- **THEN** the chain's record marks the paymaster as non-deterministic and lists the confirmed deviation, and the
  other contracts are marked deterministic
