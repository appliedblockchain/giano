## ADDED Requirements

### Requirement: Each chain profile declares a network class
Every chain profile SHALL declare its network class: `mainnet` or `testnet`. Local chains (31337, 31338) are the class
`local` implicitly and have no profile.

#### Scenario: Profile without a class
- **WHEN** a chain profile has no `network` field, or an unknown value
- **THEN** the profile is rejected, and the error lists the accepted classes

#### Scenario: Record of another class
- **WHEN** a run resolves a chain's class (from a profile or `--network`) differently from the class its deployment
  record states
- **THEN** it refuses before reading or signing anything else, naming both classes

### Requirement: One canonical deployer per network class
The deploy configuration SHALL name one canonical deployer address per class. The mainnet and testnet deployers SHALL
be different addresses whenever both are set; both MAY be unset. While a class's deployer is unset, the deploy tooling SHALL refuse to sign for any chain in
that class, and SHALL still allow a read-only plan.

#### Scenario: Unset mainnet deployer
- **WHEN** an operator runs a deployment for a mainnet profile while the mainnet deployer is unset
- **THEN** the run prints its plan, sends nothing and exits non-zero, saying that the mainnet canonical deployer is
  not configured

#### Scenario: Same address for both classes
- **WHEN** the configuration sets the mainnet and testnet deployers to the same address, in any letter case
- **THEN** the deploy tooling refuses to load the configuration

#### Scenario: Both deployers unset
- **WHEN** neither the mainnet nor the testnet deployer is set
- **THEN** the configuration loads, local deployments work, and every non-local plan carries the "not configured"
  blocker

### Requirement: Local chains use a fixed local deployer
Local chains SHALL impersonate a fixed placeholder deployer that never changes. Setting or changing the testnet or
mainnet deployer SHALL NOT change any local-chain address.

#### Scenario: Setting a real deployer leaves the devnet alone
- **WHEN** the testnet or mainnet deployer address is changed
- **THEN** the local chains' contract addresses and the committed devnet state are unchanged

### Requirement: Expected addresses are deterministic per class
For each contract, the expected address on a chain SHALL be the CREATE3 address of the chain's class deployer and the
contract's fixed label, so every chain in a class shares one set of expected addresses. One exception applies: an
implementation the chain was upgraded to, which its deployment record lists among its upgrade targets at the CREATE3
address of the class deployer and that target's versioned label (`giano.paymaster.impl@v3`), SHALL have that
address as its expected address. It is where every chain of the class has that upgrade, so it is deterministic and
not a deviation, whatever release it holds.

A deployment run SHALL print, for every contract, the expected address, the address it will use, and whether that is
a deviation. While the class deployer is unset, the expected address SHALL be shown as unresolved and no deviation
SHALL be derived from it. The address a run uses SHALL be resolved in this order: the profile's override, then the
address the chain's deployment record lists, then the expected address when it already holds code, and otherwise
the CREATE3 address of the signing key. A plan without a signing key SHALL use the expected address only when neither
an override nor a recorded address applies.

#### Scenario: Default mainnet plan
- **WHEN** an operator plans a deployment for a mainnet profile with no overrides
- **THEN** every planned address is the CREATE3 address of the mainnet deployer and the contract's label, and none is
  marked as a deviation

#### Scenario: Plan after a canonical paymaster upgrade
- **WHEN** a chain's paymaster was upgraded by the class deployer, and its record lists the paymaster implementation
  at the CREATE3 address of the class deployer and the versioned label
- **THEN** the plan expects the paymaster implementation at that address, marks it deterministic, reports no
  deviation for it, and does not refuse it for holding a release other than the selected one

#### Scenario: Keyless verification of a recorded non-canonical deployment
- **WHEN** a run without a signing key verifies a chain whose record lists a contract at an address other than the
  expected one (deployed by another key, or confirmed as a deviation)
- **THEN** it verifies the contract at the recorded address, reports it as a deviation, and does not report it
  missing at the expected address

### Requirement: Profiles can override contract addresses
A chain profile MAY override the address of the wallet implementation, the factory, the paymaster implementation
and the paymaster proxy. The timelock is not overridable: its address is `timelock.address`. An overridden contract
SHALL be verified at the override address, not deployed: it must already hold release code that passes the
registry's verification. Contracts that depend on it SHALL use the override address. An overridden factory SHALL
clone the planned wallet implementation. An overridden paymaster proxy SHALL point at the planned paymaster
implementation, have the profile's EntryPoint and fee parameters, and grant `ROLE_ADMIN` to the planned role admin.

#### Scenario: Overridden paymaster
- **WHEN** a profile overrides the paymaster proxy address and that address holds release paymaster code
- **THEN** the run deploys the other missing contracts at their deterministic addresses, and records the paymaster at
  the override address as a deviation

#### Scenario: Overridden proxy pointing elsewhere
- **WHEN** a profile overrides only the paymaster proxy, and its implementation slot holds a paymaster implementation
  other than the planned one
- **THEN** the run refuses before signing, and suggests overriding `paymasterImplementation` with the slot's address

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
the chain. Non-interactive runs that sign SHALL refuse a mainnet deployment that deviates, and no flag or
environment variable SHALL skip the typed confirmation. A run that signs nothing (a plan, or a verify-only run without
a key) SHALL report the deviations and not refuse. A deviation the deployment record already lists as confirmed, for the
same contract at the same address, SHALL be reported but SHALL NOT need a new confirmation.

#### Scenario: Interactive deviation
- **WHEN** an interactive mainnet run has an override
- **THEN** it signs nothing until the operator types the deviation phrase for that chain

#### Scenario: Non-interactive deviation
- **WHEN** a non-interactive mainnet run has any deviation
- **THEN** it exits non-zero without signing, and lists the deviations

#### Scenario: Verify-only run on a deviating mainnet
- **WHEN** a run without a signing key plans a mainnet whose plan has a deviation
- **THEN** it prints the deviations and does not refuse on their account

#### Scenario: Deviation confirmed earlier
- **WHEN** a mainnet run's only deviations are listed as confirmed in the chain's deployment record
- **THEN** it reports them and requires no new deviation confirmation

#### Scenario: Promptless CLI on a deviating mainnet
- **WHEN** `deploy:cli core` targets a mainnet profile whose plan has a deviation
- **THEN** it exits non-zero without signing, and names the guided wizard as the way to confirm it

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
- per contract: its label, address, expected address, release, the raw code hash, the release fingerprint the code
  matched, and the deploying transaction when deployed in that run;
- whether each address is deterministic;
- every deviation the operator confirmed.

Records for non-local chains SHALL be committed.

### Requirement: Deployers hold no authority on deployed contracts
On every non-local chain, the deploy tooling SHALL refuse a paymaster `ROLE_ADMIN` that is the signing key or a
configured canonical deployer, and SHALL refuse to adopt an existing paymaster proxy on which either holds
`ROLE_ADMIN`.

#### Scenario: Deployer given as role admin
- **WHEN** a testnet or mainnet run is given the signing key's address as `ROLE_ADMIN`
- **THEN** it refuses before signing, and says that the role admin must be a timelock or Safe, not a deployer

### Requirement: Mainnet chains are production chains for R-29
The test fixtures (the permissive paymaster and the test ERC-20) SHALL NOT be deployed to, registered for, or left
unreported on any chain in R-29's fixed production list or any chain whose profile or record declares `mainnet`.

#### Scenario: Newly adopted mainnet
- **WHEN** an operator runs `deploy:cli testing` against a chain whose profile declares `mainnet`, and the chain is not
  in the fixed list
- **THEN** it refuses, naming R-29

#### Scenario: Record after a confirmed deviation
- **WHEN** a mainnet run completes after the operator confirmed an overridden paymaster
- **THEN** the chain's record marks the paymaster as non-deterministic and lists the confirmed deviation, and the
  other contracts are marked deterministic
