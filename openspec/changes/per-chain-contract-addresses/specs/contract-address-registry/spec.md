## ADDED Requirements

### Requirement: Contract addresses are resolved per chain
Every Giano-deployed contract address SHALL be resolved per chain: from the chain's deployment record, then the chain's
address overrides, then, in a deployment, that deployment's chain configuration. No component SHALL assume that a
contract has the same address on two chains. The canonical EntryPoint and CreateX are third-party contracts at
published addresses and are not affected.

#### Scenario: Mainnet chains at different addresses
- **WHEN** chain A's record puts the paymaster proxy at `0xA…` and chain B's override puts it at `0xB…`
- **THEN** the registry returns `0xA…` for chain A and `0xB…` for chain B, and neither value is reported as an error

#### Scenario: Unknown chain
- **WHEN** a consumer asks the registry for a chain with no deployment record and no override
- **THEN** it gets an error that names the chain and lists the registered chains

### Requirement: No fixed Giano contract address is published
The published contracts package SHALL NOT export a fixed address for any Giano-deployed contract: the wallet
implementation, factory, paymaster implementation, paymaster proxy, timelock or test fixtures. It SHALL export the
per-chain registry and its accessor instead.

#### Scenario: Consumer looks for the factory
- **WHEN** an integrator needs the factory address for chain 8453
- **THEN** the package offers it only through the registry for chain 8453, and offers no chain-independent constant

### Requirement: Releases publish code fingerprints
Each contract release SHALL publish, for every deployable contract, a code fingerprint and the positions of the
immutables the fingerprint masks. The fingerprint is the hash of the runtime code with every immutable value masked.
Fingerprints SHALL be generated from the committed releases, committed, and checked for drift in CI.

#### Scenario: Fingerprint drift
- **WHEN** a release's committed fingerprints differ from those regenerated from its committed compiler input
- **THEN** CI fails, naming the release and the contract

### Requirement: Code is verified against a release wherever it sits
Code at any address SHALL be accepted as a contract's release code only when its masked hash equals that contract's
fingerprint for some release. Verification SHALL report which release matched.

#### Scenario: Release code at a non-deterministic address
- **WHEN** a chain registers a factory at an overridden address whose code is release `v2`'s factory
- **THEN** the code check passes and reports release `v2`

#### Scenario: Foreign code at a registered address
- **WHEN** the code at a chain's registered factory matches no release's factory fingerprint
- **THEN** verification fails, naming the chain, the contract, the address and the observed hash

### Requirement: Immutables are checked against the chain's own addresses
Because fingerprints mask immutables, verification SHALL check each meaningful immutable against the chain's
registered addresses. The factory's `implementation` SHALL be the chain's registered wallet implementation. The wallet
implementation's EntryPoint SHALL be the chain's EntryPoint. The paymaster proxy's implementation slot SHALL hold
paymaster release code.

#### Scenario: Factory bound to another implementation
- **WHEN** a factory runs release code but its `implementation` differs from the chain's registered implementation
- **THEN** verification fails with an implementation mismatch that shows both addresses

#### Scenario: New immutable without a check
- **WHEN** a release adds a contract immutable that has no registered semantic check
- **THEN** the contracts test suite fails, naming the contract and the immutable

### Requirement: The registry is built only from verified records
Generating the registry SHALL fail when a non-local chain's record lacks the factory or the wallet implementation,
when a recorded code hash matches no release fingerprint, or when an override is not a valid address. It SHALL NOT
fail because an address differs from the deterministic one. Local chains (31337, 31338) SHALL never enter the
committed registry.

#### Scenario: Overridden address enters the registry
- **WHEN** a mainnet chain's record shows the paymaster proxy at an overridden address, with release code
- **THEN** the registry is generated with that address

#### Scenario: Unknown code in a record
- **WHEN** a record lists a contract whose code hash matches no release
- **THEN** generation fails and names the chain, the contract and the hash

### Requirement: wallet-api admits a chain by its own addresses
wallet-api SHALL admit a chain only after verifying, at configuration load and against the chain itself:
- the chain id;
- the EntryPoint;
- release code and immutables at the chain's resolved factory and wallet implementation;
- the paymaster's presence when one is configured.

It SHALL NOT compare a factory or implementation address with a constant. An unreachable endpoint stays non-fatal: the
chain starts unavailable and is retried.

#### Scenario: Two mainnets with different paymaster addresses
- **WHEN** a deployment serves two chains whose release-code factories derive the same probe address, and whose
  paymaster proxies are at different addresses
- **THEN** both chains are admitted

#### Scenario: Unreachable chain
- **WHEN** a chain's RPC endpoint does not answer at boot
- **THEN** the chain starts unavailable and is retried in the background

### Requirement: Served chains derive the same wallet
Every chain served by one deployment SHALL have a factory that derives the same account address for the fixed probe
owner (MC-22). A mismatch SHALL refuse the deployment, and SHALL NOT fall back to per-chain wallet addresses (MC-23).

#### Scenario: Factories that disagree
- **WHEN** two served chains' factories derive different addresses for the probe owner
- **THEN** wallet-api refuses to start and names both chains and both derived addresses

### Requirement: Doctor applies the same verification
`giano-doctor` SHALL verify a chain with the same code, immutable and probe checks as wallet-api. It SHALL report,
for each address, whether it is the deterministic address for the chain's network class.

#### Scenario: Doctor on an overridden chain
- **WHEN** doctor checks a chain whose paymaster proxy is overridden and holds release code
- **THEN** the paymaster check passes, and the report marks the address as non-deterministic
