## MODIFIED Requirements

### Requirement: Mainnet chains are production chains for R-29
The test fixtures (the permissive paymaster and the test ERC-20) SHALL NOT be deployed to, registered for, or left
unreported on any chain in R-29's fixed production list, any chain on the fixed mainnet list, or any chain whose
profile or record declares `mainnet`. A chain on the fixed mainnet list SHALL NOT be treated as `testnet`, whatever its
profile, its record or the command line declares.

#### Scenario: Newly adopted mainnet
- **WHEN** an operator runs `deploy:cli testing` against a chain whose profile declares `mainnet`, and the chain is not
  in the fixed list
- **THEN** it refuses, naming R-29

#### Scenario: Ethereum mainnet without a profile
- **WHEN** an operator runs `deploy:cli testing` against chain 1 with no profile
- **THEN** it refuses, naming R-29

#### Scenario: Mainnet-list chain declared testnet
- **WHEN** an operator passes `--network testnet`, or selects a profile declaring `testnet`, for a chain on the fixed
  mainnet list
- **THEN** the run refuses before planning, saying that the chain is a mainnet

## ADDED Requirements

### Requirement: A testnet deployment can be rehearsed on a fork
The deploy tooling SHALL let an operator rehearse a testnet-class deployment on an anvil fork of a public testnet,
with a rehearsal deployer standing in for the class's canonical deployer. It SHALL accept a rehearsal deployer only
when the RPC is an anvil node running a fork, and SHALL refuse one on any other RPC. A rehearsal SHALL NOT write the
committed deployment records, the address registry or the shipped profiles. Its record, profile copy and address
output SHALL go to a rehearsal directory that git ignores. Apart from the deployer, a rehearsal SHALL run the same
checks as a real run of its class.

#### Scenario: Rehearsal on a Base Sepolia fork
- **WHEN** an operator runs the rehearsal against an anvil fork of Base Sepolia (chain 84532) with a rehearsal
  deployer
- **THEN** the wizard plans and deploys the profile's release at that deployer's CREATE3 addresses, after the same
  CreateX, EntryPoint and release checks as a real run, and writes its record only to the rehearsal directory

#### Scenario: Rehearsal deployer on a real RPC
- **WHEN** a rehearsal deployer is supplied and the RPC is not an anvil fork
- **THEN** the run refuses before planning, saying that a rehearsal deployer is accepted only on a fork

#### Scenario: Committed files untouched
- **WHEN** a rehearsal completes
- **THEN** `deployments/`, `addresses.ts` and `deploy/chains/*.json` are unchanged

### Requirement: Profiles pin the current release until the chain is deployed
A shipped chain profile whose chain has no deployment record SHALL pin the newest committed contract release. Once the
chain has a deployment record, the profile's release SHALL stay the one the record was deployed from. The check SHALL
run in CI.

#### Scenario: New release cut while a profile is undeployed
- **WHEN** a new release `vN` is committed and a shipped profile with no deployment record still pins an older
  release
- **THEN** CI fails, naming the profile, its release and `vN`

#### Scenario: Deployed chain keeps its release
- **WHEN** a new release is committed and a shipped profile's chain has a deployment record
- **THEN** CI passes with the profile still pinning the release the record was deployed from

### Requirement: A timelocked upgrade is reconciled into the deployment record
When a chain's paymaster proxy points at an implementation that the chain's deployment record lists among its upgrade
targets, and that implementation holds release code, the deploy tooling SHALL treat it as the chain's paymaster
implementation. It SHALL NOT report a blocker or a deviation for it. A run that writes the record SHALL update the
record's paymaster implementation to it. This SHALL hold however the upgrade was executed: directly, through the
timelock, or through a Safe. A proxy pointing at an implementation that is not a recorded upgrade target SHALL still be
a blocker.

#### Scenario: Plan after the timelock executes an upgrade
- **WHEN** `deploy:cli upgrade --timelock` deployed and recorded an upgrade target, the timelock later executed the
  upgrade, and an operator then runs a plan, `contracts:sponsorship` or the keyless verify Job for that chain
- **THEN** the run passes the paymaster implementation check and names the upgrade target as the implementation in
  use

#### Scenario: Signing run updates the record
- **WHEN** a run that writes the record sees the proxy pointing at a recorded upgrade target
- **THEN** the record's paymaster implementation becomes that target, and the regenerated registry lists it

#### Scenario: Unrecorded implementation
- **WHEN** the proxy points at an implementation that the record does not list as an upgrade target
- **THEN** the run reports the blocker and says to record the upgrade or investigate it

### Requirement: A handed-off deployment verifies against its profile
Once a chain's profile names its timelock, the deploy tooling SHALL accept that timelock as the paymaster's `ROLE_ADMIN`
holder in every check that compares the paymaster's role admin with the profile: a plan, the keyless verify Job and the
operator workflows' pre-checks. It SHALL still refuse a paymaster on which neither the profile's role admin nor its
timelock holds `ROLE_ADMIN`, and one on which a deployer holds it. Provisioning SHALL keep requiring the bootstrap role
admin's key, and SHALL say, when the role has been handed to the timelock, that role changes now go through timelock
proposals.

#### Scenario: Plan after the handoff
- **WHEN** the handoff gave `ROLE_ADMIN` to the profile's timelock and renounced the bootstrap key's, and an operator
  runs a plan for that chain
- **THEN** the role admin check passes, naming the timelock as the holder

#### Scenario: Provisioning after the handoff
- **WHEN** an operator runs `contracts:provision` after the handoff
- **THEN** it refuses before sending anything, and says that `ROLE_ADMIN` is held by the timelock and role changes go
  through its proposals

### Requirement: Every core run checks the chain's prerequisites
Every deployment of the core contracts SHALL refuse to sign unless the chain has CreateX with its upstream runtime
codehash and the canonical EntryPoint v0.9 runtime. This applies to the guided wizard and the low-level `deploy:cli
core` alike. Outside local chains, the EntryPoint the paymaster is initialised with SHALL be the canonical EntryPoint
v0.9. An override of it SHALL be accepted only on a local chain.

#### Scenario: Low-level run against foreign CreateX code
- **WHEN** `deploy:cli core` with a signing key targets a chain where the CreateX address holds code with another
  codehash
- **THEN** it refuses before signing, naming the expected and actual codehash

#### Scenario: EntryPoint override on a testnet
- **WHEN** an operator passes `--entry-point` to a core run on a non-local chain
- **THEN** the run refuses, saying that the wallet implementation is bound to the canonical EntryPoint v0.9

### Requirement: Provisioning supports separate role holders and a public signer address
The profile-driven provisioning command SHALL accept the sponsorship signer as a public address, and SHALL NOT require
the signer's private key. It SHALL accept a separate holder for each immediate paymaster role. Granting every role to
one address SHALL require an explicit opt-in and SHALL be refused on a mainnet chain. A tenant's withdrawal address
SHALL be supplied explicitly on a mainnet chain, never defaulted to the operator.

#### Scenario: HSM-held sponsorship signer
- **WHEN** the operator environment supplies the sponsorship signer's address and no signer private key
- **THEN** provisioning registers that address as a signer

#### Scenario: Separate holders
- **WHEN** the operator environment names a holder for each immediate role
- **THEN** each role is granted to its holder, and the doctor run at the end checks that topology

#### Scenario: One address for every role on a mainnet
- **WHEN** an operator asks provisioning on a mainnet chain to grant every role to one address
- **THEN** provisioning refuses before sending anything

### Requirement: Sponsorship rules name the tenant's contracts on a public chain
`contracts:sponsorship` SHALL install an allowlist of at least one contract, because the wallet-api enables no
sponsorship, wallet management included, for a tenant whose allowlist is empty. On a chain without the demo ERC-20 it
SHALL take the tenant's contracts from the operator environment, and SHALL refuse before calling the admin API when
none are given.

#### Scenario: Public chain with no contracts named
- **WHEN** an operator runs `contracts:sponsorship` on a chain without the demo ERC-20 and names no contract
- **THEN** the command refuses before any API call, saying that an empty allowlist sponsors nothing

#### Scenario: Public chain with the tenant's contracts
- **WHEN** the operator environment names the tenant's contracts
- **THEN** each is allow-listed for every function, sponsorship is enabled, and the rules read back as valid

### Requirement: The timelock handoff is verified before it is sent
Before granting the timelocked roles to a timelock and renouncing `ROLE_ADMIN`, the handoff SHALL verify all of the
following on-chain:
- the timelock's code matches a committed release's `GianoTimelock` fingerprint;
- its proposers and executors equal the profile's;
- its minimum delay and each per-function delay are at least the profile's published values;
- the delay policy passes the role-change rule.

On a mainnet chain, every proposer SHALL be a contract, such as a Safe. It SHALL never be an address without code, or an
EOA whose only code is an EIP-7702 delegation designator (`0xef0100` followed by an address), because a single key
controls both. Any failed check SHALL stop the handoff before anything is sent. The doctor SHALL classify proposers the
same way.

#### Scenario: Proposer mismatch
- **WHEN** the timelock's on-chain proposers differ from the profile's `timelock.proposers`
- **THEN** the handoff sends nothing and names the difference

#### Scenario: EOA proposer on a mainnet
- **WHEN** a mainnet profile's proposer is an address with no code
- **THEN** the handoff refuses, saying that a mainnet proposer must be a Safe or another contract

#### Scenario: EIP-7702-delegated proposer
- **WHEN** a proposer's code is an EIP-7702 delegation designator
- **THEN** the handoff on a mainnet refuses it as an EOA, and the doctor reports it as a key, not as a contract account

#### Scenario: Unrecognised timelock code
- **WHEN** the timelock address holds code that matches no release's `GianoTimelock` fingerprint
- **THEN** the handoff sends nothing and names the address and its codehash

### Requirement: RPC URLs are redacted in output
The deploy tooling and the doctor SHALL NOT print an RPC URL's path, query string or credentials. They SHALL print
only the scheme and host, so that a keyed provider URL never reaches a terminal, a CI log or a Job log.

#### Scenario: Keyed provider URL
- **WHEN** a run is given `https://example-node.provider.com/abc123secret/`
- **THEN** its output names `https://example-node.provider.com` and never contains `abc123secret`

### Requirement: The doctor checks the prerequisites the contracts depend on
The doctor's chain check SHALL fail when CreateX or the canonical EntryPoint v0.9 is missing or holds other code, and
when the chain lacks the Cancun opcodes the contracts use. A chain with neither the RIP-7212 precompile nor a deployed
P-256 verifier SHALL be reported as informational, with the higher gas cost, and SHALL NOT fail, because the wallet
verifies P-256 with its own built-in fallback. The doctor SHALL NOT require the Arachnid CREATE2 factory, and SHALL NOT
point to a script that does not exist.

#### Scenario: Chain without RIP-7212
- **WHEN** the doctor checks a chain with no `0x100` precompile and no verifier at the daimo address
- **THEN** the P-256 line is informational, says that passkey checks use the wallet's built-in verifier at a higher gas
  cost, and the chain check can still pass

#### Scenario: CreateX missing
- **WHEN** the doctor checks a chain with no code at the CreateX address
- **THEN** the chain check fails, naming CreateX and the adoption checklist step
