# contract-deployment Specification

## Purpose
How the contracts tooling deploys Giano to a chain: each chain profile belongs to a network class (mainnet, testnet or
local) with its own canonical deployer and deterministic CREATE3 addresses, a profile can override an address, every
deviation from the deterministic route is recorded and, on mainnet, explicitly confirmed, and deployers end the
deployment holding no authority on the contracts.

## Requirements

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
contract's fixed label, so every chain in a class shares one set of expected addresses. A deployment run SHALL print,
for every contract, the expected address, the address it will use, and whether that is a deviation. While the class
deployer is unset, the expected address SHALL be shown as unresolved and no deviation SHALL be derived from it.

#### Scenario: Default mainnet plan
- **WHEN** an operator plans a deployment for a mainnet profile with no overrides
- **THEN** every planned address is the CREATE3 address of the mainnet deployer and the contract's label, and none is
  marked as a deviation

### Requirement: Canonical upgrade targets are deterministic
An implementation the chain was upgraded to, which its deployment record lists among its upgrade targets at the
CREATE3 address of the class deployer and the target's versioned label (`giano.paymaster.impl@v3`), SHALL have that
address as its expected address. It is where every chain of the class has that upgrade: it SHALL be deterministic, not
a deviation, whatever release it holds.

#### Scenario: Plan after a canonical paymaster upgrade
- **WHEN** a chain's paymaster was upgraded by the class deployer, and its record lists the paymaster implementation
  at the CREATE3 address of the class deployer and the versioned label
- **THEN** the plan expects the paymaster implementation at that address, marks it deterministic, reports no
  deviation for it, and does not refuse it for holding a release other than the selected one

### Requirement: A run resolves the address it uses from the profile and the record first
The address a run uses for a contract SHALL be, in order: the profile's override; the address the chain's deployment
record lists; the expected address when it already holds code; otherwise the CREATE3 address of the signing key. A
run without a signing key SHALL use the expected address only when neither an override nor a recorded address applies.

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
implementation, have the profile's EntryPoint, and grant `ROLE_ADMIN` to the planned role admin. Its fee parameters
are reported when they differ from the profile's, not refused: the fee and parameter admins tune them after
deployment.

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

### Requirement: A verify-only run accepts any release
On a deployment, and on a plan that previews one, existing code at a non-overridden address (deterministic or
recorded) SHALL be the selected release's, unless it is a recorded canonical upgrade target. A verify-only run
(`deploy:cli core` without a key, as the Helm Job runs it) SHALL accept any release's code there, because a chain keeps
the release it was adopted at (the factory's implementation is immutable). `deploy:cli core` SHALL take the release
from `--release`, else the chain profile's `release`, else the latest.

#### Scenario: Verify-only run on a chain adopted at an older release
- **WHEN** the verify-only Helm Job runs on a chain whose contracts hold release v2 after v3 is cut
- **THEN** the plan has no release blocker and the run records the chain's v2 contracts

#### Scenario: Deployment against another release
- **WHEN** a run with a key, or a keyless `--plan`, selects v3 on a chain whose wallet implementation holds v2
- **THEN** the plan is refused with "already holds release v2, not the selected v3"

#### Scenario: Tuned paymaster fees
- **WHEN** `deploy:cli core` runs on a chain whose paymaster's `penaltyBps` was changed with `setPenaltyBps`
- **THEN** the run warns that the fee differs from its configuration and continues

### Requirement: The deployment record states how each address was obtained
Each deployment record SHALL hold:
- the chain id and network class;
- the signing deployer, or null until a signing run deploys something;
- per contract: its label, address, expected address, release, the raw code hash, the release fingerprint the code
  matched, and the deploying transaction when deployed in that run;
- whether each address is deterministic;
- every deviation the operator confirmed.

Records for non-local chains SHALL be committed.

#### Scenario: Record after a confirmed deviation
- **WHEN** a mainnet run completes after the operator confirmed an overridden paymaster
- **THEN** the chain's record marks the paymaster as non-deterministic and lists the confirmed deviation, and the
  other contracts are marked deterministic

### Requirement: Deployers hold no authority on deployed contracts
On every non-local chain, the deploy tooling SHALL refuse a paymaster `ROLE_ADMIN` that is the signing key or a
configured canonical deployer, and SHALL refuse to adopt an existing paymaster proxy on which either holds
`ROLE_ADMIN`.

#### Scenario: Deployer given as role admin
- **WHEN** a testnet or mainnet run is given the signing key's address as `ROLE_ADMIN`
- **THEN** it refuses before signing, and says that the role admin must be a timelock or Safe, not a deployer

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

#### Scenario: A mistyped role holder
- **WHEN** a named role holder, signer, stake or tenant funding amount is not valid
- **THEN** provisioning refuses before sending anything

#### Scenario: A run that stops part-way
- **WHEN** a provisioning run with separate holders fails after the bootstrap key took the signer, stake or tenant
  admin role for the run
- **THEN** the bootstrap key gives those roles up before the command exits, and a rerun with the same arguments
  resumes

#### Scenario: A rerun after a run that could not clean up
- **WHEN** the bootstrap key still holds the signer, stake or tenant admin role and is not its named holder
- **THEN** the rerun gives the role up, whether or not the rerun granted it

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
- the timelock is the published one: the profile's timelock address, else the deployment record's;
- the timelock's code matches a committed release's `GianoTimelock` fingerprint;
- its proposers and executors equal the profile's, and no other account holds a proposer, canceller, executor or
  admin role, judged from the timelock's role-grant history since its deployment block;
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

#### Scenario: Another timelock than the published one
- **WHEN** `--timelock` names an address other than the profile's timelock address
- **THEN** the handoff sends nothing and names both addresses

#### Scenario: The role-grant history cannot be read
- **WHEN** the timelock's deployment block is unknown, or an `eth_getLogs` query over its role grants fails
- **THEN** the handoff sends nothing, saying that extra role holders cannot be ruled out. It reads the history at
  most 200 blocks per query, the span the Base Sepolia public RPC serves

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
