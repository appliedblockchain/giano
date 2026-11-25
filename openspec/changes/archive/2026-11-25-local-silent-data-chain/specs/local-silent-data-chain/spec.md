# Spec Delta

## Purpose

Gives every local stack a Silent Data chain: an anvil node behind Silent Data's published gateway, so the private token flow and Giano's behaviour on a restricted RPC are tested locally and in CI.

## ADDED Requirements

### Requirement: Local stacks run a Silent Data chain behind the published gateway
The infrastructure and e2e stacks SHALL run chain 31339, named "Devnet SD (Silent Data)": an anvil node with a baked state, behind Silent Data's gateway. The gateway SHALL be the published `@appliedblockchain/silentdatarollup-custom-rpc` package at an exact version from the lockfile. Chains 31337 and 31338 SHALL stay plain anvil.

#### Scenario: Stack starts
- **WHEN** a local stack starts
- **THEN** the gateway answers `eth_chainId` with 31339, and Devnet A and Devnet B answer as before

#### Scenario: Gateway restrictions apply
- **WHEN** a client sends `eth_getStorageAt` or `anvil_setBalance` to the gateway
- **THEN** the gateway refuses the method, and the same request sent to the node directly succeeds

### Requirement: Components reach the Silent Data chain only through the gateway
wallet-api, the bundler, paymaster-admin, both wallets and the demo dApp SHALL reach chain 31339 only through the gateway. The chain's backend entry SHALL set `bundler.stateOverride: false`. No component SHALL check for chain 31339 by its id to handle Silent Data or the gateway differently. That behaviour SHALL come only from the chain's `GIANO_CHAINS` entry. The lists of local devnet chain ids are separate: 31339 SHALL join them next to 31337 and 31338.

#### Scenario: Backend configuration
- **WHEN** the local stack's `GIANO_CHAINS` is read
- **THEN** the entry for 31339 has the gateway's URL as `rpcUrl` and `bundler.stateOverride` set to `false`

#### Scenario: Sponsored operation through the gateway
- **WHEN** a wallet sends a sponsored user operation on 31339
- **THEN** the bundler estimates it without a state override, submits it through the gateway, and wallet-api settles it from the receipt

### Requirement: The Silent Data chain's state comes from the shared generator
The state of chain 31339 SHALL come from the same generator as the other local chains, with the same pinned anvil. Every local chain SHALL carry the private test token at the same address, and `e2e/devnet/addresses.json` SHALL record that address. The generator SHALL refuse to write a state whose addresses differ from the recorded ones.

#### Scenario: Identical addresses
- **WHEN** the generator runs for 31339
- **THEN** the factory, the paymaster, the test ERC-20 and the private test token are at the addresses `addresses.json` records

#### Scenario: Divergent address
- **WHEN** a generator run for 31339 deploys a contract at an address that differs from `addresses.json`
- **THEN** the run fails and writes no state file

### Requirement: Both demo tenants are sponsored on the Silent Data chain
The local stacks SHALL install the sponsorship rules of tenants `stock` and `byo` on chain 31339, as on the other local chains. The rules' allowlist SHALL include the private test token.

#### Scenario: Private mint sponsored
- **WHEN** a `stock` or `byo` wallet mints the private test token on 31339
- **THEN** the paymaster sponsors the operation, and the tenant's sponsorship balance on 31339 shows the debit

### Requirement: The BYO wallet fixture serves a list of chains
The BYO wallet fixture SHALL accept a list of chains, each with an id and a name, and SHALL serve every chain in the list. In a devnet checkout with no chain variables, it SHALL serve every local chain. It SHALL still accept the pair `CHAIN_ID` / `CHAIN_B_ID`, and SHALL refuse to start when both forms are set.

#### Scenario: Three chains
- **WHEN** the fixture starts with a list of 31337, 31338 and 31339
- **THEN** a dApp can connect to each of the three chains through it

#### Scenario: Legacy pair
- **WHEN** only `CHAIN_ID` and `CHAIN_B_ID` are set
- **THEN** the fixture serves those two chains, as before

#### Scenario: Both forms set
- **WHEN** both the list and `CHAIN_ID` are set
- **THEN** the fixture exits non-zero with a message that names both variables, before it serves anything

### Requirement: An end-to-end test proves the gateway enforces privacy
The e2e suite SHALL check that the gateway enforces privacy before it tests the private token flow. An unsigned balance read of the private token SHALL fail through the gateway, and the same read sent to the node directly SHALL succeed.

#### Scenario: Gateway missing
- **WHEN** chain 31339's RPC is plain anvil without the gateway
- **THEN** the check fails, and the test names the gateway as the cause

### Requirement: The private token flow is tested end to end for both tenants
The demo e2e project SHALL drive the demo's private token section on chain 31339 through a real wallet popup: the message for an undeployed wallet, mint, the read approval, the signed balance read, transfer and the outsider view. It SHALL check the settlement and the sponsorship debit. It SHALL run the flow once for `stock` and once for `byo`.

#### Scenario: Stock flow
- **WHEN** the demo spec runs for tenant `stock`
- **THEN** each step's outcome is confirmed in the demo's ledger, the signed read shows the minted balance, and the outsider view shows the unsigned read refused

#### Scenario: BYO flow
- **WHEN** the demo spec runs for tenant `byo`
- **THEN** the same steps pass through the BYO wallet fixture

#### Scenario: CI
- **WHEN** the e2e workflow runs its "reference demo" leg
- **THEN** it builds the gateway image, waits for the gateway to answer, and runs the private token spec
