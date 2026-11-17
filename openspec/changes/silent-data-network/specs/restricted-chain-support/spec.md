# Spec Delta

## Purpose

Giano's bundler, its wallet-api chain checks and its operator tools work on a chain whose RPC restricts reads or that charges no gas, such as a Silent Data chain. Per-chain settings and fallbacks handle each restriction, so no component needs to know the chain by name.

## ADDED Requirements

### Requirement: The proxy implementation is read without storage access
When an RPC refuses `eth_getStorageAt`, the paymaster proxy's implementation SHALL be read from the proxy's latest ERC-1967 `Upgraded` event. This applies to wallet-api's chain check, `giano-doctor` and the paymaster SDK. Each log query SHALL span at most 9,000 blocks, counted inclusively. When the storage read succeeds, it SHALL be used, and no logs SHALL be read. When the storage read fails for any other reason than a refusal of the method, that error SHALL be raised and no logs SHALL be read.

#### Scenario: Storage read refused
- **WHEN** the RPC refuses `eth_getStorageAt` and the proxy's latest `Upgraded` event names implementation `I`
- **THEN** the implementation read returns `I`, and the release check runs against the code at `I`

#### Scenario: Upgrade older than one span
- **WHEN** the latest `Upgraded` event is more than 9,000 blocks before the latest block
- **THEN** the reader queries earlier spans of at most 9,000 blocks each, from newest to oldest, and returns the implementation from the first span that holds an event

#### Scenario: No upgrade event
- **WHEN** the storage read is refused and no span holds an `Upgraded` event for the proxy
- **THEN** the read reports no implementation, and the check fails as it does for an empty slot

#### Scenario: Walk limit reached
- **WHEN** the storage read is refused and the walk sends its maximum number of log queries without finding an `Upgraded` event
- **THEN** the read fails with an error that names the blocks searched and says to pass the proxy's deployment block, and no further log query is sent

#### Scenario: Repeated read through the same client
- **WHEN** the storage read is refused and the implementation is read again through the same client
- **THEN** the reader queries only the blocks after the last block it read, and returns the implementation of a newer `Upgraded` event when one is there

#### Scenario: Other storage-read failure
- **WHEN** the storage read fails with a timeout, a rate limit or any error other than a refusal of the method
- **THEN** that error is raised unchanged, and no log query is sent

#### Scenario: Storage refused and log read fails
- **WHEN** the storage read is refused and a log query fails
- **THEN** the read fails with an error that names both failures and carries the storage-read error as its cause

#### Scenario: Storage refused and logs unavailable
- **WHEN** the storage read is refused and the client cannot read logs
- **THEN** the original storage-read error is raised unchanged

### Requirement: Gas estimation without state overrides
A chain's `bundler` section SHALL accept `stateOverride`, a boolean whose default is `true`. With `false`, the bundler SHALL estimate a user operation without any `eth_call` state override, and SHALL return fixed limits: verification gas of at least 1,000,000, and paymaster verification gas of at least 200,000 when there is a paymaster. A higher verification or paymaster verification gas that the caller sends SHALL be kept.

#### Scenario: Chain refuses state overrides
- **WHEN** a chain sets `bundler.stateOverride: false` and a wallet asks for an estimate with no limits
- **THEN** the estimate returns verification gas 1,000,000 and call gas 300,000, and the RPC receives no `eth_call` with a third parameter

### Requirement: Call gas without state overrides
On a chain with `stateOverride: false`, the estimated call gas SHALL be 0 when the call data is empty. Otherwise it SHALL be the call gas the caller sends, when that is above 0, and 300,000 when the caller sends none.

#### Scenario: Caller sends no call gas
- **WHEN** the caller sends call gas 0 with non-empty call data
- **THEN** the estimate returns call gas 300,000

#### Scenario: Caller knows its call gas
- **WHEN** the caller sends call gas 120,000 on a chain with `stateOverride: false`
- **THEN** the estimate keeps call gas 120,000

#### Scenario: Empty call data
- **WHEN** the user operation's call data is empty
- **THEN** the estimated call gas is 0

#### Scenario: Default chain
- **WHEN** a chain's `bundler` section does not name `stateOverride`
- **THEN** the bundler simulates with state overrides, as before this change

### Requirement: Pre-verification gas does not depend on simulation
The pre-verification gas SHALL be computed the same way whether the bundler simulates or uses fixed limits. On an OP Stack chain, that includes the L1 data fee.

#### Scenario: Fixed limits on an OP Stack chain
- **WHEN** a chain with `chainType: "op-stack"` sets `stateOverride: false`
- **THEN** the estimated pre-verification gas includes the L1 data fee, as it does with simulation

### Requirement: A fee of 0 is accepted on a chain that charges no gas
At estimation, the bundler SHALL refuse a user operation whose `maxFeePerGas` is 0 only when the latest block's base fee is above 0. On a chain whose base fee is 0 or absent, a fee of 0 SHALL be accepted.

#### Scenario: Gasless chain
- **WHEN** the latest block's base fee is 0 and a wallet asks for an estimate with `maxFeePerGas` 0
- **THEN** the estimate succeeds

#### Scenario: Chain that charges gas
- **WHEN** the latest block's base fee is above 0 and a wallet asks for an estimate with `maxFeePerGas` 0
- **THEN** the bundler answers with invalid-params error "user operation max fee per gas must be larger than 0 during gas estimation"

### Requirement: Fixed limits are sponsored and settled like simulated ones
On a chain that charges gas and sets `stateOverride: false`, wallet-api SHALL compute the sponsorship maximum charge and the tenant reservation from the fixed limits the bundler returned, with the same rules as for simulated limits. The tenant SHALL be charged what the paymaster's `Sponsored` event records (gas cost, fee and overhead), as for simulated limits, and the rest of the reservation SHALL be released.

#### Scenario: Sponsored operation on a gas-charging restricted chain
- **WHEN** a tenant with a sufficient balance and cap sponsors an ETH transfer on a chain with base fee above 0 and `stateOverride: false`
- **THEN** the operation succeeds, the tenant's ledger is charged the `Sponsored` event's gas cost plus its fee plus its overhead, and the reservation above that is released
- **AND** the `Sponsored` gas cost is at most the `UserOperationEvent`'s `actualGasCost`

#### Scenario: Cap below the fixed-limit charge
- **WHEN** the maximum charge from the fixed limits exceeds the tenant's `maxCostPerTxWei`
- **THEN** wallet-api refuses sponsorship with the existing cap refusal, naming the maximum charge and the cap, and no reservation is made

#### Scenario: Gasless chain
- **WHEN** the same operation runs on a chain with base fee 0 and `maxFeePerGas` 0
- **THEN** the gas part of the maximum charge is 0, and the operation succeeds

### Requirement: Operator tools sign their RPC requests on request
`deploy:cli` and `provision:paymaster` SHALL accept `--signed-rpc`. With it, every RPC request after the chain id read SHALL carry `x-timestamp` (RFC 3339) and `x-signature`. The chain id read goes unsigned, because the signature covers the chain id. The signature is the operator key's EIP-191 signature of the chain id, the exact HTTP body and the timestamp, joined. `--signed-rpc` without an operator key SHALL be refused before any request is sent.

#### Scenario: Role-gated call through a gateway that rewrites `from`
- **WHEN** `provision:paymaster --signed-rpc` estimates a call that needs a role the operator holds, through an RPC that replaces `from` on unsigned calls
- **THEN** the estimate runs as the operator, and provisioning succeeds

#### Scenario: Flag without a key
- **WHEN** `deploy:cli core --signed-rpc` runs without `DEPLOYER_PRIVATE_KEY`
- **THEN** the command exits non-zero, says the flag needs a key, and sends no request

#### Scenario: Flag absent
- **WHEN** either command runs without `--signed-rpc`
- **THEN** no request carries `x-timestamp` or `x-signature`

### Requirement: Redacted receipts do not change an operation's outcome
The outcome of a user operation SHALL come from its `UserOperationEvent` log, never from the fields of the bundle transaction's receipt that an RPC may redact (`from`, `to`, `gasUsed`).

#### Scenario: Receipt read by a non-sender
- **WHEN** the bundle transaction's receipt returns `from` as `0x0` and `gasUsed` as `0`, and the `UserOperationEvent` says the operation succeeded
- **THEN** the user operation receipt reports success, with `actualGasUsed` from the event

### Requirement: User operation lookup reveals no more than the chain
`eth_getUserOperationByHash` SHALL build its answer only from what the RPC returns to an unsigned reader. When the bundle transaction's calldata is redacted, the bundler SHALL answer `null` for that operation. It SHALL NOT return an error, and SHALL NOT fill in the operation from its own memory or from a request signed with the executor key.

#### Scenario: Redacted bundle transaction
- **WHEN** a mined operation's bundle transaction reads with calldata `0x`
- **THEN** `eth_getUserOperationByHash` answers `null`, and `eth_getUserOperationReceipt` still answers from the `UserOperationEvent`

#### Scenario: Public chain
- **WHEN** the bundle transaction's calldata is readable
- **THEN** `eth_getUserOperationByHash` returns the operation, as before this change
