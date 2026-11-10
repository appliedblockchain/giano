# platform-chain-status Specification

## Purpose

Defines what wallet-api reports about each chain it serves, for platform admins: the prober's verdict and what it last found, the node's head, the bundler and its EntryPoint, and the paymaster's ledger and watcher, answering whether the deployment can transact on that chain right now.

## Requirements

### Requirement: Platform admins read the status of each served chain
`GET /v1/platform/chains` SHALL require a platform admin session. It SHALL return the sponsorship signer's health once, the ledger lag past which wallet-api stops trusting the ledger (`maxLedgerLagBlocks`), and one entry per chain wallet-api serves, with:
- chain id and name;
- the prober's registry status, its last full verification with its failures, and its last reachability probe;
- the node: reachable, head block and head age in seconds;
- the bundler: reachable, and whether it supports the configured EntryPoint, asked with `eth_supportedEntryPoints`.

#### Scenario: No session
- **WHEN** the request has no platform admin session
- **THEN** the response is 401

### Requirement: A sponsoring chain's status includes its paymaster and watcher
For a chain that sponsors, its entry in `GET /v1/platform/chains` SHALL also carry the paymaster address, deposit, treasury, stake, invariant slack, the watcher's last synced block, its lag in blocks behind the head, and when it was checked.

#### Scenario: Sponsoring chain
- **WHEN** a platform admin reads the status of a chain that sponsors
- **THEN** its entry carries the paymaster address, deposit, treasury, stake, invariant slack, the watcher's last synced block and lag, and when it was checked

### Requirement: Each chain is probed in parallel within a timeout
Each chain SHALL be probed in parallel, each part (the node's head, the bundler, the signer) with a 3-second timeout that bounds the request as well as the wait. A part that times out SHALL be reported as unreachable without delaying the others. A bundler that answers `eth_supportedEntryPoints` with a JSON-RPC error SHALL be reported reachable, with whether it supports the EntryPoint unknown.

#### Scenario: One chain down
- **WHEN** one chain's node does not answer within 3 seconds
- **THEN** the response returns within about 3 seconds, with that chain's node unreachable and every other chain's status complete

#### Scenario: Bundler refuses the question
- **WHEN** a chain's bundler answers `eth_supportedEntryPoints` with a JSON-RPC error
- **THEN** that chain's bundler is reachable and `entryPointSupported` is null

### Requirement: Chain status holds no URL and no error message
The response SHALL NOT include any node or bundler URL, nor any error message that could hold one: a failed probe SHALL be described by a category, and verification failures by kind.

#### Scenario: A keyed node refuses a probe
- **WHEN** the node behind a URL with a provider key in its path answers a probe with HTTP 429
- **THEN** the chain's last probe reads `http 429`, and no response contains the URL or the key

### Requirement: The prober keeps what it found
For each chain, the prober SHALL keep its last full verification and the time and outcome of each reachability probe, so that `checkedAt` for a healthy chain is the last probe, not the boot time.

#### Scenario: Healthy chain
- **WHEN** a ready chain was probed 30 seconds ago
- **THEN** its `lastProbe.at` is 30 seconds ago

### Requirement: giano-bundler reports its executors
giano-bundler SHALL answer `giano_executors` on each chain's endpoint with the chain's current gas price and, for every executor key it signs with, the executor's address, its native balance read when asked, whether its lane holds a transaction, since when and for how many seconds by the bundler's own clock, and its latest and pending nonces, with how long a lane may hold one transaction before it is stuck. It SHALL NOT return a key.

#### Scenario: Executors asked for
- **WHEN** `giano_executors` is called on a chain's endpoint
- **THEN** the answer holds the chain's gas price and, for each executor key, its address, balance, whether its lane holds a transaction and for how long, and its latest and pending nonces, and no key

#### Scenario: A lane held for 90 seconds
- **WHEN** an executor's lane took its transaction 90 seconds ago by the bundler's clock
- **THEN** that executor's `heldSeconds` is 90, whatever the caller's clock says, and an idle lane's is null

### Requirement: The bundler's executors are reported per chain
`GET /v1/platform/chains` SHALL report, for each chain, the bundler's executors and gas price within the bundler's timeout, and SHALL report them as unknown, not as a failure, where the bundler does not answer the method, saying whether the bundler lacks the method or did not answer. An answer of the wrong shape SHALL make that chain's executors unknown, not fail the response.

#### Scenario: Two executors, one empty
- **WHEN** the bundler signs with two executor keys and one has no balance on chain 84532
- **THEN** that chain's entry lists both executors with their balances, the empty one at 0

#### Scenario: Bundler without the method
- **WHEN** the bundler answers `giano_executors` with a JSON-RPC error
- **THEN** that chain's bundler is reachable and its executors are unknown
