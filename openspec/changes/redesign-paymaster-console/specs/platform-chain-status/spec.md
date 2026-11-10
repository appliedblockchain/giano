## Purpose

Defines what wallet-api reports about each chain it serves, for platform admins: the prober's verdict and what it last found, the node's head, the bundler and its EntryPoint, and the paymaster's ledger and watcher, answering whether the deployment can transact on that chain right now.

## ADDED Requirements

### Requirement: Platform admins read the status of each served chain
`GET /v1/platform/chains` SHALL require a platform admin session. It SHALL return the sponsorship signer's health once, and one entry per chain wallet-api serves, with:
- chain id and name;
- the prober's registry status, its last full verification with its failures, and its last reachability probe;
- the node: reachable, head block and head age in seconds;
- the bundler: reachable, and whether it supports the configured EntryPoint, asked with `eth_supportedEntryPoints`;
- for a chain that sponsors: the paymaster address, deposit, treasury, stake, invariant slack, the watcher's last synced block, its lag in blocks behind the head, and when it was checked.

Each chain SHALL be probed in parallel, each part (the node's head, the bundler, the signer) with a 3-second timeout that bounds the request as well as the wait. A part that times out SHALL be reported as unreachable without delaying the others. A bundler that answers `eth_supportedEntryPoints` with a JSON-RPC error SHALL be reported reachable, with whether it supports the EntryPoint unknown. The response SHALL NOT include any node or bundler URL, nor any error message that could hold one: a failed probe SHALL be described by a category, and verification failures by kind.

#### Scenario: One chain down
- **WHEN** one chain's node does not answer within 3 seconds
- **THEN** the response returns within about 3 seconds, with that chain's node unreachable and every other chain's status complete

#### Scenario: A keyed node refuses a probe
- **WHEN** the node behind a URL with a provider key in its path answers a probe with HTTP 429
- **THEN** the chain's last probe reads `http 429`, and no response contains the URL or the key

#### Scenario: Bundler refuses the question
- **WHEN** a chain's bundler answers `eth_supportedEntryPoints` with a JSON-RPC error
- **THEN** that chain's bundler is reachable and `entryPointSupported` is null

#### Scenario: No session
- **WHEN** the request has no platform admin session
- **THEN** the response is 401

### Requirement: The prober keeps what it found
For each chain, the prober SHALL keep its last full verification and the time and outcome of each reachability probe, so that `checkedAt` for a healthy chain is the last probe, not the boot time.

#### Scenario: Healthy chain
- **WHEN** a ready chain was probed 30 seconds ago
- **THEN** its `lastProbe.at` is 30 seconds ago

### Requirement: The bundler's executors are reported per chain
giano-bundler SHALL answer `giano_executors` on each chain's endpoint with the chain's current gas price and, for every executor key it signs with, the executor's address, its native balance read when asked, whether its lane holds a transaction and since when, and its latest and pending nonces, with how long a lane may hold one transaction before it is stuck. It SHALL NOT return a key.

`GET /v1/platform/chains` SHALL report, for each chain, the bundler's executors and gas price within the bundler's timeout, and SHALL report them as unknown, not as a failure, where the bundler does not answer the method, saying whether the bundler lacks the method or did not answer. An answer of the wrong shape SHALL make that chain's executors unknown, not fail the response.

#### Scenario: Two executors, one empty
- **WHEN** the bundler signs with two executor keys and one has no balance on chain 84532
- **THEN** that chain's entry lists both executors with their balances, the empty one at 0

#### Scenario: Bundler without the method
- **WHEN** the bundler answers `giano_executors` with a JSON-RPC error
- **THEN** that chain's bundler is reachable and its executors are unknown
