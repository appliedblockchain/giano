## ADDED Requirements

### Requirement: Platform admins read the status of each served chain
`GET /v1/platform/chains` SHALL require a platform admin session. It SHALL return the sponsorship signer's health once, and one entry per chain wallet-api serves, with:
- chain id and name;
- the prober's registry status, its last full verification with its failures, and its last reachability probe;
- the node: reachable, head block and head age in seconds;
- the bundler: reachable, and whether it supports the configured EntryPoint, asked with `eth_supportedEntryPoints`;
- for a chain that sponsors: the paymaster address, deposit, treasury, stake, invariant slack, the watcher's last synced block, its lag in blocks behind the head, and when it was checked.

Each chain SHALL be probed in parallel with a 3-second timeout. A chain that times out SHALL be reported as unreachable without delaying the others. The response SHALL NOT include any node or bundler URL, nor any error message that could hold one: a failed probe SHALL be described by a category, and verification failures by kind.

#### Scenario: One chain down
- **WHEN** one chain's node does not answer within 3 seconds
- **THEN** the response returns within about 3 seconds, with that chain's node unreachable and every other chain's status complete

#### Scenario: A keyed node refuses a probe
- **WHEN** the node behind a URL with a provider key in its path answers a probe with HTTP 429
- **THEN** the chain's last probe reads `http 429`, and no response contains the URL or the key

#### Scenario: No session
- **WHEN** the request has no platform admin session
- **THEN** the response is 401

### Requirement: The prober keeps what it found
For each chain, the prober SHALL keep its last full verification and the time and outcome of each reachability probe, so that `checkedAt` for a healthy chain is the last probe, not the boot time.

#### Scenario: Healthy chain
- **WHEN** a ready chain was probed 30 seconds ago
- **THEN** its `lastProbe.at` is 30 seconds ago
