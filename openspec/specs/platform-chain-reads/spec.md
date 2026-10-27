# platform-chain-reads Specification

## Purpose

Defines wallet-api's chain read relay for platform admins: the one path through which a hosted paymaster console reads the chain. It forwards only bounded, read-only JSON-RPC calls from a signed-in platform admin, so the provider's keyed URL stays in wallet-api and its quota cannot be spent by anyone else.

## Requirements

### Requirement: Platform chain reads need a platform admin session
`POST /v1/platform/rpc/:chainId` SHALL exist exactly where the platform admin routes are registered. It SHALL apply the same checks as every other authenticated platform route:
- a request carrying an `Origin` header is refused with `403 platform-origin-refused` before anything else;
- a missing, unknown, expired or revoked session, or a tenant admin key, is refused with the same `401` body as every other platform authentication failure;
- the request is attributed to the platform admin id the `platform_admins` table currently gives the session's address.

The chain SHALL be resolved from the path against the configured chain registry: an unserved chain is `400 unsupported-chain` and a configured but unavailable chain is `503 chain-unavailable`, as on the other chain-bound routes.

#### Scenario: Signed-in platform admin reads
- **WHEN** a valid platform admin session posts `{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber"}` to `/v1/platform/rpc/<served chain>` with no `Origin`
- **THEN** the response is 200 with a JSON-RPC result carrying the node's block number

#### Scenario: No session
- **WHEN** the same request is sent with no bearer token
- **THEN** the response is 401 with the platform authentication failure body, and nothing is sent to the node

#### Scenario: Tenant admin key
- **WHEN** a valid tenant admin key is presented as the bearer token
- **THEN** the response is 401

#### Scenario: From a browser page
- **WHEN** a valid session's request carries `Origin: https://evil.example`
- **THEN** the response is 403 `platform-origin-refused`

#### Scenario: Platform tier disabled
- **WHEN** the environment has no platform sign-in domain
- **THEN** `/v1/platform/rpc/<chainId>` does not exist and answers 404

#### Scenario: Unserved chain
- **WHEN** a valid session requests a chain id the deployment does not serve
- **THEN** the response is 400 `unsupported-chain` listing the served chain ids

### Requirement: Only read-only methods are forwarded
The relay SHALL forward a JSON-RPC method to the node only if it is in the same read-only allowlist as the tenant RPC relay (`/v1/rpc`). `eth_chainId` SHALL be answered from configuration without a node call. Any other method SHALL be answered with a JSON-RPC error `-32601` in a `200` response, and nothing SHALL be sent to the node. A body that is not a single JSON-RPC 2.0 request object, a batch array included, SHALL be refused with `400`.

#### Scenario: Write method
- **WHEN** a signed-in platform admin sends `eth_sendRawTransaction`
- **THEN** the response carries JSON-RPC error `-32601` and the node receives nothing

#### Scenario: Debug or trace method
- **WHEN** a signed-in platform admin sends `debug_traceTransaction` or `trace_block`
- **THEN** the response carries JSON-RPC error `-32601` and the node receives nothing

#### Scenario: Batch
- **WHEN** the body is a JSON array of two requests
- **THEN** the response is 400 and the node receives nothing

### Requirement: Request bodies are small
The relay SHALL refuse a request body larger than 16 KiB with `413` before parsing it, and SHALL send nothing to the node.

#### Scenario: Oversized body
- **WHEN** a signed-in platform admin posts an `eth_call` whose body is 20 KiB
- **THEN** the response is 413 and the node receives nothing

### Requirement: Log queries are bounded
An `eth_getLogs` request SHALL be forwarded only when its filter either names a `blockHash`, or has `fromBlock` and `toBlock` as hex block numbers with `toBlock - fromBlock + 1` no greater than `PLATFORM_RPC_MAX_LOG_BLOCKS` (default 10 000). Any other `eth_getLogs` SHALL be answered with JSON-RPC error `-32602`, naming the limit, and nothing SHALL be sent to the node.

#### Scenario: Window the SDK uses
- **WHEN** a signed-in platform admin requests logs for a 9 000-block numeric range
- **THEN** the request is forwarded and the node's logs are returned

#### Scenario: Unbounded range
- **WHEN** a signed-in platform admin requests logs from `earliest` to `latest`, or over 50 000 numeric blocks
- **THEN** the response carries JSON-RPC error `-32602` naming the limit, and the node receives nothing

### Requirement: Platform chain reads are rate limited per session
Forwarded requests SHALL be limited to `PLATFORM_RPC_RATE_LIMIT_PER_MINUTE` per platform admin session. This budget SHALL be separate from `PLATFORM_RATE_LIMIT_PER_MINUTE`, so reads never use up a platform admin's tenant-management budget, and the reverse. Over the limit, the response SHALL carry JSON-RPC error `-32021` and nothing SHALL be sent to the node. The limit SHALL NOT be keyed on the client IP.

#### Scenario: Session over its limit
- **WHEN** one session exceeds `PLATFORM_RPC_RATE_LIMIT_PER_MINUTE` forwarded reads within a minute
- **THEN** further reads in that minute carry JSON-RPC error `-32021`, and another platform admin's session still reads normally

#### Scenario: Reads do not spend the management budget
- **WHEN** a session has made more chain reads than `PLATFORM_RATE_LIMIT_PER_MINUTE` within a minute
- **THEN** its next `GET /v1/platform/tenants` in that minute still succeeds

### Requirement: Node answers pass through and the provider stays hidden
A node error SHALL reach the caller with its code, message and data intact, so a revert reason survives. An unreachable node SHALL be answered with JSON-RPC error `-32023`. No response, header or error message SHALL contain the provider's URL or key. Each request SHALL be counted by method, chain and outcome.

#### Scenario: Revert
- **WHEN** a forwarded `eth_call` reverts at the node
- **THEN** the JSON-RPC error carries the node's code, message and revert data

#### Scenario: Node down
- **WHEN** the chain's RPC endpoint cannot be reached
- **THEN** the response carries JSON-RPC error `-32023` and no URL
