## Purpose

Defines who a Giano operator is and how they prove it to `wallet-api`. An operator signs an EIP-4361 message with a wallet whose address the deployment lists, and gets a short-lived operator session. That session is the only credential the operator routes accept, and it is never usable as a tenant credential or the other way round.

## ADDED Requirements

### Requirement: Operators are configured, never stored
The set of operators SHALL be the deployment's `OPERATOR_ADDRESSES` configuration: a JSON array of `{ id, address }`. Each `id` matches `^[a-z0-9-]{1,64}$` and each `address` is a 20-byte hex address, normalised to lowercase. No database write SHALL be able to add an operator.

Boot SHALL refuse a list with a duplicate `id` or `address`. Boot SHALL also refuse a non-empty list without `OPERATOR_SIWE_DOMAIN`. When the list is empty or absent, no `/v1/operator/*` route SHALL be registered.

#### Scenario: Operator API disabled
- **WHEN** `OPERATOR_ADDRESSES` is empty and a caller requests any `/v1/operator/*` path
- **THEN** the response is 404, as for any unregistered route

#### Scenario: Duplicate operator entry
- **WHEN** `OPERATOR_ADDRESSES` lists the same address under two ids
- **THEN** `wallet-api` refuses to start and names the duplicate

#### Scenario: Missing sign-in domain
- **WHEN** `OPERATOR_ADDRESSES` is non-empty and `OPERATOR_SIWE_DOMAIN` is unset
- **THEN** `wallet-api` refuses to start

### Requirement: Challenge issues a server-written sign-in message
`POST /v1/operator/auth/challenge` with `{ address, chainId }` SHALL return `200 { message }`, where `message` is an EIP-4361 message with these fields:
- `domain` is `OPERATOR_SIWE_DOMAIN`;
- `uri` is `OPERATOR_SIWE_URI`;
- `address` is the requested address, checksummed;
- `version` is `1`;
- `chainId` is the requested chain;
- the statement names the session lifetime;
- the nonce is fresh;
- `issuedAt` is now and `expirationTime` is now plus `OPERATOR_CHALLENGE_TTL_SECONDS`.

For a listed address, the service SHALL store the nonce, the address, the exact message text and its expiry. For an unlisted address, it SHALL return a message of the same shape and store nothing, so the response does not reveal whether an address is an operator.

#### Scenario: Listed address
- **WHEN** a listed operator address requests a challenge
- **THEN** the response is 200 with a message carrying the configured domain and uri, and the nonce is usable once before it expires

#### Scenario: Unlisted address
- **WHEN** an address not in `OPERATOR_ADDRESSES` requests a challenge
- **THEN** the response is 200 with a message of the same shape, and no challenge is stored

### Requirement: Verify accepts only the issued message, signed by its operator
`POST /v1/operator/auth/verify` with `{ message, signature }` SHALL create a session only when all of these hold:
- the message parses as EIP-4361;
- the signature recovers, by ECDSA, to the message's address;
- that address is in the current `OPERATOR_ADDRESSES`;
- an unused, unexpired challenge exists for that nonce and address, and its stored text equals `message` exactly.

Consuming the challenge SHALL be atomic, so a nonce yields at most one session. On success the response SHALL be `200 { token, expiresAt, operator: { id, address } }`.
- The token is 32 random bytes, base64url, prefixed `gos_`.
- Only a hash of the token is stored.
- The session lasts `OPERATOR_SESSION_TTL_SECONDS` from issue, with no renewal.

Verify SHALL need no chain RPC.

#### Scenario: Valid sign-in
- **WHEN** a listed operator signs the message the service issued and submits it before it expires
- **THEN** the response is 200 with a `gos_` token, its expiry and the operator's id and address

#### Scenario: Altered message
- **WHEN** the issued message is changed in any field (domain, uri, version, chainId, issuedAt, expirationTime or statement) and re-signed by the same operator key
- **THEN** the response is 401 and no session is created

#### Scenario: Replay
- **WHEN** a message and signature that already produced a session are submitted again
- **THEN** the response is 401

#### Scenario: Concurrent verify of one nonce
- **WHEN** two verify requests for the same issued message arrive at once
- **THEN** exactly one returns a session and the other returns 401

#### Scenario: Works with every chain down
- **WHEN** no configured chain is reachable and a listed operator verifies a valid message
- **THEN** the session is issued

### Requirement: Authentication failures are indistinguishable
Every operator authentication failure SHALL return `401` with the same body, whatever the cause. That covers:
- a bad signature, an unlisted address, a reused, expired, altered or never-issued challenge;
- a missing, unknown, expired or revoked session token;
- a tenant admin key presented as a session token.

The specific cause SHALL be recorded only in logs and in a failure counter labelled by reason.

#### Scenario: Different causes, same response
- **WHEN** verify fails once for a wrong signer and once for an expired challenge
- **THEN** both responses are 401 with identical bodies, and the failure counter records two different reasons

### Requirement: Operator routes accept only operator sessions
Every `/v1/operator/*` route except challenge and verify SHALL require a bearer operator session. The session must be unrevoked and unexpired, and its address must still be in the current `OPERATOR_ADDRESSES`. The request SHALL be attributed to the operator id the current configuration gives that address. A tenant admin key SHALL never authorise an operator route, and an operator session SHALL never authorise a `/v1/admin/*` route.

#### Scenario: Tenant admin key on an operator route
- **WHEN** a valid tenant admin key is presented to `GET /v1/operator/tenants`
- **THEN** the response is 401

#### Scenario: Operator session on a tenant admin route
- **WHEN** a valid operator session token is presented to a `/v1/admin/*` route
- **THEN** the response is 401

#### Scenario: Operator removed from configuration
- **WHEN** an operator's address is removed from `OPERATOR_ADDRESSES`, the service restarts, and a session issued before the restart is presented
- **THEN** the response is 401

#### Scenario: Expired session
- **WHEN** a session is presented after `expiresAt`
- **THEN** the response is 401

### Requirement: Operator routes refuse browser cross-origin requests
Every `/v1/operator/*` route, challenge and verify included, SHALL respond `403 operator-origin-refused` to any request that carries an `Origin` header. This holds before any authentication and whatever the CORS configuration allows.

#### Scenario: Valid session with an Origin
- **WHEN** a valid operator session calls `GET /v1/operator/tenants` with `Origin: https://evil.example`
- **THEN** the response is 403 `operator-origin-refused`

#### Scenario: Challenge from a page
- **WHEN** a challenge request carries an `Origin` that is a registered tenant origin
- **THEN** the response is 403 `operator-origin-refused`

### Requirement: Logout ends the session
`POST /v1/operator/auth/logout` with a valid operator session SHALL revoke that session and return `204`. The revoked token SHALL then fail every operator route with `401`.

#### Scenario: Logout
- **WHEN** an operator logs out and then calls `GET /v1/operator/tenants` with the same token
- **THEN** the logout returns 204 and the later call returns 401

### Requirement: Operator calls are rate limited per operator
Authenticated operator routes SHALL be limited to `OPERATOR_RATE_LIMIT_PER_MINUTE` requests per session. Challenge SHALL be limited per requested address and verify per address in the message, each with a deployment-wide ceiling. Limits SHALL NOT be keyed on the client IP.

#### Scenario: Session over its limit
- **WHEN** one operator session exceeds `OPERATOR_RATE_LIMIT_PER_MINUTE` requests within a minute
- **THEN** further requests in that minute return 429, and another operator's session is unaffected
