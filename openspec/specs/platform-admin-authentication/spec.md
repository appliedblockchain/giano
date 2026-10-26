# platform-admin-authentication Specification

## Purpose

Defines who a Giano platform admin is and how they prove it to `wallet-api`. A platform admin signs an EIP-4361 message with a wallet whose address the deployment lists, and gets a short-lived platform admin session. That session is the only credential the platform routes accept, and it is never usable as a tenant credential or the other way round.

## Requirements

### Requirement: Challenge issues a server-written sign-in message
`POST /v1/platform/auth/challenge` with `{ address, chainId }` SHALL return `200 { message }`, where `message` is an EIP-4361 message with these fields:
- `domain` is `OPERATOR_SIWE_DOMAIN`;
- `uri` is `OPERATOR_SIWE_URI`;
- `address` is the requested address, checksummed;
- `version` is `1`;
- `chainId` is the requested chain;
- the statement names the session lifetime;
- the nonce is fresh;
- `issuedAt` is now and `expirationTime` is now plus `PLATFORM_CHALLENGE_TTL_SECONDS`.

For a listed address, the service SHALL store the nonce, the address, the exact message text and its expiry. For an unlisted address, it SHALL return a message of the same shape and store nothing, so the response does not reveal whether an address is a platform admin.

#### Scenario: Listed address
- **WHEN** a listed platform admin address requests a challenge
- **THEN** the response is 200 with a message carrying the configured domain and uri, and the nonce is usable once before it expires

#### Scenario: Unlisted address
- **WHEN** an address not in `OPERATOR_ADDRESSES` requests a challenge
- **THEN** the response is 200 with a message of the same shape, and no challenge is stored

### Requirement: Verify accepts only the issued message, signed by its platform admin
`POST /v1/platform/auth/verify` with `{ message, signature }` SHALL create a session only when all of these hold:
- the message parses as EIP-4361;
- the signature recovers, by ECDSA, to the message's address;
- that address is in the current `OPERATOR_ADDRESSES`;
- an unused, unexpired challenge exists for that nonce and address, and its stored text equals `message` exactly.

Consuming the challenge SHALL be atomic, so a nonce yields at most one session. On success the response SHALL be `200 { token, expiresAt, admin: { id, address } }`.
- The token is 32 random bytes, base64url, prefixed `gps_`.
- Only a hash of the token is stored.
- The session lasts `PLATFORM_SESSION_TTL_SECONDS` from issue, with no renewal.

Verify SHALL need no chain RPC.

#### Scenario: Valid sign-in
- **WHEN** a listed platform admin signs the message the service issued and submits it before it expires
- **THEN** the response is 200 with a `gps_` token, its expiry and the platform admin's id and address

#### Scenario: Altered message
- **WHEN** the issued message is changed in any field (domain, uri, version, chainId, issuedAt, expirationTime or statement) and re-signed by the same platform admin key
- **THEN** the response is 401 and no session is created

#### Scenario: Replay
- **WHEN** a message and signature that already produced a session are submitted again
- **THEN** the response is 401

#### Scenario: Concurrent verify of one nonce
- **WHEN** two verify requests for the same issued message arrive at once
- **THEN** exactly one returns a session and the other returns 401

#### Scenario: Works with every chain down
- **WHEN** no configured chain is reachable and a listed platform admin verifies a valid message
- **THEN** the session is issued

### Requirement: Authentication failures are indistinguishable
Every platform admin authentication failure SHALL return `401` with the same body, whatever the cause. That covers:
- a bad signature, an unlisted address, a reused, expired, altered or never-issued challenge;
- a missing, unknown, expired or revoked session token;
- a tenant admin key presented as a session token.

The specific cause SHALL be recorded only in logs and in a failure counter labelled by reason.

#### Scenario: Different causes, same response
- **WHEN** verify fails once for a wrong signer and once for an expired challenge
- **THEN** both responses are 401 with identical bodies, and the failure counter records two different reasons

### Requirement: Platform admin routes accept only platform admin sessions
Every `/v1/platform/*` route except challenge and verify SHALL require a bearer platform admin session. The session must be unrevoked and unexpired, and its address must still belong to a row in the `platform_admins` table. The request SHALL be attributed to the platform admin id that table currently gives that address. A tenant admin key SHALL never authorise a platform route, and a platform admin session SHALL never authorise a `/v1/admin/*` route.

#### Scenario: Tenant admin key on a platform route
- **WHEN** a valid tenant admin key is presented to `GET /v1/platform/tenants`
- **THEN** the response is 401

#### Scenario: Platform admin session on a tenant admin route
- **WHEN** a valid platform admin session token is presented to a `/v1/admin/*` route
- **THEN** the response is 401

#### Scenario: Platform admin removed
- **WHEN** a platform admin is removed and a session issued to them before the removal is presented
- **THEN** the response is 401, with no restart needed

#### Scenario: Expired session
- **WHEN** a session is presented after `expiresAt`
- **THEN** the response is 401

### Requirement: Platform admin routes refuse browser cross-origin requests
Every `/v1/platform/*` route, challenge and verify included, SHALL respond `403 platform-origin-refused` to any request that carries an `Origin` header. This holds before any authentication and whatever the CORS configuration allows.

#### Scenario: Valid session with an Origin
- **WHEN** a valid platform admin session calls `GET /v1/platform/tenants` with `Origin: https://evil.example`
- **THEN** the response is 403 `platform-origin-refused`

#### Scenario: Challenge from a page
- **WHEN** a challenge request carries an `Origin` that is a registered tenant origin
- **THEN** the response is 403 `platform-origin-refused`

### Requirement: Logout ends the session
`POST /v1/platform/auth/logout` with a valid platform admin session SHALL revoke that session and return `204`. The revoked token SHALL then fail every platform route with `401`.

#### Scenario: Logout
- **WHEN** a platform admin logs out and then calls `GET /v1/platform/tenants` with the same token
- **THEN** the logout returns 204 and the later call returns 401

### Requirement: Platform admin calls are rate limited per platform admin
Authenticated platform routes SHALL be limited to `PLATFORM_RATE_LIMIT_PER_MINUTE` requests per session. Challenge SHALL be limited per requested address and verify per address in the message, each with a deployment-wide ceiling. Limits SHALL NOT be keyed on the client IP.

#### Scenario: Session over its limit
- **WHEN** one platform admin session exceeds `PLATFORM_RATE_LIMIT_PER_MINUTE` requests within a minute
- **THEN** further requests in that minute return 429, and another platform admin's session is unaffected
