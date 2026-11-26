## Purpose

Defines wallet-api's wallet sessions: the bearer tokens a wallet receives after a passkey ceremony. Covers how long a session stays valid, how many a user may hold, and who can end them, so that a stolen token stops working on a bounded and controllable schedule.

## ADDED Requirements

### Requirement: Sessions are opaque bearer tokens bound at issue
A successful passkey registration or authentication SHALL issue a session as an opaque random token of at least 256 bits. wallet-api SHALL store only a hash of the token, never the token itself. A session SHALL be bound at issue time to the user, the credential that authenticated and that credential's wallet, and SHALL keep those bindings for its whole life. Issuing a session for a credential whose owner key was removed SHALL be refused.

#### Scenario: Token is not stored
- **WHEN** a user completes a passkey authentication and receives a session token
- **THEN** no row in the database contains that token in plain text

#### Scenario: Removed credential
- **WHEN** a credential has been removed as an owner of its wallet and then completes an authentication ceremony
- **THEN** no session is issued

### Requirement: Sessions expire at an absolute limit and when idle
A session SHALL stop resolving at the earliest of:
- its absolute expiry, `SESSION_TTL_SECONDS` after issue (default 86400);
- `SESSION_IDLE_TIMEOUT_SECONDS` after it was last used (default 3600);
- its revocation.

A session is used when wallet-api accepts it on an authenticated request. wallet-api SHALL record the last use with a resolution of at most 60 seconds, so a session used within the last 60 seconds MAY show an older last use. The idle timeout SHALL be at least 300 seconds and SHALL NOT exceed `SESSION_TTL_SECONDS`, and wallet-api SHALL refuse to start otherwise. Using a session SHALL NOT extend its absolute expiry.

A request with an expired, idle, revoked or unknown session SHALL be answered `401` with the same body in every case, `{"error":"unauthorized","message":"invalid or expired session"}`, so the response does not reveal which applied.

#### Scenario: Used within the idle window
- **WHEN** a session is used, and used again 50 minutes later with a 60-minute idle timeout
- **THEN** the second request is accepted

#### Scenario: Idle too long
- **WHEN** a session is not used for longer than the idle timeout and is then presented
- **THEN** the response is 401 `invalid or expired session`, and the session never resolves again

#### Scenario: A refused request is not a use
- **WHEN** a session is presented on another tenant's origin, or while its tenant is suspended, and the request is refused
- **THEN** its last use is not updated, so the refusal does not keep it from going idle

#### Scenario: Activity does not extend the absolute expiry
- **WHEN** a session is used every 10 minutes until 24 hours after issue, with `SESSION_TTL_SECONDS` 86400
- **THEN** the first request after 24 hours is refused with 401

#### Scenario: Invalid configuration
- **WHEN** wallet-api starts with `SESSION_IDLE_TIMEOUT_SECONDS` greater than `SESSION_TTL_SECONDS`, or below 300
- **THEN** it refuses to start and names the variable

### Requirement: Live sessions per user are capped
A live session is one that is neither revoked nor past its absolute or idle expiry. A user SHALL hold at most `SESSION_MAX_PER_USER` live sessions (default 10, minimum 1). When issuing a session would exceed the cap, wallet-api SHALL revoke the user's live sessions that were last used longest ago until the new session fits, in the same transaction as the issue. Two concurrent sign-ins by the same user SHALL NOT leave the user above the cap.

#### Scenario: Eleventh sign-in
- **WHEN** a user holding 10 live sessions signs in again, with the cap at 10
- **THEN** the new session works, the session that was used longest ago returns 401, and the other nine still work

#### Scenario: Dead sessions do not count
- **WHEN** a user holding 10 sessions, three of them revoked or expired, signs in
- **THEN** no live session is revoked

### Requirement: A user can sign out of one session or every session
`POST /v1/sessions/logout` SHALL revoke the calling session. `POST /v1/sessions/logout-all` SHALL revoke every live session of the calling session's user, across every credential and wallet of that user, the calling session included. Both SHALL need a valid session. `logout` SHALL keep its current response, `200 {"ok": true}`. `logout-all` SHALL answer `200 {"ok": true, "revoked": <number of sessions revoked>}`. Neither SHALL affect another user's sessions, including those of another user acting for the same wallet.

#### Scenario: Sign out everywhere
- **WHEN** a user holds sessions on a laptop and on a phone and calls `logout-all` from the laptop
- **THEN** the response is 200 with `revoked: 2`, and both sessions return 401 on their next request

#### Scenario: Other users unaffected
- **WHEN** a user calls `logout-all`
- **THEN** a session of a different user of the same tenant still works

### Requirement: A tenant admin key can revoke its users' sessions
`POST /v1/admin/sessions/revoke` SHALL need a valid tenant admin key. Its body SHALL name exactly one of:
- `externalUserId`: revokes every live session of that user of the key's tenant;
- `walletAddress`: revokes every live session of the key's tenant that acts for that wallet, whichever user and credential opened it. The address is compared case-insensitively.

It SHALL answer `200` with `{"revoked": <number of sessions revoked>}`, which is `0` when the user or wallet has no live session or does not exist in the tenant. It SHALL never revoke a session of another tenant. A body that names both or neither SHALL be refused with `400`. Repeating a revocation SHALL succeed and change nothing.

#### Scenario: Stolen phone reported to the tenant
- **WHEN** a tenant admin revokes by the user's `externalUserId`
- **THEN** the response is 200 with the number of sessions revoked, and each of those sessions returns 401

#### Scenario: By wallet
- **WHEN** a tenant admin revokes by `walletAddress` in mixed case
- **THEN** every live session acting for that wallet in the tenant is revoked

#### Scenario: Another tenant's user
- **WHEN** tenant A's admin key names an `externalUserId` that exists only in tenant B
- **THEN** the response is 200 with `revoked: 0`, and tenant B's sessions still work

#### Scenario: Repeated
- **WHEN** the same revocation is sent twice
- **THEN** the second response is 200 with `revoked: 0`

### Requirement: A platform admin can revoke a tenant's user's sessions
`POST /v1/platform/tenants/:slug/sessions/revoke` SHALL exist exactly where the other platform admin routes are registered, and SHALL apply their checks (an `Origin` header is refused with 403, a missing or invalid platform admin session with 401). It SHALL accept the same body and give the same response as the tenant admin route, scoped to the tenant named by `:slug`. An unknown slug SHALL be answered as on the other `/v1/platform/tenants/:slug` routes. It SHALL work for a suspended tenant. A deleted tenant has no sessions left, so it SHALL be refused with `409 invalid-transition` and nothing SHALL be recorded.

#### Scenario: Revoke for a suspended tenant
- **WHEN** a platform admin revokes by `externalUserId` on a suspended tenant
- **THEN** the response is 200 and the user's sessions are revoked

#### Scenario: Deleted tenant
- **WHEN** a platform admin revokes on a deleted tenant
- **THEN** the response is 409 `invalid-transition`

#### Scenario: Tenant admin key on the platform route
- **WHEN** a tenant admin key is presented as the bearer token
- **THEN** the response is 401

### Requirement: Cross-origin requests carry no credentials
wallet-api's CORS responses SHALL NOT include `Access-Control-Allow-Credentials`. Authentication SHALL rely only on the `Authorization` header, which a browser never attaches on its own. The allowed origins SHALL stay as they are: a tenant's wallet origin and its `cors_origins`.

#### Scenario: Preflight from an allowed origin
- **WHEN** a tenant's wallet origin sends a CORS preflight for `POST /v1/sessions/logout-all` with `Access-Control-Request-Headers: authorization, content-type`
- **THEN** the response allows the origin and those headers, and has no `Access-Control-Allow-Credentials` header
