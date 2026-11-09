## Purpose

Defines how the Giano wallet client (wallet-core's wallet-api injection, wallet-kit and wallet-web) keeps the wallet-api session, reacts when wallet-api ends it, and lets a user sign out of one device or every device.

## ADDED Requirements

### Requirement: The session is a bearer token kept on the wallet origin
The wallet client SHALL send the session only as an `Authorization: Bearer` header to the configured wallet-api URL. It SHALL NOT send credentialed cross-origin requests. The stock wallet SHALL persist the token in the wallet origin's `localStorage`, so it survives a reload. It SHALL remove the token from storage whenever the session ends: on sign-out, on sign-out everywhere, and when wallet-api refuses it.

#### Scenario: Reload keeps the session
- **WHEN** a signed-in user reloads the wallet within the session's idle window
- **THEN** the wallet restores the account without a passkey prompt

#### Scenario: No credentialed requests
- **WHEN** the wallet calls wallet-api from a different origin
- **THEN** the request carries the bearer header and is not sent with `credentials: "include"`

### Requirement: A refused session ends the session in the client
The client SHALL send the session token to wallet-api and nowhere else. When wallet-api answers `401` to any request that carried the session still in use, the client SHALL end the session. That covers wallet-api calls, the management API, wallet-api's paymaster endpoint and its bundler and RPC relay. Ending the session SHALL:
- clear the token from memory and from storage;
- notify the host (wallet-kit) that the session changed to none;
- reject the pending call with a typed session-ended error, not a generic error.

A `401` from a service that is not wallet-api's, a `401` to a request that carried no session or a token a new sign-in has since replaced, and any other status, SHALL NOT end the session.

#### Scenario: Idle session during sponsorship
- **WHEN** a session has gone idle and the wallet asks the paymaster service to sponsor an operation
- **THEN** the call rejects with the session-ended error, the stored token is gone, and the next request needing a session asks the user to sign in

#### Scenario: Other errors keep the session
- **WHEN** wallet-api answers 429 or 503 to a call that carried the session
- **THEN** the session token is kept

#### Scenario: Another service's 401
- **WHEN** a wallet is configured with a bundler or sponsorship service that is not wallet-api's, and that service answers 401
- **THEN** the request did not carry the session token, the session is kept, and a dApp waiting on the request gets an ordinary error, not 4100

#### Scenario: A sign-in during the refused request
- **WHEN** wallet-api refuses a request sent with the old token after the user has signed in again
- **THEN** the new session is kept

### Requirement: The wallet returns to sign-in when the session ends
When the session ends in the middle of a wallet-web flow, wallet-web SHALL show its sign-in state with a message that the session ended, instead of an error. A signing request from a dApp SHALL fail with an error the dApp can tell apart from a user rejection, and SHALL NOT be retried without the user.

#### Scenario: Manage view after revocation
- **WHEN** a tenant admin revokes a user's sessions while the user has the Manage view open, and the user then renames a passkey
- **THEN** wallet-web shows the sign-in state with a "session ended" message, and the rename is not applied

### Requirement: Users can sign out everywhere
The wallet-api injection SHALL offer sign-out everywhere next to sign-out. It SHALL call wallet-api's sign-out-everywhere endpoint, then end the session locally even if that call fails. wallet-web's Manage view SHALL offer "Sign out everywhere" next to the existing sign-out, and SHALL explain that it signs out every device holding a session for this user.

#### Scenario: Sign out everywhere from Manage
- **WHEN** a signed-in user picks "Sign out everywhere" in the Manage view
- **THEN** wallet-api revokes all of the user's sessions, the wallet shows the signed-out state, and a session on another device returns 401 on its next request

#### Scenario: Offline
- **WHEN** the sign-out-everywhere call fails because wallet-api cannot be reached
- **THEN** the local session is still cleared, and the user is told the other devices may still be signed in

#### Scenario: Session already ended
- **WHEN** the user picks "Sign out everywhere" with a session wallet-api has already ended
- **THEN** the wallet shows the signed-out state with the "session ended" message, not the offline one
