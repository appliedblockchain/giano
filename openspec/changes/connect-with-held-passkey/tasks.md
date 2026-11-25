# Tasks

## 1. wallet-api

- [x] 1.1 `discoverable` on `POST /v1/webauthn/options`: an unbound sign-in challenge, no credential ids; refused for registration. Tests: a device whose stored user is another signs in to the passkey's own wallet; a bound challenge still refuses it; registration refused.
- [x] 1.2 The claim response returns the wallet being joined; OpenAPI regenerated.

## 2. SDK

- [x] 2.1 wallet-core injection: `setConnectChoice`; `existing` (discoverable), `new` (fresh external user id when needed), session first with a discoverable challenge; discoverable wallet-origin sign-in. Tests for each.
- [x] 2.2 `depositPasskeyIntoPendingAddition` names the passkey from the joined wallet and returns it.
- [x] 2.3 wallet-kit: the held-passkey flag, the connect offer on the consent request, the host setting and clearing the choice, passkey names. Tests for each.
- [x] 2.4 Changeset (wallet-core and wallet-kit minor).

## 3. Wallets and e2e

- [x] 3.1 Stock wallet connect screen with the second choice; claim screen shows the joined wallet; BYO reference parity.
- [x] 3.2 e2e: straight to the dApp after joining connects to the joined wallet; a device that last used another wallet connects with the passkey it now holds; a returning user on a fresh browser; a signed-out device creates a new wallet; passkey names.
