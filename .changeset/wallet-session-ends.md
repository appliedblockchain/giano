---
"@appliedblockchain/giano-wallet-core": minor
"@appliedblockchain/giano-wallet-kit": minor
---

A wallet-api session that wallet-api refuses now ends on the client (G5). Before, the client kept the dead token and threw a generic error.

wallet-core:

- A 401 from wallet-api to a request that carried the current session clears the token, calls `onSessionChanged(null)` and throws the new `SessionEndedError` (`code` 4100). This applies to the wallet-api injection, the management API and the ERC-7677 paymaster client. A 401 for a token a new sign-in replaced while the request was in flight ends nothing, and says to try again: the management API throws `session-replaced`, and the paymaster client a retryable `temporarily-unavailable` refusal. A 401 from wallet-api's paymaster endpoint is no longer reported as a `not-your-wallet` refusal. A 403 still is.
- `WalletApiInjection` gains `logoutAll()` (sign out everywhere; resolves `false` when wallet-api could not confirm it), `onUnauthorized(token?)`, `onSessionEnded(listener)`, `isWalletApiUrl(url)` and `sessionFetch`, a fetch that attaches the session to wallet-api URLs only and ends it on wallet-api's 401. `isSessionEndedError()` finds the error inside viem's wrapped errors.
- `createWalletManagementApi` and `createErc7677PaymasterClient` take an optional `onUnauthorized(token)`. The paymaster client also takes `sessionEndpoint` (default `true`): set it to `false` for a sponsorship service that is not wallet-api's, which then gets no token, and whose 401 stays a `not-your-wallet` refusal.
- Fix: `logout()` now actually revokes the session on wallet-api. Its bodyless request used to declare a JSON content type, which wallet-api refused with 400, so only the local token was cleared. The injection now sends that header only when a request has a body.

wallet-kit:

- The bundler transport, the paymaster client and the management API all end the session through the injection. The paymaster client now reads the session from the injection instead of `localStorage`. The token goes only to wallet-api: a bundler or sponsorship service configured elsewhere no longer receives it, and its own 401 no longer signs the user out. `sessionHttp(url, sessionFetch)` and the last parameter of `bundlerOptions` now take the injection's `sessionFetch`.
- A dApp request that fails because wallet-api ended the session is answered with EIP-1193 4100 "Unauthorized", not 4001 or an internal error. `toRpcError(error, isWalletApiUrl)` reads an HTTP 401 as that only when it came from wallet-api.
- `SessionEndedError` and `isSessionEndedError` are re-exported.
- The sponsorship pre-flight has a new `{ state: "session-ended" }`, and a `PendingRequest` gains `sessionEnded()`, which answers the dApp 4100. A review screen calls it to close a request whose session ended.
- The management controller gains `logoutAll()` and a `notice` on its state (`session-ended`, `signed-out-everywhere`, `signed-out-everywhere-unconfirmed`). A refused session moves it to `signed-out` with that notice, instead of an error, and sign out everywhere with an already-refused session keeps `session-ended`.

A custom wallet built on the injection should treat `SessionEndedError` as "sign in again". wallet-api also no longer sends `Access-Control-Allow-Credentials`, so the client must not send credentialed requests. The bearer header is all it needs.
