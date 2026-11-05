---
"@appliedblockchain/giano-wallet-core": minor
"@appliedblockchain/giano-wallet-kit": minor
---

A wallet-api session that wallet-api refuses now ends on the client (G5). Before, the client kept the dead token and threw a generic error.

wallet-core:

- A 401 to a request that carried the session clears the token, calls `onSessionChanged(null)` and throws the new `SessionEndedError` (`code` 4100). This applies to the wallet-api injection, the management API and the ERC-7677 paymaster client. A 401 from the paymaster service is no longer reported as a `not-your-wallet` refusal. A 403 still is.
- `WalletApiInjection` gains `logoutAll()` (sign out everywhere; resolves `false` when wallet-api could not confirm it), `onUnauthorized()` and `onSessionEnded(listener)`. `isSessionEndedError()` finds the error inside viem's wrapped errors.
- `createWalletManagementApi` and `createErc7677PaymasterClient` take an optional `onUnauthorized`.

wallet-kit:

- The bundler transport, the paymaster client and the management API all end the session through the injection. The paymaster client now reads the session from the injection instead of `localStorage`.
- A dApp request that fails because the session ended is answered with EIP-1193 4100 "Unauthorized", not 4001 or an internal error.
- The sponsorship pre-flight has a new `{ state: "session-ended" }`.
- The management controller gains `logoutAll()` and a `notice` on its state (`session-ended`, `signed-out-everywhere`, `signed-out-everywhere-unconfirmed`). A refused session moves it to `signed-out` with that notice, instead of an error.

A custom wallet built on the injection should treat `SessionEndedError` as "sign in again". wallet-api also no longer sends `Access-Control-Allow-Credentials`, so the client must not send credentialed requests. The bearer header is all it needs.
