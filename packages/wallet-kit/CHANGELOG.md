# @appliedblockchain/giano-wallet-kit

## 7.0.0

### Minor Changes

- 1bc3447: Fix `personal_sign` and `eth_sign` so the signature covers the message the dApp sent. A 0x-prefixed hex message with whole bytes is now signed as its raw bytes, and any other message (including odd-length hex) as UTF-8 text. Before, the provider passed the hex spelling to `signMessage` as text, so signatures failed standard EIP-191 / ERC-1271 verification. Every Giano `personal_sign` and `eth_sign` signature changes with this release; a verifier written for the old output must switch to standard verification.

  New export `toPersonalMessageBytes` (from `giano-wallet-core`, re-exported by `giano-wallet-kit`) returns the exact bytes these methods sign, so a consent screen can show the same payload.

  New `giano-wallet-kit` export `describePersonalMessage` returns what a consent screen should show for these methods. It returns the signed bytes as text only when they are valid UTF-8 with no hidden character (control, bidi, zero-width or other default-ignorable characters, or a leading BOM). Otherwise it returns hex, with `rawHex: true` so the screen can warn the user.

- 0d5331e: The wallet host now refuses any dApp request that would make the user's account call one of its own functions. Such a self-call can add or remove owners or upgrade the account, so only the wallet's own management view may build one. The check covers `eth_sendTransaction`, `eth_prepareUserOperation`, `eth_signUserOperation` and `eth_sendSignedUserOperation`, including calls inside `execute` and `executeBatch` callData. A value-only transfer to the account (no calldata) is still allowed, and so is a deploy-only user operation (callData `0x`). A dApp that wants the user to manage the wallet calls `giano_openWalletManagement`.

  The host also refuses, with error code 4100, a request it cannot check: `params` that is not an array, a transaction, call or user operation that is missing, null or not an object, a `to` or `data` that is not a string, or a user operation whose callData is not an `execute` or `executeBatch` call.

  The host runs the check before consent and again after consent, just before the provider runs the request. If no account exists at either point, the host refuses the request with error code 4900, the same code the provider gives. For `eth_signUserOperation`, the host refuses with 4100 a `sender` that is not the connected account, and fills in a missing one. The provider then refuses the request if its account changes before it signs.

  New export `checkSelfCall` returns whether a request is a self-call or cannot be checked, so a consent screen can block it as a second layer.

- ce6e605: Require a connection before a dApp can read or use the wallet account. Before, any origin in `allowedDappOrigins` could open the popup and call `giano_restoreAccount`, `eth_accounts` or `eth_prepareUserOperation` with no consent screen. It got the user's address, and `eth_prepareUserOperation` made the paymaster issue a signed authorisation and reserve tenant balance until the reservation expired.

  The `giano-wallet-kit` host now keeps a connection grant for each dApp origin in the wallet origin's `localStorage`, under its own key, so two popups cannot overwrite each other's change. It records the grant when the user approves `eth_requestAccounts` and the provider returns an account. If the storage refuses that write, the connect answers `-32603` and grants nothing. `wallet_revokePermissions` from that origin removes the grant, and answers `-32603` if the storage refuses the write. The host checks the grant again after the silent restore and after consent, so a revoke from another popup also stops a request that is already waiting. An origin with no grant gets `[]` from `eth_accounts` and EIP-1193 `4100`, with `data: { reason: "not-connected" }`, from every method that uses the account: `eth_sendTransaction`, `personal_sign`, `eth_sign`, `eth_signTypedData_v4`, `eth_signUserOperation`, `signed_eth_call`, `eth_prepareUserOperation` and `eth_sendSignedUserOperation`. The host checks the grant before it restores the account, so a refused origin never receives an `accountsChanged` event. The host also relays `accountsChanged` only to an origin that holds a grant, so signing in from the management view no longer sends the address to an origin that never connected. The event that a first connect emits is no longer relayed; the dApp reads the accounts from the `eth_requestAccounts` result. The host refuses `giano_restoreAccount` from an application with `4200`.

  A dApp that already connected before this release has no grant yet. Its next account request gets `4100`, and it must call `eth_requestAccounts` again once. The `giano-connector` provider now treats that marked `4100` like `4900`: it drops its cached session and emits `accountsChanged` with `[]` and `disconnect`, so the dApp shows the user as disconnected instead of connected with every action failing. Any other `4100`, such as a refused self-call or an ended wallet session, refuses only that request and leaves the dApp connected. `giano-wallet-transport` exports the marker as `NOT_CONNECTED_REASON` and the check as `isNotConnectedError`.

- 0ef6cf7: A wallet-api session that wallet-api refuses now ends on the client (G5). Before, the client kept the dead token and threw a generic error.

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

### Patch Changes

- Updated dependencies [fd2ef19]
- Updated dependencies [802f12f]
- Updated dependencies [2ab5e9b]
- Updated dependencies [7938cef]
- Updated dependencies [43a6ddc]
- Updated dependencies [af3fd88]
- Updated dependencies [8f28872]
- Updated dependencies [a8ceffb]
- Updated dependencies [1bc3447]
- Updated dependencies [68eadca]
- Updated dependencies [0d5331e]
- Updated dependencies [75a6c17]
- Updated dependencies [08bd62d]
- Updated dependencies [c59d890]
- Updated dependencies [4f5edcf]
- Updated dependencies [ce6e605]
- Updated dependencies [0ef6cf7]
  - @appliedblockchain/giano-contracts@7.0.0
  - @appliedblockchain/giano-wallet-core@7.0.0
  - @appliedblockchain/giano-wallet-transport@7.0.0
  - @appliedblockchain/giano-tx-describe@7.0.0

## 6.0.1

### Patch Changes

- Updated dependencies [67e7522]
  - @appliedblockchain/giano-wallet-core@6.0.1
  - @appliedblockchain/giano-contracts@6.0.1
  - @appliedblockchain/giano-wallet-transport@6.0.1
  - @appliedblockchain/giano-tx-describe@6.0.1

## 6.0.0

### Minor Changes

- fc4164a: Add an optional wallet-owned passkeyDevicePreference setting to suggest mobile authentication through WebAuthn hybrid hints. Default browser choice, credential eligibility, user verification, and explicit enrollment behavior are preserved.

### Patch Changes

- Updated dependencies [fc4164a]
- Updated dependencies [4c85f2e]
- Updated dependencies [4c85f2e]
  - @appliedblockchain/giano-wallet-core@6.0.0
  - @appliedblockchain/giano-tx-describe@6.0.0
  - @appliedblockchain/giano-wallet-transport@6.0.0
  - @appliedblockchain/giano-contracts@6.0.0

## 5.0.0

### Patch Changes

- Updated dependencies [95a40c2]
- Updated dependencies [00f0c39]
- Updated dependencies [544ac79]
- Updated dependencies [b448e54]
- Updated dependencies [eb8a25f]
  - @appliedblockchain/giano-contracts@5.0.0
  - @appliedblockchain/giano-wallet-core@5.0.0
  - @appliedblockchain/giano-tx-describe@5.0.0
  - @appliedblockchain/giano-wallet-transport@5.0.0

## 4.0.0

### Patch Changes

- 01b008f: Source linted and formatted with Biome (its default configuration) instead of ESLint. No change to
  any export or its behaviour: event listeners are still called the same way, now from callbacks that
  return nothing.
- 762221a: Built with tsdown instead of tsup (which is no longer maintained). Declarations are generated from
  source by oxc (`isolatedDeclarations`) rather than by the TypeScript compiler, so exported functions
  and constants now carry explicit types. Same entry points, file names and runtime exports; every
  export's type is equivalent to before (checked by mutual assignability, and member by member for
  classes), and the declarations compile with TypeScript 5.0.4 through 7.0.

  - `giano-wallet-core`: `createGianoProvider(...).gianoClient` is typed as viem's `PublicClient`.
    The previous declaration printed an expansion of it that viem's `PublicClient` did not accept, so
    passing it to anything typed `PublicClient` failed to compile. It also exports the
    `ReplaySafeTypedData` type that `toReplaySafeTypedData` returns.
  - Bundles keep their JSDoc comments, and `giano-paymaster-sdk`'s library bundle no longer shares a
    chunk with its CLI.

- bb23680: Built and typechecked with TypeScript 7 only. No API changes. Consumers need TypeScript 5.0.4 or later, as before.

  - `giano-wallet-core`'s declarations no longer import viem internals by relative path
    (`../../types/misc.js` and three more), which failed to resolve in a consuming project with
    `skipLibCheck` off. The inferred `createGianoProvider` return type is printed in a different
    member order; the type is the same.
  - Classes with constructor parameter properties (the SDK error classes, `TransportRpcError` and
    friends) now declare those fields in the emitted JavaScript, as `tsc` does for an ES2022 target.
    Each field is assigned in the same constructor, so instances are unchanged.
  - Declaration bundles list type-only exports in a separate `export type { … }` clause.

- Updated dependencies [01b008f]
- Updated dependencies [bc75e86]
- Updated dependencies [762221a]
- Updated dependencies [bb23680]
  - @appliedblockchain/giano-contracts@4.0.0
  - @appliedblockchain/giano-wallet-core@4.0.0
  - @appliedblockchain/giano-wallet-transport@4.0.0
  - @appliedblockchain/giano-tx-describe@4.0.0

## 3.1.1

### Patch Changes

- Updated dependencies [cea82f2]
  - @appliedblockchain/giano-wallet-core@3.1.1
  - @appliedblockchain/giano-contracts@3.1.1
  - @appliedblockchain/giano-wallet-transport@3.1.1
  - @appliedblockchain/giano-tx-describe@3.1.1

## 3.1.0

### Patch Changes

- Updated dependencies [344a793]
  - @appliedblockchain/giano-contracts@3.1.0
  - @appliedblockchain/giano-wallet-core@3.1.0
  - @appliedblockchain/giano-wallet-transport@3.1.0
  - @appliedblockchain/giano-tx-describe@3.1.0

## 3.0.0

### Major Changes

- 6552edc: A wallet origin no longer needs a route to a node or a bundler: a chain entry needs only its
  `chainId`. `rpcUrl` defaults to wallet-api's read relay, `${walletApiUrl}/v1/rpc/${chainId}`
  (tenant-bound, read-only allowlist), and `bundlerUrl` to wallet-api's bundler relay,
  `${walletApiUrl}/v1/bundler/${chainId}` — the ERC-4337 surface viem's bundler client speaks, behind
  the session, with `eth_sendUserOperation` going through the same policy, audit and idempotency
  pipeline as `POST /v1/userops`. Explicit `rpcUrl` / `bundlerUrl` still dial a node or bundler directly.

  **Breaking:** `bundlerOptions` takes the session-token getter as a required fifth argument, and the
  new `sessionHttp` transport attaches the wallet-api session bearer to every bundler call. Both
  relays require wallet-api at or above the version that ships them.

### Minor Changes

- fcd51ea: Human-readable transaction descriptions on the consent screen.

  - New package `@appliedblockchain/giano-tx-describe`: turns a transaction request plus a set of
    ERC-7730 clear-signing mappings into an intent sentence and labelled fields, or an explicit
    `unknown` result carrying the raw data. Ships generic ERC-20 / ERC-721 mappings (flagged as
    generic), describes native transfers without a mapping, validates descriptors with per-path
    issues, and depends on nothing else in Giano.
  - `wallet-kit`: every `WalletRuntime` gains `describeTransaction(tx)`, which fetches and caches the
    tenant's mappings from wallet-api (`GET /v1/tx-mappings`), resolves ERC-20 symbol and decimals
    from the chain, and never rejects. `WalletChainConfig` gains an optional `nativeCurrency`
    (default ETH, 18 decimals) so amounts are named in the chain's own currency.
  - `contracts`: the shared chain descriptor schema gains the optional `nativeCurrency` field.

- 42753c8: New package: the wallet SDK ("the kit") — the framework-agnostic orchestration a Giano wallet
  origin is built from (WALLET-SDK-REQUIREMENTS.md). One package now holds what wallet-web and the
  BYO reference each re-implemented by hand: config validation, the per-chain runtimes (fee-before-
  paymaster, sponsorship pre-flight, one shared wallet-api injection), the transport host with its
  single-slot consent gate, and the headless wallet-management controller (chain-before-registry,
  per-chain index re-reads, fingerprint recompute, the last-owner guard). A React adapter ships
  behind `@appliedblockchain/giano-wallet-kit/react`; the core is framework-free. Both Giano wallet
  UIs now build on it (WK-30, WK-31).

### Patch Changes

- b6a635f: Pin Giano siblings exactly in published tarballs. Inter-package dependencies move from `workspace:^`
  to `workspace:*`, which pnpm rewrites at pack time to the sibling's exact version rather than a
  caret range — so installing one of the six installs that release, not a resolution across two.
- 5b8b279: Verify paymaster sponsorship signatures using ECDSA recovery without inspecting or calling the signer during ERC-4337 validation. ERC-1271 sponsorship signers are no longer supported; existing contract signers must be replaced with ECDSA keys.

  Fix the raw prepare/sign/send user-operation flow across wallet popups, require consent for raw signing and authenticated reads, and preserve RainbowKit wallet metadata.

- Updated dependencies [ca66fdc]
- Updated dependencies [b6a635f]
- Updated dependencies
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [5b8b279]
- Updated dependencies [62a5d2c]
- Updated dependencies [fcd51ea]
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
  - @appliedblockchain/giano-wallet-core@3.0.0
  - @appliedblockchain/giano-contracts@3.0.0
  - @appliedblockchain/giano-tx-describe@3.0.0
  - @appliedblockchain/giano-wallet-transport@3.0.0
