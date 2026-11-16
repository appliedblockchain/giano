# @appliedblockchain/giano-wallet-transport

## 7.0.1

## 7.0.0

### Minor Changes

- ce6e605: Require a connection before a dApp can read or use the wallet account. Before, any origin in `allowedDappOrigins` could open the popup and call `giano_restoreAccount`, `eth_accounts` or `eth_prepareUserOperation` with no consent screen. It got the user's address, and `eth_prepareUserOperation` made the paymaster issue a signed authorisation and reserve tenant balance until the reservation expired.

  The `giano-wallet-kit` host now keeps a connection grant for each dApp origin in the wallet origin's `localStorage`, under its own key, so two popups cannot overwrite each other's change. It records the grant when the user approves `eth_requestAccounts` and the provider returns an account. If the storage refuses that write, the connect answers `-32603` and grants nothing. `wallet_revokePermissions` from that origin removes the grant, and answers `-32603` if the storage refuses the write. The host checks the grant again after the silent restore and after consent, so a revoke from another popup also stops a request that is already waiting. An origin with no grant gets `[]` from `eth_accounts` and EIP-1193 `4100`, with `data: { reason: "not-connected" }`, from every method that uses the account: `eth_sendTransaction`, `personal_sign`, `eth_sign`, `eth_signTypedData_v4`, `eth_signUserOperation`, `signed_eth_call`, `eth_prepareUserOperation` and `eth_sendSignedUserOperation`. The host checks the grant before it restores the account, so a refused origin never receives an `accountsChanged` event. The host also relays `accountsChanged` only to an origin that holds a grant, so signing in from the management view no longer sends the address to an origin that never connected. The event that a first connect emits is no longer relayed; the dApp reads the accounts from the `eth_requestAccounts` result. The host refuses `giano_restoreAccount` from an application with `4200`.

  A dApp that already connected before this release has no grant yet. Its next account request gets `4100`, and it must call `eth_requestAccounts` again once. The `giano-connector` provider now treats that marked `4100` like `4900`: it drops its cached session and emits `accountsChanged` with `[]` and `disconnect`, so the dApp shows the user as disconnected instead of connected with every action failing. Any other `4100`, such as a refused self-call or an ended wallet session, refuses only that request and leaves the dApp connected. `giano-wallet-transport` exports the marker as `NOT_CONNECTED_REASON` and the check as `isNotConnectedError`.

## 6.0.1

## 6.0.0

### Major Changes

- 4c85f2e: Move to zod 4 (4.6.7). The exported zod schemas (`transportMessageSchema` and the message schemas in `giano-wallet-transport`; `chainDescriptorSchema`, `walletApiChainSchema`, `bundlerChainSchema` and the other chain schemas in `giano-contracts`) are now zod 4 types. A consumer that composes them with its own schemas, or names their types, must use zod 4. The parsed values do not change: `bundlerChainSchema` still fills the `bundler` section's defaults when the section is absent. This release fixes GHSA-mrhx-c7xc-m3w5 (high: zod below 4.6.6 can exhaust memory while validating oversized constrained collections), which no zod 3 release fixes. Consumers get the fix by installing this version.

## 5.0.0

### Patch Changes

- 00f0c39: Runtime dependencies are now pinned to exact versions (ABIP-7): `zod@3.24.4` in contracts,
  `@noble/hashes@1.8.0` in tx-describe, `ox@0.7.1` and `uuid@11.1.1` in wallet-core, and `ulid@3.0.2`
  in wallet-transport. These are the versions every release already shipped and tested with. A project
  that wants a different version can choose it with its own package manager's overrides. Peer
  dependencies (`viem`, `react`, `wagmi`, `@rainbow-me/rainbowkit`) keep their semver ranges, so
  integrators still choose those versions themselves.

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

## 3.1.1

## 3.1.0

## 3.0.0

### Minor Changes

- 42753c8: New popup transport package: versioned `{giano, id, type, payload}` envelope
  (handshake/ack with version+capability negotiation, rpc/rpc:response with EIP-1193 error
  codes, event, ready, close), zod validation in both directions, strict
  targetOrigin/event.origin/event.source discipline with first-validated-origin pinning on
  the wallet side, and a Safari-safe PopupManager (synchronous about:blank open, then
  navigate) with a typed POPUP_BLOCKED error and documented COOP caveat.
