# @appliedblockchain/giano-wallet-transport

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
