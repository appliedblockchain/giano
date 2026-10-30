# @appliedblockchain/giano-wallet-core

## 5.0.0

### Major Changes

- 95a40c2: Move Giano from EntryPoint v0.7 to the final v0.9 release, including EIP-712 operation hashes, Cancun contract artifacts, bundler simulations, canonical deployment checks and configuration. Existing accounts and paymaster deposits require an explicit migration; old signed operations are incompatible. Require viem 2.57.11 or later for v0.9 types and hashing.
- eb8a25f: Require WebAuthn user verification (G4). The wallet contract in release v2 now rejects any passkey signature whose authenticator data lacks the UV flag, so presence alone (for example a security key used without its PIN) no longer authorises an operation or an ERC-1271 signature. `BaseCredentialInfo.userVerification` now accepts only `'required'`; `'preferred'` and `'discouraged'` are refused up front. wallet-api enforces the same rule at registration, sign-in and owner addition.

### Patch Changes

- 00f0c39: Runtime dependencies are now pinned to exact versions (ABIP-7): `zod@3.24.4` in contracts,
  `@noble/hashes@1.8.0` in tx-describe, `ox@0.7.1` and `uuid@11.1.1` in wallet-core, and `ulid@3.0.2`
  in wallet-transport. These are the versions every release already shipped and tested with. A project
  that wants a different version can choose it with its own package manager's overrides. Peer
  dependencies (`viem`, `react`, `wagmi`, `@rainbow-me/rainbowkit`) keep their semver ranges, so
  integrators still choose those versions themselves.
- Updated dependencies [95a40c2]
- Updated dependencies [00f0c39]
- Updated dependencies [544ac79]
- Updated dependencies [b448e54]
- Updated dependencies [eb8a25f]
  - @appliedblockchain/giano-contracts@5.0.0

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

## 3.1.1

### Patch Changes

- cea82f2: Passkey signatures no longer fail about one time in 256. `r` and `s` are now decoded from the authenticator's DER bytes, not taken from ox's `parseAsn1Signature`, which misreads an `r` with a leading zero byte. The account then rejected the signature: `AA24 signature error` on user operations, `InvalidSignature()` on signed reads.
  - @appliedblockchain/giano-contracts@3.1.1

## 3.1.0

### Patch Changes

- Updated dependencies [344a793]
  - @appliedblockchain/giano-contracts@3.1.0

## 3.0.0

### Minor Changes

- 42753c8: New `@appliedblockchain/giano-wallet-core` package: the EIP-1193 provider, passkey smart
  account (`toGianoSmartAccount`), deployment helpers and the `GianoProviderInjection` seam
  (including the wallet-api reference injection) now live here, extracted from the connector
  with no behavior change. The connector re-exports everything, so existing imports keep
  working. Fee estimation is now injectable (`estimateFeesPerGas`) and the inverted hardcoded
  gas defaults (priority 400 gwei > max 200 gwei) are fixed.

### Patch Changes

- ca66fdc: Dependency audit: `uuid` 11.1.0 → 11.1.1 (GHSA-w5hq-g745-h8pq: missing buffer bounds check in v3/v5/v6). No API change.
- b6a635f: Pin Giano siblings exactly in published tarballs. Inter-package dependencies move from `workspace:^`
  to `workspace:*`, which pnpm rewrites at pack time to the sibling's exact version rather than a
  caret range — so installing one of the six installs that release, not a resolution across two.
- 42753c8: Phase 4: `ChainType.EVM` replaces the placeholder `HARDHAT` (kept as a 0-valued alias so
  existing encoded user ids still decode). Fixed-mode versioning now ships all Giano
  packages and images at one version — see COMPATIBILITY.md.
- 5b8b279: Verify paymaster sponsorship signatures using ECDSA recovery without inspecting or calling the signer during ERC-4337 validation. ERC-1271 sponsorship signers are no longer supported; existing contract signers must be replaced with ECDSA keys.

  Fix the raw prepare/sign/send user-operation flow across wallet popups, require consent for raw signing and authenticated reads, and preserve RainbowKit wallet metadata.

- Updated dependencies
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [5b8b279]
- Updated dependencies [62a5d2c]
- Updated dependencies [fcd51ea]
  - @appliedblockchain/giano-contracts@3.0.0
