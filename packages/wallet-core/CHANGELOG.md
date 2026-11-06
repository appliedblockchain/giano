# @appliedblockchain/giano-wallet-core

## 7.0.0

### Major Changes

- 08bd62d: Bind the `signedStaticCall` signature to the call it authorises. Before, the owner signed only the function selector and `signedAt`. Anyone who saw one signature could make any read as the wallet for 30 minutes, for example a view that answers only `msg.sender == wallet`.

  `AuthenticatedStaticCaller` now hashes the selector, `signedAt`, the target and `keccak256(data)`. The new `staticCallHash(target, data, signedAt)` pure function returns this hash. `signedStaticCall` also rejects a `signedAt` later than `block.timestamp`, with the new `StaticCallSignatureNotYetValid` error. Before, a future `signedAt` made a signature last longer than the 30-minute lifetime. The other two errors are renamed: `SignatureExpired` is now `StaticCallSignatureExpired`, and `InvalidSignature` is now `StaticCallInvalidSignature`. `signedStaticCall` returns a target's revert data unchanged, so the new names let a client tell the wallet's errors from a target's. Deploy this as a new wallet implementation; the storage layout does not change. Contract release `v3` contains this change, and the two e2e devnet states are rebuilt from `v3`.

  In `giano-wallet-core`, `signStaticCallPermission` now takes `{ target, data, signedAt? }`. `signedAt` defaults to 30 seconds before the latest block timestamp. The contract rejects a future `signedAt`, so the SDK does not use the local clock, and the margin covers an RPC node that is a block or two behind. The new `staticCallHash` export returns the same hash as the contract. `signed_eth_call` keeps one signature per (account, target, calldata) instead of one signature for every read, and checks `to` and `data` before it asks for a signature. It renews a signature on the local clock, counted from when it was signed, so a local clock that differs from the chain's does not affect it. If the wallet rejects a cached signature, the provider removes it and signs again once. If the wallet also rejects the new signature, the provider removes that one too. Identical concurrent reads share one signature, and the provider asks for one passkey signature at a time. A read whose session ends (disconnect, chain switch or new account) before it finishes does not sign, cache or send anything, and fails with an error that asks the dApp to send it again.

  The signed message changes. This SDK works only with wallets that run the new implementation, and older SDKs fail against it.

### Minor Changes

- 1bc3447: Fix `personal_sign` and `eth_sign` so the signature covers the message the dApp sent. A 0x-prefixed hex message with whole bytes is now signed as its raw bytes, and any other message (including odd-length hex) as UTF-8 text. Before, the provider passed the hex spelling to `signMessage` as text, so signatures failed standard EIP-191 / ERC-1271 verification. Every Giano `personal_sign` and `eth_sign` signature changes with this release; a verifier written for the old output must switch to standard verification.

  New export `toPersonalMessageBytes` (from `giano-wallet-core`, re-exported by `giano-wallet-kit`) returns the exact bytes these methods sign, so a consent screen can show the same payload.

  New `giano-wallet-kit` export `describePersonalMessage` returns what a consent screen should show for these methods. It returns the signed bytes as text only when they are valid UTF-8 with no hidden character (control, bidi, zero-width or other default-ignorable characters, or a leading BOM). Otherwise it returns hex, with `rawHex: true` so the screen can warn the user.

### Patch Changes

- Updated dependencies [7938cef]
- Updated dependencies [43a6ddc]
- Updated dependencies [75a6c17]
- Updated dependencies [08bd62d]
  - @appliedblockchain/giano-contracts@7.0.0

## 6.0.1

### Patch Changes

- 67e7522: `eth_signUserOperation` now signs only for the connected chain and account. It rejects an operation whose `chainId` differs from the connected chain ("Chain mismatch") or whose `sender` differs from the connected account ("Address mismatch"). Before, a dApp could supply any `chainId` and get a signature that is valid on another chain.
  - @appliedblockchain/giano-contracts@6.0.1

## 6.0.0

### Minor Changes

- fc4164a: Add an optional wallet-owned passkeyDevicePreference setting to suggest mobile authentication through WebAuthn hybrid hints. Default browser choice, credential eligibility, user verification, and explicit enrollment behavior are preserved.

### Patch Changes

- Updated dependencies [4c85f2e]
  - @appliedblockchain/giano-contracts@6.0.0

## 5.0.0

### Major Changes

- 95a40c2: Move Giano from EntryPoint v0.7 to the final v0.9 release, including EIP-712 operation hashes, Cancun contract artifacts, bundler simulations, canonical deployment checks and configuration. Existing accounts and paymaster deposits require an explicit migration; old signed operations are incompatible. Require viem 2.57.10 or later for v0.9 types and hashing.
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
