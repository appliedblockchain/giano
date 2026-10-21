---
'@appliedblockchain/giano-contracts': patch
'@appliedblockchain/giano-wallet-core': patch
'@appliedblockchain/giano-wallet-transport': patch
'@appliedblockchain/giano-connector': patch
'@appliedblockchain/giano-tx-describe': patch
'@appliedblockchain/giano-wallet-kit': patch
'@appliedblockchain/giano-paymaster-sdk': patch
---

Built with tsdown instead of tsup (which is no longer maintained). Declarations are generated from
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
