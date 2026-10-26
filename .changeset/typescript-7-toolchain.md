---
'@appliedblockchain/giano-contracts': patch
'@appliedblockchain/giano-wallet-core': patch
'@appliedblockchain/giano-wallet-transport': patch
'@appliedblockchain/giano-connector': patch
'@appliedblockchain/giano-tx-describe': patch
'@appliedblockchain/giano-wallet-kit': patch
'@appliedblockchain/giano-paymaster-sdk': patch
---

Built with the TypeScript 7 toolchain (declarations still emitted through the 6.0 API) and tsup 9.
No API changes. Consumers need TypeScript 5.0.4 or later, as before.

- `giano-wallet-core`'s declarations no longer import viem internals by relative path
  (`../../types/misc.js` and three more), which failed to resolve in a consuming project with
  `skipLibCheck` off. The inferred `createGianoProvider` return type is printed in a different
  member order; the type is the same.
- Classes with constructor parameter properties (the SDK error classes, `TransportRpcError` and
  friends) now declare those fields in the emitted JavaScript, as `tsc` does for an ES2022 target.
  Each field is assigned in the same constructor, so instances are unchanged.
- Declaration bundles list type-only exports in a separate `export type { … }` clause.
