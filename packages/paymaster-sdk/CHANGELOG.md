# @appliedblockchain/giano-paymaster-sdk

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

- @appliedblockchain/giano-contracts@3.1.1

## 3.1.0

### Patch Changes

- Updated dependencies [344a793]
  - @appliedblockchain/giano-contracts@3.1.0

## 3.0.0

### Minor Changes

- dedd314: Read logs in one window at the head instead of reconstructing history from genesis.

  `getTenantSlugs` and `getSponsorships` asked for `earliest`..`latest` in a single `eth_getLogs`.
  Hosted endpoints refuse that — Base Sepolia answers `eth_getLogs is limited to a 10,000 range`
  (-32614) — so both failed outright on every chain but a local devnet.

  Walking the range a window at a time would have unbroken them and then broken them again later:
  that walk grows by about five windows a day on a two-second chain, so a read that takes 2s against
  a week-old deployment takes 43s at six months and is refused outright before two years. Both reads
  are now a **single query over a window ending at the head**, which costs the same on a chain's
  first day as on its ten-thousandth.

  Both return the range they covered and the window before it, so a caller pages backwards
  explicitly:

  ```ts
  let page = await paymaster.getSponsorships();
  let records = [...page.records];
  while (records.length < 100 && page.older) {
    page = await paymaster.getSponsorships({ range: page.older });
    records = [...page.records, ...records]; // older first: the result stays newest-last
  }
  ```

  The span narrows on its own when a node's cap is tighter than the default 9,000, and the client
  keeps the span that worked, so `logWindow` only ever saves a discovery round trip.

  `getTenantSlugs` also takes a `tenantId`, filtered on the indexed topic, so hunting one known
  tenant's label backwards is the node skipping windows rather than the caller downloading and
  discarding them.

  **Breaking:** `getSponsorships()` returns `{ fromBlock, toBlock, older?, records }` rather than an
  array, and `getTenantSlugs()` returns `{ fromBlock, toBlock, older?, slugs }` rather than a `Map`.
  Both took `fromBlock`/`toBlock` options and now take a single `range` inside an options object.
  `listTenants({ withSlugs: true })` still folds labels in, but a caller that needs to know _which_
  blocks they came from — to say so on screen, or to page back for the ones that predate them — has
  to call `getTenantSlugs` itself, since only that returns the window.

- 42753c8: Make the paymaster's tenant roster enumerable on-chain, and add a client library for it.

  `GianoPaymaster` gains an append-only set of registered tenant ids and four views over it —
  `tenantCount`, `tenantIdAt`, `getTenantIds` and `getTenants(start, count)`, the last returning each
  id paired with its full accounting record. Previously the roster could only be reconstructed by
  replaying `TenantRegistered` logs, which meant no client could list tenants or compute
  `Σ balances` from view calls alone. The new field is appended to the ERC-7201 namespace, so the
  storage layout change is additive and upgrade-safe; the committed layout snapshot moves with it.

  `@appliedblockchain/giano-paymaster-sdk` is new: a viem client covering every read and write on the
  paymaster, with the signer injected by the caller so the package never handles key material. Writes
  are simulated before signing, so a missing role arrives as a typed error naming the role rather
  than a reverted transaction. It also carries the role catalogue, tenant-id conversion, and the
  deployment health checks `giano-doctor` runs, as a pure function of an overview. Ships with a
  narrated walkthrough (`pnpm paymaster:demo`) and a management CLI (`giano-paymaster`).

### Patch Changes

- b6a635f: Pin Giano siblings exactly in published tarballs. Inter-package dependencies move from `workspace:^`
  to `workspace:*`, which pnpm rewrites at pack time to the sibling's exact version rather than a
  caret range — so installing one of the six installs that release, not a resolution across two.
- Updated dependencies
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [5b8b279]
- Updated dependencies [62a5d2c]
- Updated dependencies [fcd51ea]
  - @appliedblockchain/giano-contracts@3.0.0
