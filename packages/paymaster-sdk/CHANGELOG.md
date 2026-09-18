# @appliedblockchain/giano-paymaster-sdk

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
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [62a5d2c]
  - @appliedblockchain/giano-contracts@3.0.0
