---
'@appliedblockchain/giano-paymaster-sdk': minor
---

Read logs in one window at the head instead of reconstructing history from genesis.

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
`listTenants({ withSlugs: true })` still folds labels in, but a caller that needs to know *which*
blocks they came from — to say so on screen, or to page back for the ones that predate them — has
to call `getTenantSlugs` itself, since only that returns the window.
