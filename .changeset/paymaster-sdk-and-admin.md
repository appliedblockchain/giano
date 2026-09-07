---
'@appliedblockchain/giano-contracts': minor
'@appliedblockchain/giano-paymaster-sdk': minor
---

Make the paymaster's tenant roster enumerable on-chain, and add a client library for it.

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
