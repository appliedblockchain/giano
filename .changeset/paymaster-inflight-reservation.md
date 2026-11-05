---
"@appliedblockchain/giano-contracts": patch
---

`GianoPaymaster` now reserves each sponsored operation's maximum charge from validation until settlement, in transient storage. `withdrawTenant` cannot take a reserved amount. Validation checks each operation against the balance minus the earlier reservations in the same bundle. Before, a tenant's withdrawal address could withdraw the whole balance while a sponsored operation was executing. The gas then came out of the other tenants' share of the deposit. Deploy this as a new paymaster implementation; the storage layout and the ABI do not change.
