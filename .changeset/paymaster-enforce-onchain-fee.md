---
"@appliedblockchain/giano-contracts": patch
---

`GianoPaymaster.validatePaymasterUserOp` now rejects a sponsorship authorisation whose `feeWei` is above `feeFor(tenantId)`, with the new `FeeAboveConfigured` error. The timelocked fee setting is now the maximum fee. Before, the contract charged any fee the signing key put in the authorisation. A lower fee is still accepted. Deploy this as a new paymaster implementation; the storage layout does not change.
