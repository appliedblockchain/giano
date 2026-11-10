---
"@appliedblockchain/giano-contracts": patch
---

`GianoPaymaster.validatePaymasterUserOp` now rejects an operation whose `paymasterPostOpGasLimit` is below the new `MIN_POST_OP_GAS_LIMIT` constant (100,000 gas), with the new `PostOpGasLimitTooLow` error. The tenant is charged only in `postOp`. Before, a client could ask for a postOp gas limit too small for settlement. `postOp` then ran out of gas, and the EntryPoint took the gas from the shared deposit without charging the tenant. The loss fell on the other tenants and the treasury. Deploy this as a new paymaster implementation; the storage layout does not change.
