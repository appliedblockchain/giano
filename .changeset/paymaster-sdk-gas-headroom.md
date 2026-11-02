---
"@appliedblockchain/giano-paymaster-sdk": patch
---

Writes from `GianoPaymasterClient` and `GianoTimelockClient` are sent with a fifth more gas than the node estimates. A bare estimate can be exactly the gas a call is charged after refunds, and a call that clears storage (cancelling a timelock operation, revoking a role) then runs out of gas and reverts.
