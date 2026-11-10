---
"@appliedblockchain/giano-wallet-core": patch
---

`eth_signUserOperation` now checks the sender and signs with the same account instance. Before, a restore or login that replaced the account during the sender check made the new account sign the operation as itself.
