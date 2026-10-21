---
'@appliedblockchain/giano-contracts': patch
'@appliedblockchain/giano-wallet-core': patch
'@appliedblockchain/giano-wallet-transport': patch
'@appliedblockchain/giano-connector': patch
'@appliedblockchain/giano-tx-describe': patch
'@appliedblockchain/giano-wallet-kit': patch
'@appliedblockchain/giano-paymaster-sdk': patch
---

Source linted and formatted with Biome (its default configuration) instead of ESLint. No change to
any export or its behaviour: event listeners are still called the same way, now from callbacks that
return nothing.
