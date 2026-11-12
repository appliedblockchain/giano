---
"@appliedblockchain/giano-paymaster-sdk": patch
"@appliedblockchain/giano-tx-describe": patch
"@appliedblockchain/giano-wallet-core": patch
---

Keep three string helpers linear on long input (CodeQL js/polynomial-redos). `isBlockRangeError` searches each sentence for "limited to a" and then "range" without a regex, `formatUnits` trims trailing zeros without a regex, and `toBase64Url` removes at most two padding characters. The results for real input are unchanged.
