---
"@appliedblockchain/giano-paymaster-sdk": patch
"@appliedblockchain/giano-tx-describe": patch
"@appliedblockchain/giano-wallet-core": patch
---

Keep three string helpers linear on long input (CodeQL js/polynomial-redos). `isBlockRangeError` finds "limited to a" with `indexOf` and then tests the rest of the sentence with an anchored regex, `formatUnits` trims trailing zeros without a regex, and `toBase64Url` removes at most two padding characters. The results for real input are unchanged.
