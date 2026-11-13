---
"@appliedblockchain/giano-paymaster-sdk": patch
"@appliedblockchain/giano-tx-describe": patch
"@appliedblockchain/giano-wallet-core": patch
---

Keep three string helpers linear on long input (CodeQL js/polynomial-redos). `isBlockRangeError` searches each sentence for "limited to a" and then "range" without a regex, `formatUnits` trims trailing zeros without a regex, and `toBase64Url` removes at most two padding characters. The results for real input are unchanged.

`formatUnits` now throws unless `decimals` is an integer from 0 to 255 (an ERC-20 `uint8`), and `describeTransaction` treats a token whose resolver returns an invalid `decimals` value as unresolved. An invalid `nativeCurrency.decimals` makes `describeTransaction` return `unknown` with reason `decode-failed`; it still never throws.
