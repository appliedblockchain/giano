---
"@appliedblockchain/giano-paymaster-sdk": patch
---

Log reads narrow their window when wallet-api's platform read relay refuses the span ("… spanning at most 10000 blocks"), as they already do for the hosted RPCs' refusals, instead of failing on every read.
