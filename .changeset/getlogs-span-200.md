---
"@appliedblockchain/giano-paymaster-sdk": patch
---

Log reads narrow down to a 200-block span, not 250, when a node refuses a wider one. `https://sepolia.base.org` serves at most 200 (`eth_getLogs is limited to a 200 range`), so every log read against it failed once narrowing stopped at 250.
