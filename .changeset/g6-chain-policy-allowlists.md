---
"@appliedblockchain/giano-contracts": minor
---

`chainPolicySchema` (a chain document's `walletApi.policy`) accepts `"any"` for `allowedTargets` and `allowedPaymasters`, so allowing any address is a recorded choice, and three new gas caps: `maxPreVerificationGas`, `maxPaymasterVerificationGas` and `maxPaymasterPostOpGas` (G6), each a positive decimal integer (a cap of 0 would refuse every operation). An empty list is still accepted and still means any address.
