---
"@appliedblockchain/giano-contracts": minor
---

`chainPolicySchema` (a chain document's `walletApi.policy`) accepts `"any"` for `allowedTargets` and `allowedPaymasters`, so allowing any address is a recorded choice, and three new gas caps: `maxPreVerificationGas`, `maxPaymasterVerificationGas` and `maxPaymasterPostOpGas` (G6). An empty list is still accepted and still means any address.
