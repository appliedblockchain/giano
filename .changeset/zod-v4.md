---
"@appliedblockchain/giano-wallet-transport": major
"@appliedblockchain/giano-contracts": major
---

Move to zod 4 (4.6.7). The exported zod schemas (`transportMessageSchema` and the message schemas in `giano-wallet-transport`; `chainDescriptorSchema`, `walletApiChainSchema`, `bundlerChainSchema` and the other chain schemas in `giano-contracts`) are now zod 4 types. A consumer that composes them with its own schemas, or names their types, must use zod 4. The parsed values do not change: `bundlerChainSchema` still fills the `bundler` section's defaults when the section is absent. This release fixes GHSA-mrhx-c7xc-m3w5 (high: zod below 4.6.6 can exhaust memory while validating oversized constrained collections), which no zod 3 release fixes. Consumers get the fix by installing this version.
