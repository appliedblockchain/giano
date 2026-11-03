---
"@appliedblockchain/giano-tx-describe": patch
---

Move to zod 4 (4.6.7), which fixes GHSA-mrhx-c7xc-m3w5 (high: zod below 4.6.6 can exhaust memory while validating oversized constrained collections). The public types do not include zod, and `validateMapping` keeps its custom messages. zod's default messages for other issues now use zod 4's wording.
