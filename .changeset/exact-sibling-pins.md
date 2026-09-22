---
'@appliedblockchain/giano-connector': patch
'@appliedblockchain/giano-paymaster-sdk': patch
'@appliedblockchain/giano-wallet-core': patch
'@appliedblockchain/giano-wallet-kit': patch
---

Pin Giano siblings exactly in published tarballs. Inter-package dependencies move from `workspace:^`
to `workspace:*`, which pnpm rewrites at pack time to the sibling's exact version rather than a
caret range — so installing one of the six installs that release, not a resolution across two.
