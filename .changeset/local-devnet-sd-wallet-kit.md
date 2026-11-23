---
"@appliedblockchain/giano-wallet-kit": patch
---

The wallet kit names the local Silent Data chain 31339 "Local devnet SD" when a configuration gives no name. It now takes every such name from giano-contracts' `defaultChainName`, instead of keeping its own copy of the list (H6).
