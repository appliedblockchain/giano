---
"@appliedblockchain/giano-contracts": minor
---

`deploy:cli` and `provision:paymaster` accept `--signed-rpc` (Silent Data, H6).

With the flag, every RPC request carries `x-timestamp` and `x-signature`, signed with the deployer key, so an RPC that replaces `from` on unsigned calls keeps the operator as `from`. The flag needs `DEPLOYER_PRIVATE_KEY`, and the command refuses to start without it.
