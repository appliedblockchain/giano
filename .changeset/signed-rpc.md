---
"@appliedblockchain/giano-contracts": minor
---

`deploy:cli` and `provision:paymaster` accept `--signed-rpc` (Silent Data, H6).

With the flag, every RPC request carries `x-timestamp` and `x-signature`, signed with the key the command sends from, so an RPC that replaces `from` on unsigned calls keeps the operator as `from`. That key is `DEPLOYER_PRIVATE_KEY`, or `ROLE_ADMIN_PRIVATE_KEY` for `deploy:cli timelock` and `handoff`; `deploy:cli upgrade --execute` also signs the upgrader's requests with `UPGRADER_PRIVATE_KEY`. Each command refuses to start without the key it needs.
