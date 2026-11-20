---
"@appliedblockchain/giano-contracts": patch
---

`provision:paymaster` no longer fails with "nonce has already been used" on a fast node. ethers cached the account's nonce for 250 ms, so a role grant that followed another within that time reused its nonce. The script's providers now send every request to the node (H6).
