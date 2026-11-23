---
"@appliedblockchain/giano-contracts": patch
---

`provision:paymaster` no longer fails with "nonce has already been used". It now counts its own nonces with ethers' `NonceManager`, so a fast node or a load-balanced RPC that lags behind the last receipt cannot hand it a nonce already used. Its providers also send every request to the node, so a read that follows a change sees the new value. Without `DEPLOYER_PRIVATE_KEY`, it now signs with the Anvil key on every local chain (31337, 31338 and 31339), not only on 31337 (H6).
