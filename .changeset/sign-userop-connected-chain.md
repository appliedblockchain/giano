---
"@appliedblockchain/giano-wallet-core": patch
---

`eth_signUserOperation` now signs only for the connected chain and account. It rejects an operation whose `chainId` differs from the connected chain ("Chain mismatch") or whose `sender` differs from the connected account ("Address mismatch"). Before, a dApp could supply any `chainId` and get a signature that is valid on another chain.
