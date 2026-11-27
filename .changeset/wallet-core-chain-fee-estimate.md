---
"@appliedblockchain/giano-wallet-core": patch
---

`createGianoProvider` without `estimateFeesPerGas` now reads fees from the current chain (its EIP-1559 estimate, or `eth_gasPrice` on a chain without one) instead of a fixed 200 gwei / 2 gwei. The fixed figure was far above an L2's fees: it inflated the paymaster prefund and is refused by wallet-api's per-chain fee caps on OP Mainnet, Base and Base Sepolia.
