---
"@appliedblockchain/giano-wallet-core": patch
"@appliedblockchain/giano-wallet-transport": patch
"@appliedblockchain/giano-connector": patch
"@appliedblockchain/giano-tx-describe": patch
"@appliedblockchain/giano-wallet-kit": patch
---

Remove every non-null assertion (`!`) and explicit `any`. Biome now rejects both. No exported API or type changes, and valid input behaves as before. Changes for invalid input:
- `createGianoProvider` throws the real configuration error (`Unknown chain: N`, `No bundler for chain N`, …) when it cannot select `initialChainId`. Before, the error was an unhandled promise rejection, and the provider returned `gianoClient: undefined`.
- Where a missing value used to cause a `TypeError`, the code now throws an error that names the missing value. For example, the provider throws `GianoError("Giano not connected: …")` when it has no chain state.
