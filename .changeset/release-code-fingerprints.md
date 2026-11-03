---
"@appliedblockchain/giano-contracts": minor
---

Generate per-release code fingerprints (`release-fingerprints.ts`, `pnpm gen:releases`): the runtime code hash of every release contract with its immutables masked, so release code can be recognised at any address. The package now exports `releaseOf(contract, runtimeCode, address?)` and `RELEASE_FINGERPRINTS`. `release:verify` now shares the compiler used to produce them.
