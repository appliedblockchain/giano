---
"@appliedblockchain/giano-contracts": minor
---

Generate per-release code fingerprints (`release-fingerprints.ts`, `pnpm gen:releases`): the runtime code hash of every release contract with its immutables masked, so release code can be recognised at any address. The package now exports `releasesOf(contract, runtimeCode, address?)` (every release the code is, since a release can leave a contract unchanged), `releaseOf(contract, runtimeCode, address?, release?)` (the expected release when it is one of them, else the newest) and `RELEASE_FINGERPRINTS`. `release:verify` now shares the compiler used to produce them.
