---
'@appliedblockchain/giano-contracts': minor
'@appliedblockchain/giano-connector': minor
---

First versions published to GitHub Packages.

- contracts: committed `generated.ts` ABIs and `addresses.ts` per-chain address registry
  (`gianoAddresses`, `getGianoDeployment`, `ENTRYPOINT_V07_ADDRESS`); typechain-types dropped from
  the published surface; publish needs no solc or submodules.
- connector: viem/wagmi/RainbowKit become peer dependencies (wagmi + RainbowKit optional); proper
  `exports` map with types for `.`, `./web` and `./node`; `/node` entry no longer imports
  RainbowKit; injectable `GianoLogger` replaces console noise.
