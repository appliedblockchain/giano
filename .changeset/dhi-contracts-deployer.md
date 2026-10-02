---
---

No release. `packages/contracts` changes only outside its published files: the deployer image moves to Docker
Hardened Images (ABIP-2). It deploys with a new `hardhat.deploy.config.ts`, which replays the build stage's Foundry
remappings instead of loading `hardhat-foundry`, and runs a Node entrypoint. The Hardhat config split into
`hardhat.base.ts` compiles byte-identical artefacts, so the CREATE2 addresses are unchanged.
