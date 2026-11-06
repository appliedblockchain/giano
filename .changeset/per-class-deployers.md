---
"@appliedblockchain/giano-contracts": minor
---

The deploy tooling now has one canonical deployer per network class (`mainnet`, `testnet`, and a fixed `local` one), per-chain address overrides in chain profiles, a mainnet deviation guard, and deployment records that state how each address was obtained. `deploy:cli core` checks an existing paymaster proxy's configuration as the guided wizard does, takes its fees from the chain profile unless flags are given, and refuses a record that states another network class. The deployer image and Helm Job accept the chain's profile and committed record (`CHAIN_PROFILE_JSON`, `DEPLOYMENT_RECORD_JSON`; `deployer.chainProfile`, `deployer.deploymentRecord`).
