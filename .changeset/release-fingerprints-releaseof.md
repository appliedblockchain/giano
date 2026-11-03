---
"@appliedblockchain/giano-contracts": minor
---

Add `releaseOf(contract, runtimeCode)` and `RELEASE_FINGERPRINTS`: which release the code at any address is, matched by the release's code fingerprint (the runtime code hash with immutables masked) rather than by a fixed address. The deploy tooling now has one canonical deployer per network class (`mainnet`, `testnet`, and a fixed `local` one), per-chain address overrides in chain profiles, a mainnet deviation guard, and deployment records that state how each address was obtained.
