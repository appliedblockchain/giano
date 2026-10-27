---
"@appliedblockchain/giano-contracts": patch
"@appliedblockchain/giano-tx-describe": patch
"@appliedblockchain/giano-wallet-core": patch
"@appliedblockchain/giano-wallet-transport": patch
---

Runtime dependencies are now pinned to exact versions (ABIP-7): `zod@3.24.4` in contracts,
`@noble/hashes@1.8.0` in tx-describe, `ox@0.7.1` and `uuid@11.1.1` in wallet-core, and `ulid@3.0.2`
in wallet-transport. These are the versions every release already shipped and tested with. A project
that wants a different version can choose it with its own package manager's overrides. Peer
dependencies (`viem`, `react`, `wagmi`, `@rainbow-me/rainbowkit`) keep their semver ranges, so
integrators still choose those versions themselves.
