---
'@appliedblockchain/giano-contracts': major
---

New canonical freeze: every Giano contract moves to a new CREATE2 address.

OpenZeppelin goes from 5.3.0 to 5.4.0 to clear GHSA-9rcw-c2f9-2j55. OZ 5.4 emits `mcopy`, so the
canonical EVM target moves from `paris` to `cancun`, which changes the bytecode of every contract:

| Constant | Old | New |
|---|---|---|
| `CANONICAL_FACTORY` | `0x26dCd29390eba3B22BcCbd2143989E5994Ac7050` | `0x072aF5D2f787533C5114020D50bf847aB6146bE9` |
| `CANONICAL_IMPLEMENTATION` | `0x15cC758f7D3188c2361f6141CEaa9Ab2792bea56` | `0x8BA285D7Aff26D42DCCc9CE202112aa3d058Ac72` |
| `CANONICAL_SPONSORSHIP_PAYMASTER` | `0xf98b56de62ce88cEb70A9155582248cDBf2D0718` | `0x737870Df331E2b78d9d4429eF94e187E1b1DE6D8` |
| `CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION` | `0xFc6e7a0b9b5E9E27C8E2caf8961A13FD16ebd818` | `0xA37b6d278Db64F92855724076458853B2c5B0d80` |
| `CANONICAL_PAYMASTER_DEPLOYER` | `0xD90a7Ec5724DA9f30D3224Eb68d39B2790b36b09` | `0xaFd669c6D0BD987FdE71B005027250E1C89Fbb4e` |

A smart account's address comes from the factory, so every passkey now resolves to a different
account address. Anything that hard-codes an old address must be updated.

Base, Base Sepolia and Sepolia are listed under the new `pendingDeployment` key in
`address-overrides.json`. `gianoAddresses` names the new canonical factory and implementation for
them, but nothing is deployed there yet. Each entry is removed once that chain is redeployed and its
journal is committed.
