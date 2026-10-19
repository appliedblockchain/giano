---
'@appliedblockchain/giano-contracts': patch
---

OpenZeppelin 5.3.0 → 5.4.0 (GHSA-9rcw-c2f9-2j55). The wallet factory and implementation keep their
canonical addresses: the one OpenZeppelin file the wallet compiles, `utils/Base64.sol`, is pinned to
its 5.3.0 bytes in `vendor/openzeppelin-contracts-5.3.0/` and published with the package, because solc
embeds every source file's hash in the bytecode.

The paymaster is rebuilt against OpenZeppelin 5.4.0, so its fresh-deployment freeze moves:

| Constant | Old | New |
|---|---|---|
| `CANONICAL_SPONSORSHIP_PAYMASTER` | `0xbD95de95b018697D72A9A3B6B2Ef565093C2B294` | `0x5Eaf2d3b813f227D2E8c0cFcD1e5D111Ade1d489` |
| `CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION` | `0xeC7BFA2E5A8d6029C210B986a957aB58E7C70434` | `0x40465E7c728cE8887958FA2fBe620924aebbC873` |
| `CANONICAL_PAYMASTER_DEPLOYER` | `0xD90a7Ec5724DA9f30D3224Eb68d39B2790b36b09` | `0x2bB91D45b12F2cF59fd1dC1D331B5850104FFed5` |

Existing proxies keep their address: upgrade them through UUPS with `hh:upgrade:paymaster`.
