---
"@appliedblockchain/giano-contracts": patch
---

The package now exports `resolveChainType`, `ChainType` and `gasPriceOracleAbi`, so giano-bundler and wallet-api decide whether a chain is OP Stack in one place, from the bundler's configured `chainType`. `chargesNoGas` also accepts `opStack` as a function, which it calls only once the gas price is 0. The package also exports `proxyDeployBlock`: a proxy's recorded deployment block applies only to that proxy, with addresses compared without regard to case. giano-doctor, wallet-api and the deploy tooling use it to decide where the `Upgraded`-log walk starts (G44).
