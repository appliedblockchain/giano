---
"@appliedblockchain/giano-contracts": minor
---

Contracts: the new `chargesNoGas` tells whether a chain charges nothing for gas, so that a user operation with a fee of 0 is the correct fee (H6). The gas price is the latest block's base fee, or `eth_gasPrice` on a chain whose blocks carry none. On an OP Stack chain, the GasPriceOracle's L1 fee must also be 0. `GAS_PRICE_ORACLE` exports the predeploy's address. giano-bundler (estimation and submission) and wallet-api's `pm_getPaymasterData` use it, so a fee of 0 is no longer accepted on a legacy-priced chain that charges gas, or on an OP Stack chain whose L1 fee is above 0.
