---
"@appliedblockchain/giano-contracts": patch
---

`deploy:cli private-test-token` deploys the private test token (`GianoTestPrivateErc20`) alone, without the test ERC-20 and the permissive paymaster that `testing` also deploys (Silent Data, H6). A Silent Data testnet that the platform serves can then carry the demo's private token. It runs only where the chain's profile sets `privateTestErc20: true`, never on a production chain, and on a public chain only from the class's canonical deployer. Without a key it only verifies. `testing`, the registry build and `doctor` now refuse the permissive paymaster on both Silent Data testnets (R-29), which the platform serves. The deploy preflight no longer requires the deployer's ETH reserve (`minDeployerBalanceEth`) on a chain that charges nothing for gas, as `chargesNoGas` decides, and prints that it skipped the check. Such a chain can hold no ETH at all, like copper-heron (19877). On every chain that charges gas, the check is unchanged.
