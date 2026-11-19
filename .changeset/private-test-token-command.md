---
"@appliedblockchain/giano-contracts": patch
---

`deploy:cli private-test-token` deploys the private test token (`GianoTestPrivateErc20`) alone, without the test ERC-20 and the permissive paymaster that `testing` also deploys (Silent Data, H6). A Silent Data testnet that the platform serves can then carry the demo's private token. It runs only where the chain's profile sets `privateTestErc20: true`, never on a production chain, and on a public chain only from the class's canonical deployer. Without a key it only verifies.
