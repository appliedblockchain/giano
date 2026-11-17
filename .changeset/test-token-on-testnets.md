---
"@appliedblockchain/giano-contracts": patch
---

`deploy:cli test-token` deploys the test ERC-20 alone, without the permissive paymaster, so the served testnets (Base Sepolia, Ethereum Sepolia) can carry the reference dApp's token. It refuses a mainnet, and on a public chain it signs only as the class's canonical deployer, so the token lands at its deterministic address. The registry still refuses a `testPaymaster` on every production chain, and now refuses a `testErc20` only on a mainnet.
