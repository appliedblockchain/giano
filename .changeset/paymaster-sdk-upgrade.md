---
"@appliedblockchain/giano-paymaster-sdk": minor
---

`GianoPaymasterClient.getImplementation()` reads the implementation behind the proxy from the ERC-1967 slot, and `upgradeToAndCall(implementation, data?)` sends an upgrade from a wallet that holds `UPGRADER_ROLE`, as on a devnet. `ERC1967_IMPLEMENTATION_SLOT` is exported. On a handed-off deployment, keep proposing upgrades through `timelock(...).proposeUpgrade`.
