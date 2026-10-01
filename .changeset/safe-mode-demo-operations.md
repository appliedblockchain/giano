---
'@appliedblockchain/giano-contracts': patch
'@appliedblockchain/giano-wallet-core': patch
'@appliedblockchain/giano-wallet-kit': patch
'@appliedblockchain/giano-connector': patch
---

Verify paymaster ECDSA signatures without inspecting signer bytecode during ERC-4337 validation. Existing ERC-1271 signers must be removed and re-added after a paymaster implementation upgrade to record their signer type.

Fix the raw prepare/sign/send user-operation flow across wallet popups, require consent for raw signing and authenticated reads, and preserve RainbowKit wallet metadata.
