---
'@appliedblockchain/giano-contracts': patch
'@appliedblockchain/giano-wallet-core': patch
'@appliedblockchain/giano-wallet-kit': patch
'@appliedblockchain/giano-connector': patch
---

Verify paymaster sponsorship signatures using ECDSA recovery without inspecting or calling the signer during ERC-4337 validation. ERC-1271 sponsorship signers are no longer supported; existing contract signers must be replaced with ECDSA keys.

Fix the raw prepare/sign/send user-operation flow across wallet popups, require consent for raw signing and authenticated reads, and preserve RainbowKit wallet metadata.
