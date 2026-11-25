---
"@appliedblockchain/giano-wallet-core": minor
"@appliedblockchain/giano-wallet-kit": minor
---

The wallet can show where each passkey is stored (PS-1). wallet-api now reports, per credential, a `storage` object: the passkey provider named by the authenticator's AAGUID (for example Google Password Manager, Apple Passwords, 1Password), whether the passkey is synced, and whether it can be. wallet-core types it as `PasskeyStorage`, optional on `RegistryCredential` so an older wallet-api still works. wallet-kit carries it onto each `OwnerRow` as `storage` and re-exports the type. Storage is display only: it never decides anything.
