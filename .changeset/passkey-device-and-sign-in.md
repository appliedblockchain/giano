---
"@appliedblockchain/giano-wallet-core": minor
"@appliedblockchain/giano-wallet-kit": minor
---

The wallet can tell passkeys apart by the device and browser they were added from, and the wallet origin has one sign-in.

- wallet-core: `PasskeyAddedFrom` (`{ device, browser }`), optional on `RegistryCredential` and on `PendingAddition`, as wallet-api now reports it.
- wallet-kit: `OwnerRow.addedFrom`, and `addedFrom` on the add flow's `confirm-fingerprint` step, so a wallet can show where a new passkey was created before the user signs for it. `signIn` is now a discoverable sign-in with any passkey the device holds; `signInWithExistingPasskey` is a deprecated alias of it.
