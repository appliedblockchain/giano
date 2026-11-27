---
"@appliedblockchain/giano-wallet-core": patch
"@appliedblockchain/giano-wallet-kit": minor
---

Wallet management reports what really happened, and stops before a passkey prompt that could not succeed.

- wallet-kit: a chain that cannot be read fails the owner change instead of being skipped as "not deployed", so the change is not reported complete. `WalletRuntime.isAccountDeployed` resolves `null` when the chain cannot be read.
- wallet-kit: when the owner is added on-chain but wallet-api fails to record the new passkey, the add flow's `done` step has `saveFailed` and `retrySave`, and `ok` is false until it is saved.
- wallet-kit: a wallet deployed nowhere yet lists its own passkey as its owner, not as "not an owner"; when the chain that may hold the wallet cannot be read, the view is `unreadable`.
- wallet-kit: removing the passkey in use ends the session here even if wallet-api cannot confirm it.
- wallet-kit: a change stops before any passkey prompt when sponsorship cannot be checked or the session ended; an address that is already an owner is refused at input (`already-owner`).
- wallet-kit: a cancelled or abandoned pending addition is declined as `cancelled`, apart from a refused fingerprint, so only the latter is alertable (WM-52). `rename` resolves whether it was saved. A settled slot stops the poll. Only wallet-api's refusal of the session signs the user out.
- wallet-core: `declinePendingAddition(id, reason?)` sends the reason.
