---
"@appliedblockchain/giano-wallet-core": minor
"@appliedblockchain/giano-wallet-kit": minor
---

A connect without a session can sign in with whichever passkey the device holds, instead of only the passkeys of the user its browser last knew. A device that joined a wallet from another device no longer creates a new wallet on its first connect, and a returning user on a fresh browser can sign in with their synced passkey.

- wallet-core: `createWalletApiInjection().setConnectChoice("existing" | "new" | null)`. `existing` asks the browser for any passkey it holds, with a challenge bound to no user (wallet-api's new `discoverable` option); `new` creates a wallet, under a fresh external user id when the stored one already has a wallet. A session still decides. `signInWithExistingPasskey` uses a discoverable challenge. `depositPasskeyIntoPendingAddition` accepts a `userName` function of the joined wallet's address, and returns `walletAddress`.
- wallet-kit: a connect `PendingRequest` carries `connect` (`session`, `held-passkey` or `default`) and, when there is a choice, `approveAlternative`. The host applies the choice to that connect alone. The device remembers that it holds a passkey (`hasPasskeyOnDevice`, `markPasskeyOnDevice`). New passkeys are named after their wallet when it is known, else after the day (`passkeyName`), so a picker can tell them apart.
