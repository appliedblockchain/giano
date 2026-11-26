---
"@appliedblockchain/giano-wallet-core": minor
"@appliedblockchain/giano-wallet-kit": patch
---

A wallet used from several devices now signs with the passkey this device holds, for the wallet the passkey is bound to. Before, the wallet-api injection used the user's first registered passkey: a device that joined a wallet through a pending addition could not connect (`Invalid credential`), and the first device could derive the joined passkey's own, empty account.

- `createWalletApiInjection().getCredentialInfo()` takes the credential and the wallet address from the session (`GET /v1/me`). Without a session it offers every credential of the user, and the authenticator presents the ones it holds.
- `GianoProviderInjection.onCredentialSignedIn` may return the wallet address the credential signs for, as `onCredentialCreated` already may. `true` keeps the old behaviour. The wallet-api injection returns the address from `authentication/verify`, and `eth_requestAccounts` connects to it.
- `giano_restoreAccount` no longer restores from the first of several credentials. It returns `[]`, and the caller signs in.
- New export `signInWithWebAuthn`: the passkey sign-in, returning the WebAuthn account and the address the injection named. `getWebAuthnAccount` is unchanged.
- The wallet-api injection's `logout()` ends the session here first, as a logout, and then tells wallet-api. Before, removing the passkey in use (WM-30) revoked the session, the logout got a 401, and the wallet reported "Your session ended" in place of the removal's outcome.
- wallet-kit: an owner change skips a chain where the account is not deployed before it restores the account there. A passkey added as an owner cannot connect to an undeployed account, so the chain was reported failed, and the change incomplete, instead of skipped.
