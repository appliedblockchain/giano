---
"@appliedblockchain/giano-wallet-core": minor
---

A wallet used from several devices now signs with the passkey this device holds, for the wallet the passkey is bound to. Before, the wallet-api injection used the user's first registered passkey: a device that joined a wallet through a pending addition could not connect (`Invalid credential`), and the first device could derive the joined passkey's own, empty account.

- `createWalletApiInjection().getCredentialInfo()` takes the credential and the wallet address from the session (`GET /v1/me`). Without a session it offers every credential of the user, and the authenticator presents the ones it holds.
- `GianoProviderInjection.onCredentialSignedIn` may return the wallet address the credential signs for, as `onCredentialCreated` already may. `true` keeps the old behaviour. The wallet-api injection returns the address from `authentication/verify`, and `eth_requestAccounts` connects to it.
- `giano_restoreAccount` no longer restores from the first of several credentials. It returns `[]`, and the caller signs in.
- New export `signInWithWebAuthn`: the passkey sign-in, returning the WebAuthn account and the address the injection named. `getWebAuthnAccount` is unchanged.
