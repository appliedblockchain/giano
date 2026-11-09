---
"@appliedblockchain/giano-wallet-core": minor
---

A secondary owner can now connect to the shared smart account. Before, a passkey added with `addOwnerPublicKey` always connected to the address derived from that passkey, which is a different, empty account, because the passkey was never part of the factory salt.

`CredentialInfo` has a new optional `address`: the smart account to connect to. `eth_requestAccounts` and `giano_restoreAccount` connect to it when the injection sets it, after a check that the passkey can sign for it. A deployed account must list the passkey as an owner (`isOwnerBytes`). An account that is not deployed yet must be the passkey's own derived address. When the check fails, the provider throws `GianoAccountOwnerError` and stays disconnected. It never falls back to the derived address. `giano_restoreAccount` throws this error too, where it otherwise returns `[]`. Without `address`, nothing changes.

`address` applies only to an existing credential. Validation rejects it with `credentialId: null`, before the passkey prompt.

New exports: `connectGianoSmartAccount`, which builds the account and runs the same check, and `GianoAccountOwnerError`.
