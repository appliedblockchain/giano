---
"@appliedblockchain/giano-wallet-core": minor
---

New export `parseP256PublicKey` turns a passkey's public key into the `(x, y)` coordinates that `encodeAddOwnerPublicKey` and `publicKeyOwnerBytes` take. It accepts the SPKI key from `AuthenticatorAttestationResponse.getPublicKey()`, an uncompressed point (`0x04 ‖ x ‖ y`) or the bare `x ‖ y` coordinates, each as hex, a `Uint8Array` or an `ArrayBuffer`. It throws the new `InvalidP256PublicKeyError` for any other shape, for another algorithm or curve, for a compressed point, and for a point that is not on the P-256 curve.

The provider now uses this helper when it registers a new passkey. Before, it took the last 64 bytes of the key without checks. Now it checks the key right after the passkey is created: a malformed key fails the connect request before the provider sends the credential to the wallet-api or connects an account.

`depositPasskeyIntoPendingAddition` now returns the key this device created as `publicKey`, and computes `fingerprint` from it. Before, it returned the key that wallet-api echoed back. In the same-device flow the add-owner call is signed with that `publicKey`, so a wallet-api that echoed another key could have that key added while the screen showed the fingerprint of the device's own key. The function now parses the key with `parseP256PublicKey` before it deposits it, and throws the new `PendingAdditionKeyMismatchError` when wallet-api reports a different key.
