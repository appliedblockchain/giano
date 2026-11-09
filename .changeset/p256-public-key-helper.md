---
"@appliedblockchain/giano-wallet-core": minor
---

New export `parseP256PublicKey` turns a passkey's public key into the `(x, y)` coordinates that `encodeAddOwnerPublicKey` and `publicKeyOwnerBytes` take. It accepts the SPKI key from `AuthenticatorAttestationResponse.getPublicKey()`, an uncompressed point (`0x04 ‖ x ‖ y`) or the bare `x ‖ y` coordinates, each as hex, a `Uint8Array` or an `ArrayBuffer`. It throws the new `InvalidP256PublicKeyError` for any other shape, for another algorithm or curve, for a compressed point, and for a point that is not on the P-256 curve.

The provider now uses this helper when it registers a new passkey. Before, it took the last 64 bytes of the key without checks. Now a malformed key fails the connect request instead of reaching the wallet-api.
