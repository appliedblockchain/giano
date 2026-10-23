---
'@appliedblockchain/giano-wallet-core': patch
---

Passkey signatures no longer fail about one time in 256. `r` and `s` are now decoded from the authenticator's DER bytes, not taken from ox's `parseAsn1Signature`, which misreads an `r` with a leading zero byte. The account then rejected the signature: `AA24 signature error` on user operations, `InvalidSignature()` on signed reads.
