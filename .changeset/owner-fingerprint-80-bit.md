---
"@appliedblockchain/giano-wallet-core": major
---

Lengthen the owner fingerprint from 30 bits to 80 bits. `ownerFingerprint` now returns sixteen Crockford base32 characters in four groups, `XXXX-XXXX-XXXX-XXXX`, instead of six characters as `XXX-XXX`.

Both devices show this fingerprint when a passkey is added from a second device (WM-20). The comparison is the only check that stops the wallet-api operator from replacing the new device's key with its own. The operator receives the genuine key first and decides when the authorising device sees it, so it has unlimited time to search for a key with the same fingerprint. With 30 bits that search takes minutes on a GPU. With 80 bits it is not feasible.

Every fingerprint changes, including the ones shown for existing owners. A client that parses or checks the old `XXX-XXX` format must accept the new one. Both devices must run this version: an older SDK on one device shows a different fingerprint, so the user sees a mismatch and declines the addition.
