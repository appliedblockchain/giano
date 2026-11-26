---
"@appliedblockchain/giano-wallet-kit": minor
---

A second device can join a wallet by scanning a QR code (PS-2). The add flow's `claim-code` step carries `pairingUrl`: the wallet origin with the claim code in its fragment, which a wallet renders as a QR code. `claimCodeFromUrl` reads the code back from such a link, `pairingUrl` builds one, and `startClaimOnThisDevice(code)` starts the claim with the code filled in. The code only routes the new device: adding its passkey still needs the authorising device's signature after the fingerprint comparison, and typing the code still works.
