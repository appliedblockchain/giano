---
"@appliedblockchain/giano-wallet-core": patch
---

The wallet-api injection no longer sends the authenticator's name as the new passkey's label at registration. That name is for the passkey picker (the brand and the day), not a label for the user. Until the user names a passkey, a wallet shows it by the device and browser it was added from, the same way as a passkey added from another device.
