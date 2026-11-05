---
"@appliedblockchain/giano-wallet-core": minor
"@appliedblockchain/giano-wallet-kit": minor
---

Fix `personal_sign` and `eth_sign` so the signature covers the message the dApp sent. A 0x-prefixed hex message with whole bytes is now signed as its raw bytes, and any other message (including odd-length hex) as UTF-8 text. Before, the provider passed the hex spelling to `signMessage` as text, so signatures failed standard EIP-191 / ERC-1271 verification. Every Giano `personal_sign` and `eth_sign` signature changes with this release; a verifier written for the old output must switch to standard verification.

New export `toPersonalMessageBytes` (from `giano-wallet-core`, re-exported by `giano-wallet-kit`) returns the exact bytes these methods sign, so a consent screen can show the same payload.

New `giano-wallet-kit` export `describePersonalMessage` returns what a consent screen should show for these methods. It returns the signed bytes as text only when they are valid UTF-8 with no hidden character (control, bidi, zero-width or other default-ignorable characters, or a leading BOM). Otherwise it returns hex, with `rawHex: true` so the screen can warn the user.
