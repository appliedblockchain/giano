---
"@appliedblockchain/giano-contracts": minor
---

Add the private test token `GianoTestPrivateErc20` for Silent Data chains (H6).

It is a UCEF token (`UCEFOwned`, vendored under `vendor/ucef/`): only the holder can read its balance, and anyone can mint to themselves. `deploy:cli testing` deploys it under `giano.test.private-erc20` on chains whose profile sets `"privateTestErc20": true`, and on local chains when the release carries it. No release carries it yet; v1 to v3 predate it. The registry gains an optional `privateTestErc20` field, which a production chain never has.
