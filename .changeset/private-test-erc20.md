---
"@appliedblockchain/giano-contracts": minor
---

Add the private test token `GianoTestPrivateErc20` for Silent Data chains (H6).

It is a UCEF token (`UCEFOwned`, from the `appliedblockchain/ucef-contracts` git submodule): only the holder can read its balance, and anyone can mint to themselves. `deploy:cli testing` deploys it under `giano.test.private-erc20` on chains whose profile sets `"privateTestErc20": true`, and on every local chain, so `local:deploy` deploys it too. No release carries it: it is deployed from the committed artifact `fixtures/private-test-erc20.json` (`pnpm gen:fixtures`), whatever the release. The registry gains an optional `privateTestErc20` field, which a production chain never has.

The package does not ship the token's Solidity source, because it imports UCEF from `lib/`, which the package does not ship. Its ABI is in `generated.ts`.
