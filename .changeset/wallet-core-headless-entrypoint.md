---
"@appliedblockchain/giano-wallet-core": patch
---

Document `giano-wallet-core` as the headless entrypoint for backends. The README now shows how to use the account and management exports in plain Node, and which passkey functions still need a browser. A new test keeps this true: it fails when a browser, React or RainbowKit package enters the dependency tree, or when the built package cannot load and sign a UserOperation in Node with no DOM globals.
