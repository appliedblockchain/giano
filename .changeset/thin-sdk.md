---
'@appliedblockchain/giano-connector': major
---

1.0.0 — the connector becomes the thin Giano SDK. The default entry point now exposes
`createGianoWalletProvider({ walletUrl, chain, transport })`: reads answered dApp-side,
wallet actions via the popup transport to a deployed Giano wallet origin, receipts via
the wallet-api public endpoint, session cached in localStorage. `createGianoConnector`
(wagmi) and `giano` (RainbowKit) work unchanged on top. The full 0.x embedded surface
moved to the deprecated `@appliedblockchain/giano-connector/embedded` subpath (`./web`
aliases it) with a ≥2-minor deprecation window; `./node` re-exports wallet-core. No
WebAuthn/credential/bundler code is reachable from the default entry point.
