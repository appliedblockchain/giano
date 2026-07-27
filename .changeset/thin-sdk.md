---
'@appliedblockchain/giano-connector': major
---

1.0.0 — the connector becomes the thin Giano SDK. The default entry point now exposes
`createGianoWalletProvider({ walletUrl, chain, transport })`: reads answered dApp-side,
wallet actions via the popup transport to a deployed Giano wallet origin, receipts via
the wallet-api public endpoint, session cached in localStorage. `createGianoConnector`
(wagmi) and `giano` (RainbowKit) work unchanged on top. The 0.x embedded surface is
**removed**: the `./embedded`, `./web` and `./node` subpaths are gone and the package no
longer depends on `giano-wallet-core`, so no WebAuthn/credential/bundler code is reachable
from a dApp bundle at all. Migration notes are in the package README.
