# @appliedblockchain/giano-connector

## 3.0.0

### Major Changes

- 42753c8: 1.0.0 — the connector becomes the thin Giano SDK. The default entry point now exposes
  `createGianoWalletProvider({ walletUrl, chain, transport })`: reads answered dApp-side,
  wallet actions via the popup transport to a deployed Giano wallet origin, receipts via
  the wallet-api public endpoint, session cached in localStorage. `createGianoConnector`
  (wagmi) and `giano` (RainbowKit) work unchanged on top. The 0.x embedded surface is
  **removed**: the `./embedded`, `./web` and `./node` subpaths are gone and the package no
  longer depends on `giano-wallet-core`, so no WebAuthn/credential/bundler code is reachable
  from a dApp bundle at all. Migration notes are in the package README.

### Minor Changes

- 42753c8: First versions published to GitHub Packages.

  - contracts: committed `generated.ts` ABIs and `addresses.ts` per-chain address registry
    (`gianoAddresses`, `getGianoDeployment`, `ENTRYPOINT_V07_ADDRESS`); typechain-types dropped from
    the published surface; publish needs no solc or submodules.
  - connector: viem/wagmi/RainbowKit become peer dependencies (wagmi + RainbowKit optional); proper
    `exports` map with types for `.`, `./web` and `./node`; `/node` entry no longer imports
    RainbowKit; injectable `GianoLogger` replaces console noise.

- 42753c8: New `@appliedblockchain/giano-wallet-core` package: the EIP-1193 provider, passkey smart
  account (`toGianoSmartAccount`), deployment helpers and the `GianoProviderInjection` seam
  (including the wallet-api reference injection) now live here, extracted from the connector
  with no behavior change. The connector re-exports everything, so existing imports keep
  working. Fee estimation is now injectable (`estimateFeesPerGas`) and the inverted hardcoded
  gas defaults (priority 400 gwei > max 200 gwei) are fixed.

### Patch Changes

- Updated dependencies [42753c8]
  - @appliedblockchain/giano-wallet-transport@3.0.0
