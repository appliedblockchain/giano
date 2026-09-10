# @appliedblockchain/giano-wallet-core

## 3.0.0

### Minor Changes

- 42753c8: New `@appliedblockchain/giano-wallet-core` package: the EIP-1193 provider, passkey smart
  account (`toGianoSmartAccount`), deployment helpers and the `GianoProviderInjection` seam
  (including the wallet-api reference injection) now live here, extracted from the connector
  with no behavior change. The connector re-exports everything, so existing imports keep
  working. Fee estimation is now injectable (`estimateFeesPerGas`) and the inverted hardcoded
  gas defaults (priority 400 gwei > max 200 gwei) are fixed.

### Patch Changes

- 42753c8: Phase 4: `ChainType.EVM` replaces the placeholder `HARDHAT` (kept as a 0-valued alias so
  existing encoded user ids still decode). Fixed-mode versioning now ships all Giano
  packages and images at one version — see COMPATIBILITY.md.
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
  - @appliedblockchain/giano-contracts@3.0.0
