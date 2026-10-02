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

- b6a635f: Pin Giano siblings exactly in published tarballs. Inter-package dependencies move from `workspace:^`
  to `workspace:*`, which pnpm rewrites at pack time to the sibling's exact version rather than a
  caret range — so installing one of the six installs that release, not a resolution across two.
- 42753c8: Phase 4: `ChainType.EVM` replaces the placeholder `HARDHAT` (kept as a 0-valued alias so
  existing encoded user ids still decode). Fixed-mode versioning now ships all Giano
  packages and images at one version — see COMPATIBILITY.md.
- 5b8b279: Verify paymaster sponsorship signatures using ECDSA recovery without inspecting or calling the signer during ERC-4337 validation. ERC-1271 sponsorship signers are no longer supported; existing contract signers must be replaced with ECDSA keys.

  Fix the raw prepare/sign/send user-operation flow across wallet popups, require consent for raw signing and authenticated reads, and preserve RainbowKit wallet metadata.

- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [5b8b279]
- Updated dependencies [62a5d2c]
- Updated dependencies [fcd51ea]
  - @appliedblockchain/giano-contracts@3.0.0
