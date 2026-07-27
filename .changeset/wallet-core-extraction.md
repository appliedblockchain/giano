---
'@appliedblockchain/giano-wallet-core': minor
'@appliedblockchain/giano-connector': minor
---

New `@appliedblockchain/giano-wallet-core` package: the EIP-1193 provider, passkey smart
account (`toGianoSmartAccount`), deployment helpers and the `GianoProviderInjection` seam
(including the wallet-api reference injection) now live here, extracted from the connector
with no behavior change. The connector re-exports everything, so existing imports keep
working. Fee estimation is now injectable (`estimateFeesPerGas`) and the inverted hardcoded
gas defaults (priority 400 gwei > max 200 gwei) are fixed.
