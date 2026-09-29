---
'@appliedblockchain/giano-tx-describe': minor
'@appliedblockchain/giano-wallet-kit': minor
'@appliedblockchain/giano-contracts': minor
---

Human-readable transaction descriptions on the consent screen.

- New package `@appliedblockchain/giano-tx-describe`: turns a transaction request plus a set of
  ERC-7730 clear-signing mappings into an intent sentence and labelled fields, or an explicit
  `unknown` result carrying the raw data. Ships generic ERC-20 / ERC-721 mappings (flagged as
  generic), describes native transfers without a mapping, validates descriptors with per-path
  issues, and depends on nothing else in Giano.
- `wallet-kit`: every `WalletRuntime` gains `describeTransaction(tx)`, which fetches and caches the
  tenant's mappings from wallet-api (`GET /v1/tx-mappings`), resolves ERC-20 symbol and decimals
  from the chain, and never rejects. `WalletChainConfig` gains an optional `nativeCurrency`
  (default ETH, 18 decimals) so amounts are named in the chain's own currency.
- `contracts`: the shared chain descriptor schema gains the optional `nativeCurrency` field.
