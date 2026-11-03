---
"@appliedblockchain/giano-contracts": major
---

Remove the fixed contract addresses. `canonical.ts` is gone, and with it `CANONICAL_FACTORY`, `CANONICAL_IMPLEMENTATION`, `CANONICAL_SPONSORSHIP_PAYMASTER`, `CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION`, `CANONICAL_DEPLOYER`, `CANONICAL_LABELS`, `CANONICAL_ACCOUNT_NONCE`, `CANONICAL_CODE` and `canonicalCodeAt`. Contract addresses are per chain: testnets and mainnets have different canonical deployers, and a chain may override single contracts.

Replacements:
- addresses: `getGianoDeployment(chainId)` (or `gianoAddresses[chainId]`), which now also gives `implementation`;
- code verification: `releaseOf(contract, runtimeCode)` with `RELEASE_FINGERPRINTS`, which matches code against a release wherever it sits;
- the account nonce: always `0n`.

The `walletApi` section of the backend chain document (`walletApiChainSchema`) accepts an optional `implementation`.
