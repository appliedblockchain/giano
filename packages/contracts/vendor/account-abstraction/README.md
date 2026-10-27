# ERC-4337 v0.9.0

Unmodified contracts from eth-infinitism/account-abstraction tag v0.9.0, commit b36a1ed52ae00da6f8a4c8d50181e2877e4fa410. Vendored because npm latest is 0.8.0 and 0.9.0-rc.1 predates final security fixes.

EntryPoint.json contains the exact creation/runtime bytecode and ABI verified on Ethereum mainnet by Sourcify (exact matches), at 0x433709009B8330FDa32311DF1C2AFA402eD8D009. Source: https://sourcify.dev/server/v2/contract/1/0x433709009B8330FDa32311DF1C2AFA402eD8D009?fields=all

simulation-input.json extends that verified standard input with the unmodified v0.9 simulation/account contracts and a test-only VerifyingPaymaster fixture adapted from the v0.7 sample (new BasePaymaster constructor and direct sender field). Solidity 0.8.28, Cancun, via IR, 1,000,000 optimizer runs; embedded OpenZeppelin 5.1.0 sources. Compile with solc --standard-json; generated simulation bytecode is not an on-chain deployment artifact.

Upstream: https://github.com/eth-infinitism/account-abstraction/releases/tag/v0.9.0

Rebuild/check: `SOLC=/path/to/solc-0.8.28 node scripts/generate-entrypoint-artifacts.mjs --check` from packages/contracts. The script also reproduces the verified canonical EntryPoint creation code, and binds SenderCreator simulation runtime to the canonical EntryPoint address. Then run the bundler simulation generator.
