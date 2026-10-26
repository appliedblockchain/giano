# @appliedblockchain/giano-contracts

## 3.1.1

## 3.1.0

### Minor Changes

- 344a793: The backend chain document gains per-service sections. `walletApiChainSchema` and `bundlerChainSchema` read one shared document: `chainId`, `name`, `rpcUrl`, `entryPoint` and `sponsorshipPaymaster` at the top, then `walletApi`, `bundler` and `paymasterAdmin` sections. Each schema validates its own section strictly and accepts the others as-is. `backendChainDescriptorSchema` is deprecated.

## 3.0.0

### Minor Changes

- 42753c8: Make the paymaster's tenant roster enumerable on-chain, and add a client library for it.

  `GianoPaymaster` gains an append-only set of registered tenant ids and four views over it —
  `tenantCount`, `tenantIdAt`, `getTenantIds` and `getTenants(start, count)`, the last returning each
  id paired with its full accounting record. Previously the roster could only be reconstructed by
  replaying `TenantRegistered` logs, which meant no client could list tenants or compute
  `Σ balances` from view calls alone. The new field is appended to the ERC-7201 namespace, so the
  storage layout change is additive and upgrade-safe; the committed layout snapshot moves with it.

  `@appliedblockchain/giano-paymaster-sdk` is new: a viem client covering every read and write on the
  paymaster, with the signer injected by the caller so the package never handles key material. Writes
  are simulated before signing, so a missing role arrives as a typed error naming the role rather
  than a reverted transaction. It also carries the role catalogue, tenant-id conversion, and the
  deployment health checks `giano-doctor` runs, as a pure function of an overview. Ships with a
  narrated walkthrough (`pnpm paymaster:demo`) and a management CLI (`giano-paymaster`).

- 42753c8: First versions published to GitHub Packages.

  - contracts: committed `generated.ts` ABIs and `addresses.ts` per-chain address registry
    (`gianoAddresses`, `getGianoDeployment`, `ENTRYPOINT_V07_ADDRESS`); typechain-types dropped from
    the published surface; publish needs no solc or submodules.
  - connector: viem/wagmi/RainbowKit become peer dependencies (wagmi + RainbowKit optional); proper
    `exports` map with types for `.`, `./web` and `./node`; `/node` entry no longer imports
    RainbowKit; injectable `GianoLogger` replaces console noise.

- fcd51ea: Human-readable transaction descriptions on the consent screen.

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

### Patch Changes

- OpenZeppelin 5.3.0 → 5.4.0 (GHSA-9rcw-c2f9-2j55). The wallet factory and implementation keep their
  canonical addresses: the one OpenZeppelin file the wallet compiles, `utils/Base64.sol`, is pinned to
  its 5.3.0 bytes in `vendor/openzeppelin-contracts-5.3.0/` and published with the package, because solc
  embeds every source file's hash in the bytecode.

  The paymaster is rebuilt against OpenZeppelin 5.4.0, so its fresh-deployment freeze moves:

  | Constant                                         | Old                                          | New                                          |
  | ------------------------------------------------ | -------------------------------------------- | -------------------------------------------- |
  | `CANONICAL_SPONSORSHIP_PAYMASTER`                | `0xbD95de95b018697D72A9A3B6B2Ef565093C2B294` | `0x5Eaf2d3b813f227D2E8c0cFcD1e5D111Ade1d489` |
  | `CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION` | `0xeC7BFA2E5A8d6029C210B986a957aB58E7C70434` | `0x40465E7c728cE8887958FA2fBe620924aebbC873` |
  | `CANONICAL_PAYMASTER_DEPLOYER`                   | `0xD90a7Ec5724DA9f30D3224Eb68d39B2790b36b09` | `0x2bB91D45b12F2cF59fd1dC1D331B5850104FFed5` |

  Existing proxies keep their address: upgrade them through UUPS with `hh:upgrade:paymaster`.

- 5b8b279: Verify paymaster sponsorship signatures using ECDSA recovery without inspecting or calling the signer during ERC-4337 validation. ERC-1271 sponsorship signers are no longer supported; existing contract signers must be replaced with ECDSA keys.

  Fix the raw prepare/sign/send user-operation flow across wallet popups, require consent for raw signing and authenticated reads, and preserve RainbowKit wallet metadata.

- 62a5d2c: Register Ethereum Sepolia (11155111) in `gianoAddresses`. The canonical factory and wallet
  implementation are deployed there at their frozen addresses with runtime bytecode identical to Base
  Sepolia's, but the deployment was made outside this repo and its Ignition journal was never
  committed, so the address generator had nothing to read and consumers that default `factoryAddress`
  from the registry — wallet-kit and wallet-api both do — could not resolve the chain. A
  `deployed_addresses.json` reconstructed from the on-chain deployment stands in until the journal is
  recovered; `ignition/deployments/chain-11155111/README.md` records its provenance and what it does
  not cover.
