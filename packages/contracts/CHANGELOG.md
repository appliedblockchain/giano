# @appliedblockchain/giano-contracts

## 5.0.0

### Major Changes

- 95a40c2: Move Giano from EntryPoint v0.7 to the final v0.9 release, including EIP-712 operation hashes, Cancun contract artifacts, bundler simulations, canonical deployment checks and configuration. Existing accounts and paymaster deposits require an explicit migration; old signed operations are incompatible. Require viem 2.57.11 or later for v0.9 types and hashing.
- b448e54: Put critical paymaster admin operations behind a timelock (G9). `setTenantWithdrawAddress` moves from `TENANT_ADMIN_ROLE` to a new `WITHDRAW_ADDRESS_ADMIN_ROLE`, so a holder of the tenant-admin role can no longer redirect withdrawals. New `GianoTimelock` contract (in release v2): an OpenZeppelin `TimelockController` with its own delay per function, which holds `ROLE_ADMIN`, `UPGRADER_ROLE`, `FEE_ADMIN_ROLE` and `WITHDRAW_ADDRESS_ADMIN_ROLE`. The package exports the timelock policy and proposal encoders (`TIMELOCKED_OPERATIONS`, `encodeTimelockProposal`, `safeTransactionBatch`, …) and `gianoTimelockAbi`. The deploy CLI gains `timelock`, `handoff` and `upgrade --timelock`, and `giano-doctor chain --timelock` checks the topology and delays.

  Timelock support (G9). `GianoTimelockClient` (or `paymaster.timelock(address)`) reads a GianoTimelock's per-function delays, lists its operations with their state and ETA from the timelock's logs, builds a proposal for each timelocked paymaster action (default fee, tenant fee, withdrawal address, role grant and revoke, upgrade) with the delay the timelock enforces plus the Safe Transaction Builder batch, and executes a ready operation where executors are open. `WITHDRAW_ADDRESS_ADMIN_ROLE` joins the role list and `setTenantWithdrawAddress` is documented under it rather than `TENANT_ADMIN_ROLE`; every role description now says whether it is `timelocked`, and a `MissingRoleError` for a timelocked role says to propose the call. The `giano-paymaster` CLI gains `--timelock` (timelocked commands print the proposal instead of sending, `--safe-json` writes the batch), `upgrade`, and `timelock status | pending | execute`.

- eb8a25f: Require WebAuthn user verification (G4). The wallet contract in release v2 now rejects any passkey signature whose authenticator data lacks the UV flag, so presence alone (for example a security key used without its PIN) no longer authorises an operation or an ERC-1271 signature. `BaseCredentialInfo.userVerification` now accepts only `'required'`; `'preferred'` and `'discouraged'` are refused up front. wallet-api enforces the same rule at registration, sign-in and owner addition.

### Patch Changes

- 00f0c39: Runtime dependencies are now pinned to exact versions (ABIP-7): `zod@3.24.4` in contracts,
  `@noble/hashes@1.8.0` in tx-describe, `ox@0.7.1` and `uuid@11.1.1` in wallet-core, and `ulid@3.0.2`
  in wallet-transport. These are the versions every release already shipped and tested with. A project
  that wants a different version can choose it with its own package manager's overrides. Peer
  dependencies (`viem`, `react`, `wagmi`, `@rainbow-me/rainbowkit`) keep their semver ranges, so
  integrators still choose those versions themselves.
- 544ac79: Add generic guided deployment and operator workflows driven by persisted chain profiles, initially including Base Sepolia and Ethereum Sepolia with read-only prerequisite checks, release-code and proxy configuration verification, explicit transaction confirmation, and per-contract deployment checkpoints.

## 4.0.0

### Major Changes

- bc75e86: Canonical contracts are now deployed with CREATE3 through CreateX, from committed releases, by a
  dedicated canonical deployer. Every canonical address is a function of that deployer and a fixed
  label only, so no future compiler, toolchain or contract release moves it again.

  Breaking:

  - **New canonical addresses.** `CANONICAL_FACTORY`, `CANONICAL_IMPLEMENTATION`,
    `CANONICAL_SPONSORSHIP_PAYMASTER` and `CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION` all change.
    They still derive from a placeholder deployer and change once more when the real one is set.
  - **The address registry is empty** (`gianoAddresses`, `getGianoDeployment`) until the chains are
    redeployed under the new scheme; the old Base, Base Sepolia and Sepolia deployments are dropped.
  - Removed: `CANONICAL_PAYMASTER_DEPLOYER`, `gianoPaymasterDeployerAbi` and `create2Abi`. CreateX's
    `deployCreate3AndInit` deploys and initialises the paymaster proxy atomically, so
    `GianoPaymasterDeployer` is gone.
  - `PrivateERC20` and `PermissivePaymaster` (test fixtures) take their holder and owner as
    constructor arguments.

  Added: `CANONICAL_DEPLOYER`, `CANONICAL_LABELS`, `CANONICAL_CODE` (the runtime codehash each
  release leaves at each canonical address) and `canonicalCodeAt(address, codehash)`. An address no
  longer proves which code sits there; check the code too.

### Patch Changes

- 01b008f: Source linted and formatted with Biome (its default configuration) instead of ESLint. No change to
  any export or its behaviour: event listeners are still called the same way, now from callbacks that
  return nothing.
- 762221a: Built with tsdown instead of tsup (which is no longer maintained). Declarations are generated from
  source by oxc (`isolatedDeclarations`) rather than by the TypeScript compiler, so exported functions
  and constants now carry explicit types. Same entry points, file names and runtime exports; every
  export's type is equivalent to before (checked by mutual assignability, and member by member for
  classes), and the declarations compile with TypeScript 5.0.4 through 7.0.

  - `giano-wallet-core`: `createGianoProvider(...).gianoClient` is typed as viem's `PublicClient`.
    The previous declaration printed an expansion of it that viem's `PublicClient` did not accept, so
    passing it to anything typed `PublicClient` failed to compile. It also exports the
    `ReplaySafeTypedData` type that `toReplaySafeTypedData` returns.
  - Bundles keep their JSDoc comments, and `giano-paymaster-sdk`'s library bundle no longer shares a
    chunk with its CLI.

- bb23680: Built and typechecked with TypeScript 7 only. No API changes. Consumers need TypeScript 5.0.4 or later, as before.

  - `giano-wallet-core`'s declarations no longer import viem internals by relative path
    (`../../types/misc.js` and three more), which failed to resolve in a consuming project with
    `skipLibCheck` off. The inferred `createGianoProvider` return type is printed in a different
    member order; the type is the same.
  - Classes with constructor parameter properties (the SDK error classes, `TransportRpcError` and
    friends) now declare those fields in the emitted JavaScript, as `tsc` does for an ES2022 target.
    Each field is assigned in the same constructor, so instances are unchanged.
  - Declaration bundles list type-only exports in a separate `export type { … }` clause.

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
    (`gianoAddresses`, `getGianoDeployment`, `ENTRYPOINT_V09_ADDRESS`); typechain-types dropped from
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
