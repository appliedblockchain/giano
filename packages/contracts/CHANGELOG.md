# @appliedblockchain/giano-contracts

## 7.1.0

### Minor Changes

- 3f3e8db: The bundler chain section accepts `stateOverride` (default `true`) (Silent Data, H6).

  Set it to `false` for an RPC that refuses `eth_call` state overrides. The bundler then returns fixed gas limits instead of simulating. It keeps the call gas the caller sends, and a higher verification gas the caller sends.

- c950c90: The deploy tooling can rehearse a testnet deployment on an anvil fork (`pnpm contracts:rehearse`). A stand-in deployer is accepted only when the RPC reports a fork, and everything a rehearsal writes stays in `deploy/rehearsal/`.

  Fixes to the deployment path:

  - A paymaster upgrade executed through the timelock is read from the proxy and reconciled into the record, instead of blocking every later plan, provision and verify run.
  - A handed-off chain verifies with its timelock as `ROLE_ADMIN`.
  - Provisioning takes the sponsorship signer's address and one holder per immediate role. It refuses every-role-on-one-address and a defaulted tenant withdrawal address on a mainnet, and explains its refusal after the hand-off.
  - The hand-off checks the timelock's release code, proposers, executors and delays before sending anything. On a mainnet, proposers must be contracts; EIP-7702-delegated EOAs count as keys.
  - Chains on the mainnet list are always production chains and can never be treated as testnets.
  - `deploy:cli core` runs the wizard's chain prerequisite checks (CreateX codehash, EntryPoint v0.9, Cancun), and `--entry-point` is local-only.
  - The doctor checks CreateX and Cancun instead of the Arachnid factory, and reports a chain without a P-256 precompile as informational.
  - RPC URLs are printed as their origin only.

  The testnet profiles now pin release `v3`.

- 4e7d63e: Add the private test token `GianoTestPrivateErc20` for Silent Data chains (H6).

  It is a UCEF token (`UCEFOwned`, from the `appliedblockchain/ucef-contracts` git submodule): only the holder can read its balance, and anyone can mint to themselves. `deploy:cli testing` deploys it under `giano.test.private-erc20` on chains whose profile sets `"privateTestErc20": true`, and on every local chain, so `local:deploy` deploys it too. No release carries it: it is deployed from the committed artifact `fixtures/private-test-erc20.json` (`pnpm gen:fixtures`), whatever the release. The registry gains an optional `privateTestErc20` field, which a production chain never has.

  The package does not ship the token's Solidity source, because it imports UCEF from `lib/`, which the package does not ship. Its ABI is in `generated.ts`.

- 120ed8a: Read the proxy implementation without `eth_getStorageAt` (Silent Data, H6).

  `proxyImplementation` now falls back to the proxy's latest `Upgraded` event when the RPC refuses the method `eth_getStorageAt`. Any other storage-read error, such as a timeout or a rate limit, is raised as before. When the fallback fails too, the error carries the storage-read error as `cause`.

  The fallback reads logs in spans of at most 9,000 blocks, counted inclusively. The walk stops at the optional `fromBlock` (such as the proxy's deployment block). One read sends at most `maxChunks` requests (default 1,000, a non-negative safe integer); at the limit it throws, and the next read through the same client continues the search further back. The result is kept per client, proxy and `fromBlock`, up to a checkpoint 64 blocks behind the head, so a later read on the same client reads only the newer blocks, and a reorganisation cannot leave a removed upgrade behind.

  `proxyImplementation` takes an optional third argument, `{ fromBlock, maxChunks }`. `proxyImplementationWithSource` returns `{ implementation, source }`, where `source` is `"slot"` or `"logs"`: an answer from the logs is not verified against the implementation slot, and wallet-api's chain check and giano-doctor report it as a warning. New exports: `proxyImplementationWithSource`, `implementationFromUpgradedLogs`, `isMethodRefusedError`, `UPGRADED_TOPIC`, `UPGRADED_LOG_CHUNK`, `UPGRADED_LOG_MAX_CHUNKS` and the type `UpgradedLogWalkOptions`. giano-doctor and the paymaster SDK's `readImplementationSlot` use the same fallback.

  The deploy tooling (`contracts:deploy`, `deploy:cli core`, `contracts:provision`, `contracts:sponsorship`) refuses a paymaster implementation read from the logs, and does not reconcile the deployment record to it, unless the operator passes the new flag `--accept-unverified-implementation`. With the flag, it prints a warning. The deployer image takes `ACCEPT_UNVERIFIED_IMPLEMENTATION=true` for the same flag. `contracts:deploy` accepts the log answer without the flag for a paymaster proxy that the same run deployed, when the proxy's only `Upgraded` event, up to the head, is the one in its deployment transaction and names the implementation the run deployed.

  Paymaster SDK: the new `readImplementationWithSource()` returns `{ address, source }`. `getImplementationCode()` also returns `source`, and `HealthContext.implementation` takes an optional `source`. `getHealth()` reports a release read from the logs as a warning, "implementation is a release, but not verified", not as a pass.

- 5f5d4c4: `deploy:cli` and `provision:paymaster` accept `--signed-rpc` (Silent Data, H6).

  With the flag, every RPC request carries `x-timestamp` and `x-signature`, signed with the key the command sends from, so an RPC that replaces `from` on unsigned calls keeps the operator as `from`. That key is `DEPLOYER_PRIVATE_KEY`, or `ROLE_ADMIN_PRIVATE_KEY` for `deploy:cli timelock` and `handoff`; `deploy:cli upgrade --execute` also signs the upgrader's requests with `UPGRADER_PRIVATE_KEY`. Each command refuses to start without the key it needs.

- 08288d7: The registry carries release v3 on Base Sepolia (84532) and Ethereum Sepolia (11155111): `getGianoDeployment(chainId)` returns the factory, wallet implementation and sponsorship paymaster deployed there on 2026-11-17, at the same addresses on both chains.

### Patch Changes

- c08878a: Deploy tooling follow-ups from the #279 review (G42):
  - On a mainnet, provisioning needs all six role holders, each a different address and none of them the operator key, and an unstake delay of at least a day. `provision:paymaster` checks this too when run directly, not only the `contracts:provision` wrapper.
  - `--unstake-delay` accepts durations (`90`, `6h`, `1d`) and is checked with the other arguments, before the first transaction.
  - The chain prerequisite check reports Cancun as unavailable only when the node says an opcode is missing. A rate limit, a timeout, a rejected request or a revert is reported as an RPC failure.
  - The records directory follows the activated rehearsal, which checks the RPC is an anvil fork, instead of the `GIANO_REHEARSAL_DEPLOYER` variable alone.
  - `handoff` refuses when neither the chain profile nor the deployment record names the timelock's address.
  - `handoff --from-block` is checked against the chain: the timelock must have no code before that block. It also can't start after the recorded deployment block.
- 77deabf: `deploy:cli test-token` deploys the test ERC-20 alone, without the permissive paymaster, so the served testnets (Base Sepolia, Ethereum Sepolia) can carry the reference dApp's token. It refuses a mainnet, and on a public chain it signs only as the class's canonical deployer, so the token lands at its deterministic address. The registry still refuses a `testPaymaster` on every production chain, and now refuses a `testErc20` only on a mainnet.
- 91333c4: The registry carries the test ERC-20 on Base Sepolia and Ethereum Sepolia: `getGianoDeployment(chainId).testErc20` is `0x461E0641a3615336b7D2E4C5D71fB2BB88038C93` on both, the reference dApp's open-mint token.

## 7.0.1

## 7.0.0

### Major Changes

- 8f28872: Remove the fixed contract addresses. `canonical.ts` is gone, and with it `CANONICAL_FACTORY`, `CANONICAL_IMPLEMENTATION`, `CANONICAL_SPONSORSHIP_PAYMASTER`, `CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION`, `CANONICAL_DEPLOYER`, `CANONICAL_LABELS`, `CANONICAL_ACCOUNT_NONCE`, `CANONICAL_CODE` and `canonicalCodeAt`. Contract addresses are per chain: testnets and mainnets have different canonical deployers, and a chain may override single contracts.

  Replacements:

  - addresses: `getGianoDeployment(chainId)` (or `gianoAddresses[chainId]`), which now also gives `implementation`;
  - code verification: `releaseOf(contract, runtimeCode)` with `RELEASE_FINGERPRINTS`, which matches code against a release wherever it sits;
  - the account nonce: always `0n`;
  - a paymaster proxy's implementation: `proxyImplementation(client, proxy)`, or `implementationFromSlot(word)` with `IMPLEMENTATION_SLOT` for a non-viem client.

  The `walletApi` section of the backend chain document (`walletApiChainSchema`) accepts an optional `implementation`.

- 08bd62d: Bind the `signedStaticCall` signature to the call it authorises. Before, the owner signed only the function selector and `signedAt`. Anyone who saw one signature could make any read as the wallet for 30 minutes, for example a view that answers only `msg.sender == wallet`.

  `AuthenticatedStaticCaller` now hashes the selector, `signedAt`, the target and `keccak256(data)`. The new `staticCallHash(target, data, signedAt)` pure function returns this hash. `signedStaticCall` also rejects a `signedAt` later than `block.timestamp`, with the new `StaticCallSignatureNotYetValid` error. Before, a future `signedAt` made a signature last longer than the 30-minute lifetime. The other two errors are renamed: `SignatureExpired` is now `StaticCallSignatureExpired`, and `InvalidSignature` is now `StaticCallInvalidSignature`. `signedStaticCall` returns a target's revert data unchanged, so the new names let a client tell the wallet's errors from a target's. Deploy this as a new wallet implementation; the storage layout does not change. Contract release `v3` contains this change, and the two e2e devnet states are rebuilt from `v3`.

  In `giano-wallet-core`, `signStaticCallPermission` now takes `{ target, data, signedAt? }`. `signedAt` defaults to 30 seconds before the latest block timestamp. The contract rejects a future `signedAt`, so the SDK does not use the local clock, and the margin covers an RPC node that is a block or two behind. The new `staticCallHash` export returns the same hash as the contract. `signed_eth_call` keeps one signature per (account, target, calldata) instead of one signature for every read, and checks `to` and `data` before it asks for a signature. It renews a signature on the local clock, counted from when it was signed, so a local clock that differs from the chain's does not affect it. If the wallet rejects a cached signature, the provider removes it and signs again once. If the wallet also rejects the new signature, the provider removes that one too. Identical concurrent reads share one signature, and the provider asks for one passkey signature at a time. A read whose session ends (disconnect, chain switch or new account) before it finishes does not sign, cache or send anything, and fails with an error that asks the dApp to send it again.

  The signed message changes. This SDK works only with wallets that run the new implementation, and older SDKs fail against it.

### Minor Changes

- fd2ef19: `timelockedRoleProblems` and `delayShortfalls` judge a timelock's role topology and delays against the published policy, for `giano-doctor` and the SDK's `assessHealth` alike.

  `parseDelayList` parses a `minDelay=2d,upgradeToAndCall=7d,…` flag, as `giano-doctor` and the SDK's CLI take it.

- af3fd88: `GianoPaymaster.validatePaymasterUserOp` now rejects an operation whose `paymasterPostOpGasLimit` is below the new `MIN_POST_OP_GAS_LIMIT` constant (100,000 gas), with the new `PostOpGasLimitTooLow` error. The tenant is charged only in `postOp`. Before, a client could ask for a postOp gas limit too small for settlement. `postOp` then ran out of gas, and the EntryPoint took the gas from the shared deposit without charging the tenant. The loss fell on the other tenants and the treasury. Deploy this as a new paymaster implementation; the storage layout does not change.

  The package also exports `PAYMASTER_MIN_POST_OP_GAS_LIMIT` (`100_000n`), the same floor for off-chain code. A sponsorship service must not sign a smaller `paymasterPostOpGasLimit`. The authorisation covers that limit, so the check also protects paymasters deployed before this release. A forge test fails if the exported value and the contract constant differ.

- a8ceffb: The deploy tooling now has one canonical deployer per network class (`mainnet`, `testnet`, and a fixed `local` one), per-chain address overrides in chain profiles, a mainnet deviation guard, and deployment records that state how each address was obtained. `deploy:cli core` checks an existing paymaster proxy's configuration as the guided wizard does, takes its fees from the chain profile unless flags are given, and refuses a record that states another network class. The deployer image and Helm Job accept the chain's profile and committed record (`CHAIN_PROFILE_JSON`, `DEPLOYMENT_RECORD_JSON`; `deployer.chainProfile`, `deployer.deploymentRecord`).
- 68eadca: Generate per-release code fingerprints (`release-fingerprints.ts`, `pnpm gen:releases`): the runtime code hash of every release contract with its immutables masked, so release code can be recognised at any address. The package now exports `releasesOf(contract, runtimeCode, address?)` (every release the code is, since a release can leave a contract unchanged), `releaseOf(contract, runtimeCode, address?, release?)` (the expected release when it is one of them, else the newest) and `RELEASE_FINGERPRINTS`. `release:verify` now shares the compiler used to produce them.

### Patch Changes

- 7938cef: `GianoPaymaster.validatePaymasterUserOp` now rejects a sponsorship authorisation whose `feeWei` is above `feeFor(tenantId)`, with the new `FeeAboveConfigured` error. The timelocked fee setting is now the maximum fee. Before, the contract charged any fee the signing key put in the authorisation. A lower fee is still accepted. Deploy this as a new paymaster implementation; the storage layout does not change.
- 43a6ddc: `GianoPaymaster` now reserves each sponsored operation's maximum charge from validation until settlement, in transient storage. `withdrawTenant` cannot take a reserved amount. Validation checks each operation against the balance minus the earlier reservations in the same bundle. Before, a tenant's withdrawal address could withdraw the whole balance while a sponsored operation was executing. The gas then came out of the other tenants' share of the deposit. Deploy this as a new paymaster implementation; the storage layout and the ABI do not change.
- 75a6c17: `getSignatureLifetime()` in `AuthenticatedStaticCaller` is now `pure` instead of `view`. It returns a constant and reads no state. The ABI in `generated.ts` now says `stateMutability: 'pure'`. Calls to it work as before. The wallet and factory bytecode differs from contract release `v3`, so a later release must include this change before it is deployed. Contract addresses do not change.

## 6.0.1

## 6.0.0

### Major Changes

- 4c85f2e: Move to zod 4 (4.6.7). The exported zod schemas (`transportMessageSchema` and the message schemas in `giano-wallet-transport`; `chainDescriptorSchema`, `walletApiChainSchema`, `bundlerChainSchema` and the other chain schemas in `giano-contracts`) are now zod 4 types. A consumer that composes them with its own schemas, or names their types, must use zod 4. The parsed values do not change: `bundlerChainSchema` still fills the `bundler` section's defaults when the section is absent. This release fixes GHSA-mrhx-c7xc-m3w5 (high: zod below 4.6.6 can exhaust memory while validating oversized constrained collections), which no zod 3 release fixes. Consumers get the fix by installing this version.

## 5.0.0

### Major Changes

- 95a40c2: Move Giano from EntryPoint v0.7 to the final v0.9 release, including EIP-712 operation hashes, Cancun contract artifacts, bundler simulations, canonical deployment checks and configuration. Existing accounts and paymaster deposits require an explicit migration; old signed operations are incompatible. Require viem 2.57.10 or later for v0.9 types and hashing.
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
