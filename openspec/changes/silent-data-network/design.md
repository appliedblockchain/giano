# Design

## Context

See proposal.md (Why) for the gateway restrictions. Giano adapts to the gateway as it is and expects no change from Silent Data. More facts that shape the approach:

- **The gateway already knows Giano wallets.** `private-rollup/services/custom-rpc` verifies a signed request from a smart wallet: the `x-signer-swc` header, then ERC-1271 on the wallet. For type `giano` (the default), it wraps the hash in Giano's EIP-712 domain, `Giano Smart Wallet`, version `1`. That domain matches `GianoSmartWallet._domainNameAndVersion()`. With `x-signer-swc`, the gateway sets the call's `from` to the wallet. A delegate ticket can also be approved by the wallet, and then an ephemeral key signs each request.
- **Delegate signing exists in the providers.** `silentdatarollup-core` (`Base.ts`) implements it with `smartWalletAddress` and `smartWalletType: 'giano'`. The delegate message is `chainId + JSON(ticket)`. For a smart wallet, the client signs `keccak256` of that message as bytes through `signMessage`.
- **The demo cannot easily take the provider package.** `services/custom-example` is its own pnpm workspace. It routes the whole `@appliedblockchain` scope to GitHub Packages, so it cannot install the public `@appliedblockchain/silentdatarollup-*` packages from npmjs (`packages/connector/README.md`).
- **The bundler's user operation lookup decodes the bundle transaction.** `services/bundler/src/lookup.ts` `byHash` decodes `handleOps` from `eth_getTransactionByHash`. On Silent Data, an unsigned reader gets `input: 0x` and `to: 0xFF…FF`, so `decodeFunctionData` throws.
- **Test fixtures deploy through `deploy:cli testing`** under `giano.test.*` labels, with CREATE3 and the class deployer. This applies to local chains and testnets only (R-29).
- **Solidity dependencies** are Forge libraries pinned in `foundry.lock`, or copies under `packages/contracts/vendor/`. UCEF (`appliedblockchain/ucef-contracts`, public, MIT, commit `03913b1`) depends on OpenZeppelin, which `packages/contracts` already has.
- **Platform chain reads** (`services/wallet-api/src/services/rpc-read-relay.ts`) forward `eth_getStorageAt` and allow log spans of up to `PLATFORM_RPC_MAX_LOG_BLOCKS` blocks, counted inclusively. That limit defaults to 10,000 and may be set as low as 9,000. The log fallback uses spans of 9,000 blocks, so it passes through the relay at any allowed setting.

## Goals / Non-Goals

**Goals:**

- Each restriction is handled by a per-chain setting or by a fallback that runs only when a call fails. A chain without restrictions behaves exactly as before.
- No new code path checks for "Silent Data" by name, and nothing is a separate build (BR-08, R2).
- Gasless and gas-charging Silent Data chains run on the same code and the same settings. The only difference is the base fee the chain reports. `stateOverride: false` and `--signed-rpc` depend on the gateway, not on the fee.
- The demo proves the privacy properties against the real gateway: a balance only the holder can read, and transactions that outsiders see redacted.

**Non-Goals:**

- Signed reads in wallet-api, wallet-web or the bundler. No current feature needs them, and a service that signs reads with its own key would see, and could leak, data the chain hides.
- Detecting restrictions automatically at run time (see Decision 2).

## Decisions

### 1. Read the proxy implementation from `Upgraded` logs only when the storage read fails

`proxyImplementation` tries `eth_getStorageAt` first. If the RPC refuses that method (`isMethodRefusedError`: code -32601, -32004 or 4200, or a "method not whitelisted / not allowed" message) and the client can read logs, it walks back from `latest` in spans of 9,000 blocks. It returns the implementation from the newest `Upgraded` event. Any other storage-read error, such as a timeout or a rate limit, is raised unchanged.

- *Bounds:* the walk stops at an optional `fromBlock` (the proxy's deployment block, where the caller knows it). One read sends at most `maxChunks` requests (default 1,000, that is 9,000,000 blocks), so a wrong address does not walk to block 0 in one read. `maxChunks` must be a non-negative safe integer. A read that reaches the limit throws, and the next read through the same client continues the search from where it stopped.
- *Repeated reads:* the result is kept per client object, per proxy and per `fromBlock`, up to a checkpoint 64 blocks behind the head. A later read on the same client searches only the blocks after the checkpoint. The console's health check reads on every block, so this normally keeps it at one `eth_getLogs` per refresh. An upgrade newer than the checkpoint is returned but not kept, so a reorganisation cannot leave a removed upgrade behind. A head below the checkpoint starts the walk again. The head is read uncached, and concurrent reads share one walk.
- *Unverified answer:* the newest `Upgraded` event is not proof of the slot. `upgradeToAndCall` delegatecalls the new implementation, and any implementation the upgrader installs can emit an `Upgraded` event from the proxy that names a known release. Silent Data refuses `eth_getStorageAt`, so no better read exists. `proxyImplementationWithSource` therefore reports the source, and wallet-api's chain check and `giano-doctor` report a log answer as a warning: read from `Upgraded` logs, not verified against the implementation slot. The chain is still served. wallet-api logs the warning at boot, and again when the background probe admits the chain later. The paymaster SDK's `readImplementationWithSource` passes the source to `getHealth`, and the console's Health, which then report a release there as a warning, not a pass. The deploy tooling (`contracts:deploy`, `deploy:cli core`, `contracts:provision`, `contracts:sponsorship`) refuses a log answer, and does not reconcile the deployment record to it, unless the operator passes `--accept-unverified-implementation`; with the flag it prints the warning. The Helm deployer Job passes the flag when `deployer.acceptUnverifiedImplementation` is `true`. After `contracts:deploy` deploys the paymaster proxy itself, it accepts the log answer without the flag only when the proxy's sole `Upgraded` event, up to the head, is the one in its deployment transaction and names the implementation the run deployed and verified (`onlyDeploymentUpgrade`). The release proxy and paymaster change the slot only with an `Upgraded` event, so that proves the slot. `contracts:provision` and `contracts:sponsorship` print each check, with its warning, before they continue or stop.

- *Why:* the storage slot stays the source of truth wherever it is readable. ERC-1967 requires the `Upgraded` event on every change, and a UUPS proxy emits it at construction and on each upgrade, so the newest event names the current implementation.
- *Alternative:* add a per-chain `storageReads: false` setting. Rejected, because the fallback needs no configuration and cannot give a wrong answer on a chain that allows storage reads.

### 2. `bundler.stateOverride` is an explicit per-chain setting

With `false`, the bundler returns fixed limits and does not simulate.

- *Why:* a refused simulation is the only gas signal the bundler has. If the bundler fell back automatically on any override error, a real simulation fault on a normal chain would turn into fixed limits instead of an error. An explicit setting keeps that error visible.
- *Fixed values:*
  - verification gas 1,000,000, enough for a passkey (P-256) validation plus wallet deployment;
  - call gas 300,000, or 1,000,000 at a fee of 0, where unused call gas costs nothing; a caller's own call gas is kept, at no less than 9,000;
  - paymaster verification gas 200,000.
- *Giano's wallet:* the fixed limits apply to a caller that sends none. Giano's wallet sends 800,000 verification gas for a passkey, and wallet-api's paymaster stub sends 150,000 paymaster verification gas; viem keeps both over the estimate. A first passkey operation needs at most about 630,000 verification gas, even without the P-256 precompile, and `FirstOperationGas.t.sol` fails CI if it reaches 700,000. The paymaster's validation stays under 60,000 (`Gas.t.sol`).
- *Cost of the fixed values:* EntryPoint v0.9 does not charge unused verification gas. It does charge for unused call gas: once more than 40,000 call gas is unused, it charges 10% of *all* the unused call gas, not only the part above 40,000. For example, a call that uses 30,000 of the fixed 300,000 is charged a further 27,000. The same penalty applies to unused paymaster postOp gas (`_getUnusedGasPenalty` in `EntryPoint.sol`). Size the caps on a gas-charging chain with both penalties included. On a gasless chain the over-reservation costs nothing. On a chain that charges gas, the prefund must cover the maxima, so a wallet that knows its call gas sends it.
- *Permanent:* the gateway refuses state overrides, and Giano expects no change to it. Fixed limits are the long-term approach on Silent Data, not a stopgap.

### 3. Accept a fee of 0 when the chain charges no gas

The simulation always prices gas at 1 wei, so the fee only matters at submission.

- *Why:* on a chain that charges no gas, a fee of 0 is the correct fee. The check reads the latest block's base fee, where blocks carry one, and `eth_gasPrice`: a chain whose gas price is above 0 would never mine a transaction at gas price 0. A base fee of 0 is not enough on its own, because a node can still require a tip (geth's `--txpool.pricelimit`), and `eth_gasPrice` then answers above 0. On an OP Stack chain the GasPriceOracle's L1 fee must also be 0: the executor pays the L1 fee, and only the operation's gas price repays it.
- *One check:* `chargesNoGas` in giano-contracts makes it for the bundler's estimator, the bundler's submitter, and wallet-api. wallet-api reads its own RPC and the bundler may read `bundler.rpcUrl`; the two can disagree only briefly while a chain's fee changes, and the result is then a refusal.
- wallet-api's `pm_getPaymasterData` makes the same check. Without it, the bundler would accept a fee-0 operation that wallet-api then refuses to sponsor. With fee 0 the gas part and the overhead of the maximum charge are 0, so the cap and the balance apply to the tenant fee alone.
- *Alternative:* a per-chain `gasless` setting. Rejected, because the base fee already says it, and a chain that later starts charging gas is handled without a configuration change.

### 4. Operator tools sign with the operator key, through `--signed-rpc`

- `deploy:cli` uses a viem transport that signs the exact HTTP body (`deploy/signed-rpc.ts`).
- `provision:paymaster` uses an ethers `FetchRequest` pre-flight hook. Its batch size is 1, so each body is signed on its own. Both build the headers with the one `signatureHeaders` in `deploy/signed-rpc.ts`, which refuses a body that is not a string.
- The operator commands (`contracts:deploy`, `contracts:provision`, `contracts:timelock`, `contracts:handoff`) take `--signed-rpc` and pass it on, so a Silent Data adoption keeps their profile checks and confirmations. The wizard signs with `CANONICAL_DEPLOYER_PRIVATE_KEY`.
- A command signs only what it sends from its key. A `handoff` plan only reads, so it goes unsigned and works where ROLE_ADMIN is a Safe.
- *Why:* the gateway keeps `from` only for a request signed by `from`. Both tools estimate role-gated calls, so they must sign.
- *Why opt-in:* the signature headers are harmless elsewhere, but signing every request costs time, and an explicit flag makes it clear which chains need it.
- *Alternative:* depend on `silentdatarollup-core` in `packages/contracts`. Rejected, because the signing scheme is small (40 lines) and the dependency brings ethers v6 provider classes into a package that uses viem for deployment.

### 5. `eth_getUserOperationByHash` answers `null` when the calldata is redacted

- *Why:* answering from the bundler's memory, or from a read signed with the executor key (the bundle transaction's sender), would give anyone who knows a hash the operation's calldata. On Silent Data, the calldata is the private part: recipients and amounts.
- *How:* a mined operation whose transaction input is `0x` (or does not decode as `handleOps`) answers `null`. The receipt still answers from `UserOperationEvent`, and wallets need only the receipt.

### 6. The demo signs Silent Data reads itself, with a delegate approved by the wallet

The private token section builds the gateway headers in a small module in the demo (viem only):

1. On the first signed read, the demo creates an ephemeral key in memory. It builds a ticket `{ expires: now + 1h, ephemeralAddress }`.
2. The wallet approves the ticket: `personal_sign` through the connector, over the bytes `keccak256(chainId + JSON(ticket))`. That is one passkey prompt.
3. Each read is sent with these headers:
   - `x-signer-swc: <wallet>`, `x-signer-swc-type: giano`;
   - `x-delegate`, `x-delegate-signature`;
   - `x-timestamp`, `x-signature` (EIP-191 signature by the ephemeral key of `chainId + body + timestamp`).

- *Why:* this keeps the demo on the published Giano surface (`personal_sign` only) and adds no package that the scope routing blocks. One prompt per hour matches "one approval per session".
- *Alternative:* add `@appliedblockchain/silentdatarollup-viem` to the demo through an `.npmrc` scope exception. Rejected for now, because a scope exception for one package is the deviation the connector README warns about.
- *Risk:* the wallet's `personal_sign` signature must be what the gateway's ERC-1271 check expects for a delegate ticket (see Risks). Task 4.1 proves this against the local gateway before any UI work.
- *Encoding (task 4.1, verified):* the dApp passes `keccak256(toBytes(chainId + JSON.stringify(ticket)))` to `personal_sign` as a `0x`-prefixed hex string. The wallet signs those 32 raw bytes, not their hex text (wallet-core `toPersonalMessageBytes`): its passkey signs `replaySafeHash(hashMessage(raw))`. The ticket JSON is exactly the `x-delegate` header value, with the keys `expires` (RFC 3339) and `ephemeralAddress`, in that order. Checked against the local gateway on anvil with a passkey-owned wallet: the delegate-signed `eth_call` ran with `CALLER` equal to the wallet. Passing the message itself as text is refused with HTTP 401 "Can not recover signer from signature".

### 7. The private test token is UCEF's `UCEFOwned` model, imported from a Forge library, with an open mint, and deployed from a committed artifact

- `packages/contracts/lib/ucef-contracts` is a git submodule of `appliedblockchain/ucef-contracts`, pinned to commit `03913b1` in `.gitmodules` and `foundry.lock`, like forge-std and solady.
- The token imports `UCEFOwned.sol` by its path under `lib/`, with no new remapping. solc records every remapping in the metadata hash of every contract, so a new remapping would change the bytecode of every release contract, not only the token's.
- A test contract `GianoTestPrivateErc20 is UCEFOwned` allows anyone to mint to themselves.
- It deploys under the label `giano.test.private-erc20` through `deploy:cli testing`, on chains whose profile enables it (`"privateTestErc20": true`), and on every local chain, so `local:deploy` deploys it on each run. A production chain's profile cannot enable it: a mainnet's, Base Sepolia's or Sepolia's (`isProductionChain`).
- No release carries it. Its creation code, runtime code and fingerprint are committed as `packages/contracts/fixtures/private-test-erc20.json`, generated from the Foundry build by `pnpm gen:fixtures`, and the deploy CLI deploys it from there, whatever the release. CI fails when the artifact does not match the source and the UCEF submodule (`pnpm gen:fixtures --check`). The deployer image ships the artifact, as it ships `vendor/createx`. A deployment record names its release as `fixture` and carries the artifact's fingerprint, which `gen:addresses` checks.
- *Why a committed artifact rather than a release:* a release is what every chain of a class is adopted at, forever, and it also freezes the wallet, factory and paymaster changes made since the last one. The token exists only for the demo (H6 R3, R4), so it must not wait for a release, and no release should carry it. A testnet still cannot compile anything at deploy time, because the deployer image has no forge and no solc, so the code has to be committed.
- *Versions:* a chain keeps the code it was deployed with, and its address depends only on the label. So the artifact keeps the fingerprints of its earlier versions (`previous`, newest first): when the code changes, `pnpm gen:fixtures` moves the fingerprint of the artifact at git HEAD there. A testnet that holds an earlier version still matches, in `gen:addresses` and in a re-run of `testing`; a new chain gets the current code. Any change to the source changes the code, even a comment, because solc appends the metadata hash.
- *Release builds:* `release:cut` and `release:status` skip the fixture sources (`forge build --skip`), so a release's `standard-input.json` carries neither the token nor UCEF.
- *Known leak:* UCEF's `totalSupply()` is public, and every mint changes it. Comparing it before and after a block shows the amounts minted, and while one account holds the whole supply, it is that account's balance. The demo does not read it. The token's NatSpec and `fixtures/README.md` say so.
- *Why a Forge library rather than a copy or the npm package:* `ucef-contracts` is public, so CI fetches the submodule without credentials, and Giano keeps no second copy of the sources. The npm package `@appliedblockchain/ucef-contracts` 0.1.1 (February 2026) is older than commit `03913b1`.
- *Why opt-in per chain:* on a public chain, the token's privacy is not enforced, because anyone can read storage and the calldata. A demo showing "private" there would mislead.

### 8. Both Silent Data testnets are adopted, one of each kind

The two chains, as read from their public RPC on 2026-11-16:

| | copper-heron | iron-kestrel |
|---|---|---|
| Chain ID | 19877 | 19874 |
| Base fee / gas price | 0 / 0 | 251 wei / about 0.001 gwei |
| OP Stack (GasPriceOracle predeploy) | no | yes |
| CreateX, Arachnid factory | absent | present |
| EntryPoint v0.9 | absent | absent |
| `eth_getStorageAt` | refused | refused |
| `eth_call` state override | refused | refused |
| Unsigned `eth_call` `from` | rewritten | rewritten |

- *Why both:* together they cover every combination this change handles: gasless and gas-charging, and an L1 data fee or none, under the same gateway. Giano's code makes no distinction between them. The base fee and `chainType: auto` decide the rest.
- *Same addresses:* both chains are in the testnet class and use the same canonical deployer, so they get the same contract addresses and the same wallet address for a passkey (MC-16). Task 9.2 checks the wallet address on both chains.

### 9. Adoption follows `specs/CHAIN-ADOPTION.md` unchanged, with two new notes

- `bundler.stateOverride: false` and `bundler.rpcUrl` set to the write URL. That URL holds a token, so it lives only in the `chains` secret.
- `--signed-rpc` on `core` and `provision:paymaster`.

## Risks / Trade-offs

- **[Risk]** The wallet's `personal_sign` signature over the ticket hash may not verify in the gateway's ERC-1271 path. The gateway may expect the raw hash where the wallet signs an EIP-191 hash, or the reverse. → Task 4.1 checks it first, against the local gateway on anvil. If it fails, the fix belongs in the demo's message encoding, not in the wallet contract or the gateway.
- **[Risk]** ERC-1271 needs deployed wallet code, so a counterfactual wallet cannot sign reads. → The demo's mint is the wallet's first operation and deploys it. Before that, the section says "deploy the wallet first", and no read is attempted.
- **[Risk]** The first `Upgraded` log walk costs one `eth_getLogs` per 9,000 blocks since the last upgrade. At 2-second blocks that is about 5 requests per day of age. → Later reads on the same client walk only the new blocks. One read gives up after 1,000 requests (about 208 days at 2-second blocks) with an error, and the next read through the same client continues the search further back. wallet-api's chain check sends at most 100 requests per check (`PAYMASTER_LOG_REQUESTS_PER_CHECK`), and the check at boot, which runs before the server listens, at most 10 (`PAYMASTER_LOG_REQUESTS_AT_BOOT`), so a long search cannot delay `/healthz` past the liveness probe. A check that stops there leaves the chain unavailable, and the background probe's next check, through the same client, continues the search until it finds the event. A one-shot caller, such as `giano-doctor`, does not resume.
- **[Risk]** On a gas-charging chain, the fixed limits raise the maximum charge. wallet-api's `computeMaxCost` adds every limit and multiplies by `maxFeePerGas`. With the fixed limits, the total is about 1.5 million gas plus pre-verification gas, compared with about 0.4 million for a simulated ETH transfer. The tenant reservation is about 4 times larger, and an operation can hit the tenant's `maxCostPerTxWei` or the platform's wallet-management cap where a simulated one would not. Settlement still charges what the paymaster's `Sponsored` event records (gas cost, fee and overhead), not the maximum. → `specs/CHAIN-ADOPTION.md` tells the operator to size the caps and the tenant balances for the fixed limits on such a chain (task 3.5). Task 2.8 checks the refusal and the settlement. Wallets that know their call gas send it, which lowers the maximum.
- **[Risk]** On a gas-charging chain, the bundler executor pays for every bundle, and the paymaster deposit must cover each operation's prefund from the fixed limits. → The usual per-chain monitoring applies: `giano_bundler_executor_balance_wei` and the paymaster low-balance alert. The gateway does not restrict `eth_getBalance` or `eth_getTransactionCount` (it restricts only `eth_getProof`), so both monitors work unsigned.
- **[Risk]** Fixed gas limits can be too low for an unusual call. The operation then reverts on chain, and on a gas-charging chain it costs the reserved gas. → The caller's call gas is kept when sent. The limits are named constants in the estimator, so they are easy to change.
- **[Risk]** With `stateOverride: false` the bundler skips every simulation, not only the gas measurement. It loses the call-revert probe and the `simulateValidation` run at the real fee, because both run `EntryPointSimulations` through a state override. So a user operation whose call reverts, or whose account cannot pay its prefund, now passes estimation. → A prefund failure is still refused at `eth_sendUserOperation`: the submitter checks `handleOps` with `eth_estimateGas` against the real EntryPoint, with no override (`submitter.ts`), so nothing is sent. A reverting call is not caught, because `handleOps` does not revert when the inner call reverts. The operation is included with `success: false`, and on a gas-charging chain it costs the gas used plus the unused-call-gas penalty. Recorded, not solved here.
- **[Trade-off]** The bundler's public endpoints and wallet-api's records still hold user operation calldata (recipients, amounts) before inclusion. On Silent Data, the operator therefore sees what the chain hides from outsiders. → Recorded, not solved here. It is inherent to an ERC-4337 bundler, and it is the same trust the Skandha bundler needs. The integration guide should state it.
- **[Trade-off]** Copper-heron cannot be adopted until the testnet canonical deployer key exists. → Shared blocker with Base Sepolia and Ethereum Sepolia. This change does not work around it with a deviation.

## Migration Plan

The work ships as one stack of PRs, listed at the top of `tasks.md`. It merges bottom-up with `gh stack merge`, which merges every PR up to the one chosen in one operation.

1. Merge PR 0, the plan, at the bottom of the stack.
2. Merge PRs 1, 2 and 3, the next three layers. With defaults, nothing changes on existing chains: `stateOverride` defaults to `true`, the log fallback runs only on a refused storage read, and `--signed-rpc` is opt-in. Each PR carries its own changeset.
3. Release `giano-contracts` and `giano-paymaster-sdk` from the merged changesets. Bump the bundler and wallet-api images.
4. Merge PR 4 (the private test token) and PR 5 (the demo section), the next two layers.
5. When the testnet key exists, add PR 6a to the top of the stack: adopt iron-kestrel per `specs/CHAIN-ADOPTION.md`, and commit `deployments/19874.json`. When the copper-heron presigned senders are also funded, add PR 6b on top of it and commit `deployments/19877.json`.
6. After each adoption PR merges, release `giano-contracts` from its changeset, so the published `addresses.ts` lists the new chain. Then add that chain's entry to the dev `chains` secret, and add `privateToken` to the demo's chain list.
7. Rollback: revert the PR, or remove the chain's entry from the `chains` secret and the demo's chain list. Other chains are unaffected.

## Open Questions

None.
