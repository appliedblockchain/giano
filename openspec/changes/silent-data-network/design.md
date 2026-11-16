# Design

## Context

See proposal.md (Why) for the gateway restrictions. More facts that shape the approach:

- **The gateway already knows Giano wallets.** `private-rollup/services/custom-rpc` verifies a signed request from a smart wallet: the `x-signer-swc` header, then ERC-1271 on the wallet. For type `giano` (the default), it wraps the hash in Giano's EIP-712 domain, `Giano Smart Wallet`, version `1`. That domain matches `GianoSmartWallet._domainNameAndVersion()`. With `x-signer-swc`, the gateway sets the call's `from` to the wallet. A delegate ticket can also be approved by the wallet, and then an ephemeral key signs each request.
- **Delegate signing exists in the providers.** `silentdatarollup-core` (`Base.ts`) implements it with `smartWalletAddress` and `smartWalletType: 'giano'`. The delegate message is `chainId + JSON(ticket)`. For a smart wallet, the client signs `keccak256` of that message as bytes through `signMessage`.
- **The demo cannot easily take the provider package.** `services/custom-example` is its own pnpm workspace. It routes the whole `@appliedblockchain` scope to GitHub Packages, so it cannot install the public `@appliedblockchain/silentdatarollup-*` packages from npmjs (`packages/connector/README.md`).
- **The bundler's user operation lookup decodes the bundle transaction.** `services/bundler/src/lookup.ts` `byHash` decodes `handleOps` from `eth_getTransactionByHash`. On Silent Data, an unsigned reader gets `input: 0x` and `to: 0xFF…FF`, so `decodeFunctionData` throws.
- **Test fixtures deploy through `deploy:cli testing`** under `giano.test.*` labels, with CREATE3 and the class deployer. This applies to local chains and testnets only (R-29).
- **Solidity dependencies** are Forge libraries pinned in `foundry.lock`, or copies under `packages/contracts/vendor/`. UCEF (`appliedblockchain/ucef-contracts`, MIT, commit `03913b1`) depends on OpenZeppelin, which `packages/contracts` already has.
- **Platform chain reads** (`services/wallet-api/src/services/rpc-read-relay.ts`) forward `eth_getStorageAt` and allow log spans of up to 10,000 blocks. The paymaster SDK's log fallback uses spans of exactly 10,000 blocks, so it passes through the relay.

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

`proxyImplementation` tries `eth_getStorageAt` first. If that fails and the client can read logs, it walks back from `latest` in spans of 10,000 blocks. It returns the implementation from the newest `Upgraded` event.

- *Why:* the storage slot stays the source of truth wherever it is readable. ERC-1967 requires the `Upgraded` event on every change, and a UUPS proxy emits it at construction and on each upgrade, so the newest event names the current implementation.
- *Alternative:* add a per-chain `storageReads: false` setting. Rejected, because the fallback needs no configuration and cannot give a wrong answer on a chain that allows storage reads.

### 2. `bundler.stateOverride` is an explicit per-chain setting

With `false`, the bundler returns fixed limits and does not simulate.

- *Why:* a refused simulation is the only gas signal the bundler has. If the bundler fell back automatically on any override error, a real simulation fault on a normal chain would turn into fixed limits instead of an error. An explicit setting keeps that error visible.
- *Fixed values:*
  - verification gas 1,000,000, enough for a passkey (P-256) validation plus wallet deployment;
  - call gas 300,000;
  - paymaster verification gas 200,000.
- *Cost of the fixed values:* EntryPoint v0.9 does not charge unused verification gas. It charges 10% of unused call gas above 40,000. On a gasless chain the over-reservation costs nothing. On a chain that charges gas, the prefund must cover the maxima, so a wallet that knows its call gas sends it.
- *Alternative:* the gateway accepts state overrides. That is Silent Data's decision and a gateway change. If they make it, the chain entry drops `stateOverride: false` and nothing else changes.

### 3. Accept a fee of 0 when the base fee is 0

The simulation always prices gas at 1 wei, so the fee only matters at submission.

- *Why:* on a chain with base fee 0, a fee of 0 is the correct fee. The check now reads the latest block's base fee.
- *Alternative:* a per-chain `gasless` setting. Rejected, because the base fee already says it, and a chain that later starts charging gas is handled without a configuration change.

### 4. Operator tools sign with the operator key, through `--signed-rpc`

- `deploy:cli` uses a viem transport that signs the exact HTTP body (`deploy/signed-rpc.ts`).
- `provision:paymaster` uses an ethers `FetchRequest` pre-flight hook. Its batch size is 1, so each body is signed on its own.
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

### 7. The private test token is UCEF's `UCEFOwned` model, copied into `vendor/`, with an open mint

- `packages/contracts/vendor/ucef/` holds `UCEF.sol`, `UCEFOwned.sol` and the interfaces they import, from commit `03913b1`, with the MIT licence and a README naming the commit.
- A test contract `GianoTestPrivateErc20 is UCEFOwned` allows anyone to mint to themselves.
- It deploys under the label `giano.test.private-erc20` through `deploy:cli testing`, on chains whose profile enables it.
- *Why vendor rather than a Forge library:* `ucef-contracts` is an organisation repository, so a Forge submodule needs repository access in CI. Three files under MIT are easy to review in a copy.
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

- **[Risk]** The wallet's `personal_sign` signature over the ticket hash may not verify in the gateway's ERC-1271 path. The gateway may expect the raw hash where the wallet signs an EIP-191 hash, or the reverse. → Task 4.1 checks it first, against the local gateway on anvil. If it fails, the fix belongs in the demo's message encoding or in the gateway's `giano` type, not in the wallet contract.
- **[Risk]** ERC-1271 needs deployed wallet code, so a counterfactual wallet cannot sign reads. → The demo's mint is the wallet's first operation and deploys it. Before that, the section says "deploy the wallet first", and no read is attempted.
- **[Risk]** The `Upgraded` log walk costs one `eth_getLogs` per 10,000 blocks since the last upgrade. At 2-second blocks that is about 4 requests per day of age, and about 1,600 after a year. wallet-api runs it at boot and on each chain check. → Acceptable for now. If it becomes slow, a later change can bound the walk by the proxy's deployment block from the deployment record.
- **[Risk]** On a gas-charging chain, the fixed limits raise the maximum charge. wallet-api's `computeMaxCost` adds every limit and multiplies by `maxFeePerGas`. With the fixed limits, the total is about 1.5 million gas plus pre-verification gas, compared with about 0.4 million for a simulated ETH transfer. The tenant reservation is about 4 times larger, and an operation can hit the tenant's `maxCostPerTxWei` or the platform's wallet-management cap where a simulated one would not. Settlement still charges what the paymaster's `Sponsored` event records (gas cost, fee and overhead), not the maximum. → `specs/CHAIN-ADOPTION.md` tells the operator to size the caps and the tenant balances for the fixed limits on such a chain (task 3.5). Task 2.8 checks the refusal and the settlement. Wallets that know their call gas send it, which lowers the maximum.
- **[Risk]** On a gas-charging chain, the bundler executor pays for every bundle, and the paymaster deposit must cover each operation's prefund from the fixed limits. → The usual per-chain monitoring applies: `giano_bundler_executor_balance_wei` and the paymaster low-balance alert. The gateway does not restrict `eth_getBalance` or `eth_getTransactionCount` (it restricts only `eth_getProof`), so both monitors work unsigned.
- **[Risk]** Fixed gas limits can be too low for an unusual call. The operation then reverts on chain, and on a gas-charging chain it costs the reserved gas. → The caller's call gas is kept when sent. The limits are named constants in the estimator, so they are easy to change.
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

- Does the Silent Data team plan to accept `eth_call` state overrides in the gateway? If so, both chains can drop `stateOverride: false` and get simulated estimates. No change to this design.
- Who funds the two presigned senders on copper-heron (0.01 ETH and 0.3 ETH)? Only the date of group 7 depends on it.
