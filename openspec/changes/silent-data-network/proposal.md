## Why

BR-08 says Giano MUST run on Silent Data Rollup as a first-class target, with no forked or variant build. Ticket H6 asks for that: Giano works on Silent Data (R1), the dev environment treats Silent Data as just another network (R2), the demo app has a Silent Data section (R3), and the demo uses a private ERC-20 to show that the privacy properties hold (R4).

Silent Data puts a gateway (the custom-rpc service) in front of its node, and that gateway restricts the JSON-RPC API. Tested locally against the gateway's published package, five restrictions break Giano as it is on `main`:

- `eth_getStorageAt` is blocked. The wallet-api boot check, `giano-doctor` and the paymaster SDK all read the paymaster proxy's implementation slot.
- `eth_call` with a state override (the third parameter) is refused. The bundler estimates gas by placing the EntryPoint simulation code with a state override.
- On an unsigned `eth_call` or `eth_estimateGas`, the gateway replaces `from` with a random address. `provision:paymaster` and `deploy:cli` estimate role-gated calls, so they fail with `AccessControlUnauthorizedAccount`.
- Receipts and transactions are redacted for a reader who is not the sender: `from` reads `0x0`, `to` reads `0xFF…FF`, and `gasUsed` reads `0`.
- `eth_getLogs` spans are limited to 10,000 blocks.

Silent Data chains come in two kinds, and Giano must work on both with the same build and the same settings:

- **Gasless chains**, such as copper-heron (chain 19877), with a base fee of 0 and a gas price of 0. Copper-heron is not OP Stack. The bundler refused a user operation with a fee of 0, although nothing on that chain charges for gas.
- **Gas-charging chains**, such as iron-kestrel (chain 19874), with a base fee of 251 wei and a gas price of about 0.001 gwei. Iron-kestrel is OP Stack, so it also charges an L1 data fee. The gateway restrictions are the same as on copper-heron (checked read-only on 2026-11-16). Gas is real, so the paymaster deposit, the tenant balances and the sponsorship caps must cover the gas limits the bundler returns.

## What Changes

Already implemented on branch `feat/silent-data-network` (uncommitted):

- The paymaster proxy's implementation is read from its latest ERC-1967 `Upgraded` event when `eth_getStorageAt` fails. This is used in `erc1967.ts` (new exports `implementationFromUpgradedLogs`, `proxyImplementation`, `UPGRADED_TOPIC`), in `giano-doctor` and in the paymaster SDK. The log walk uses spans of 10,000 blocks.
- A chain's `bundler` section gains `stateOverride` (default `true`). With `false`, the bundler does not simulate. It returns fixed gas limits. It keeps the call gas a caller sends, and a higher verification gas.
- The bundler accepts a fee of 0 at estimation when the chain's base fee is 0.
- `deploy:cli` and `provision:paymaster` gain `--signed-rpc`. Each request after the chain id read is signed with the deploying key, so the gateway keeps `from`.
- A changeset: `giano-contracts` minor, `giano-paymaster-sdk` patch. It is split into one changeset per PR before the PRs open.

The work ships as one stack of PRs, merged bottom-up: the plan, three fix PRs, the private token, the demo, and one adoption PR per chain. `tasks.md` lists them.

Still to do:

- Make the bundler's `eth_getUserOperationByHash` answer `null` when the bundle transaction's calldata is redacted. Today it fails to decode `0x` and returns an error.
- Adopt both Silent Data testnets per `specs/CHAIN-ADOPTION.md`, at the same testnet-class addresses:
  - copper-heron (19877): CreateX and the Arachnid factory from their presigned keyless transactions, then EntryPoint v0.9;
  - iron-kestrel (19874): CreateX and the Arachnid factory are already there, so only EntryPoint v0.9 is needed;
  - on each chain: `core`, `testing`, `provision:paymaster`, `giano-doctor`, a `GIANO_CHAINS` entry in the dev environment, and one sponsored transaction.
- Add the Silent Data section to the demo app (R3). For a chain that names a private token, it shows the token balance the wallet can read with a signed request, and shows that an unsigned read is refused.
- Add a private test ERC-20 (UCEF, `UCEFOwned` model) as a test fixture, deployed on Silent Data chains (R4).
- Document the restrictions in `specs/CHAIN-ADOPTION.md`: RPCs without state overrides or `eth_getStorageAt`, and when to set `stateOverride: false` and `--signed-rpc`.

Decided:

- Giano uses its own bundler (`services/bundler`) on Silent Data. It does not use the Skandha bundler in `private-rollup`. That bundler runs EntryPoint v0.6, and Giano's wallet implementation hardcodes EntryPoint v0.9.
- Silent Data is configured like any other chain, through `GIANO_CHAINS`. No component checks for "Silent Data" by name. Each restriction is a per-chain setting or a fallback that any chain can use.

**Non-goals:**

- Signed reads in wallet-api and wallet-web. Their reads that the gateway restricts (receipts, the implementation slot) already have a public alternative, the `UserOperationEvent` log and the `Upgraded` log.
- Changes to the Skandha bundler or the paymaster in `private-rollup`. Retiring them is the Silent Data team's decision.
- Simulated gas estimation on Silent Data. The gateway refuses state overrides, so this needs a gateway change, which Silent Data owns.
- Creating the testnet canonical deployer key. That is a team action, shared with the Base Sepolia and Ethereum Sepolia adoption, and this change only depends on it.

## Capabilities

### New Capabilities

- `restricted-chain-support`: how Giano's bundler, wallet-api checks and operator tools behave against a chain whose RPC restricts reads (no storage reads, no state overrides, a rewritten `from`, redacted receipts, bounded log spans) or that charges no gas.

### Modified Capabilities

- `demo-dapp`: adds the Silent Data section, which shows a private token balance read by the wallet itself and a refused unsigned read.
- `demo-deployment`: a chain entry gains an optional `privateToken` address. The Silent Data section appears only for a chain that names one.
- `test-erc20-registry`: adds a private test token, deterministic per network class, on chains that enforce private reads.

## Impact

- **Code (done):**
  - `packages/contracts/erc1967.ts`, `scripts/doctor.ts`, `scripts/provision-paymaster.ts`, `chains.ts`, `deploy/cli.ts`, new `deploy/signed-rpc.ts`;
  - `packages/paymaster-sdk/src/client.ts`;
  - `services/bundler/src/{config,estimator,registry}.ts`.
- **Code (to do):**
  - `services/custom-example` (the demo);
  - a UCEF test token under `packages/contracts`;
  - the `testing` deployment.
- **Dependencies:**
  - The UCEF Solidity sources (MIT, `appliedblockchain/ucef-contracts`), vendored at a pinned commit.
  - The demo needs a client that signs Silent Data requests for a smart wallet (`x-signer-swc`). `@appliedblockchain/silentdatarollup-core` has one. The GitHub Packages scope caveat in `packages/connector/README.md` applies.
- **Configuration:** a `GIANO_CHAINS` entry for 19877 and one for 19874. Each sets `bundler.rpcUrl` to that chain's write URL (which carries a token) and `bundler.stateOverride: false`. The `chains` secret holds them.
- **Blocked:** contract deployment on both chains waits for the testnet canonical deployer key (`DEPLOYERS.testnet` is `null`). Copper-heron also waits for someone to fund the two presigned senders: 0.01 ETH for Arachnid and 0.3 ETH for CreateX.
- **Docs:** `specs/CHAIN-ADOPTION.md`, `packages/contracts/README.md`, `services/bundler` README.
- **Integrators:** no breaking change. `stateOverride` defaults to `true`, and `--signed-rpc` is opt-in.
