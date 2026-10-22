# giano-bundler

Giano's own ERC-4337 submission service, replacing the pinned Pimlico Alto it was a drop-in for.
It is deliberately not a general-purpose bundler: there is no mempool, no bundling and no
peer-to-peer network. Every user operation it accepts is sent at once as its own
`EntryPoint.handleOps([op], executor)` transaction. EntryPoint v0.7 only.

The only client is wallet-api (`BUNDLER_URL` / `bundlerUrl` in `GIANO_CHAINS`), which applies
policy, audit and rate limits before anything reaches here. The bundler is never exposed to a
browser.

## JSON-RPC

The same methods, parameters, result shapes and error codes wallet-api used with Alto. Any POST
path is the endpoint.

| Method | Behaviour |
| --- | --- |
| `eth_chainId`, `eth_supportedEntryPoints` | From configuration and the chain. |
| `eth_estimateUserOperationGas` `[op, entryPoint]` | Simulation-based (below). Always returns all five gas fields as hex. State overrides are refused. |
| `eth_sendUserOperation` `[op, entryPoint]` | Checks, simulates against the real EntryPoint, broadcasts, then returns the hash. |
| `eth_getUserOperationReceipt` `[hash]` | Alto's receipt shape. `null` while pending. |
| `eth_getUserOperationByHash` `[hash]` | Alto's shape, decoded from the `handleOps` input. `null` while pending. |

Receipts come from the chain: an operation this process submitted is found by its transaction,
any other by its `UserOperationEvent` in the last `BUNDLER_MAX_BLOCK_RANGE` blocks. Lookups
therefore survive a restart.

`GET /health` reports the chain, the EntryPoint, the executors and the number of operations in
flight. `GET /metrics` serves Prometheus metrics (`giano_bundler_*`), including each executor's
balance. Nothing listens until the RPC answers and the EntryPoint has code, so the healthcheck
(`eth_supportedEntryPoints`) fails until then.

## How it works

**Estimation.** The EntryPoint's code is swapped for the eth-infinitism `EntryPointSimulations`
in an `eth_call` state override, so simulation runs against the real EntryPoint's storage and
needs nothing deployed. The bytecode is generated from the pinned
`@account-abstraction/contracts@0.7.0` (`pnpm generate`; a test fails if it drifts). The SenderCreator
is overridden too, because devnets whose EntryPoint was installed with `anvil_setCode` lack one.

- Simulations price the operation at 1 wei per gas, so the EntryPoint's `paid` is in gas units and
  execution gas follows exactly from v0.7's 10% unused-gas penalty.
- `verificationGasLimit` is the measured validation gas plus 30%.
- `callGasLimit` is the measured execution plus 10%. It is re-simulated at that limit to catch calls
  that need more than they use, and raised if they do.
- Paymaster gas limits the caller supplied (Giano's ERC-7677 stub always does) are kept.
- A second simulation runs the call on its own, so an operation that would revert is reported
  during estimation with its reason (`-32521`).
- A final `simulateValidation` at the real price catches an account that cannot pay its prefund
  (AA21) or a paymaster deposit that cannot cover it (AA31).

**preVerificationGas** is the calldata-and-overhead formula Alto used (21 000 + 18 300 per
operation + calldata), plus 10%. During estimation it sizes the signature and paymaster data
generously, as Alto did, because a real WebAuthn signature is longer than the stub. On an
OP-stack chain (auto-detected from the GasPriceOracle predeploy) it adds the L1 data fee, converted
to L2 gas at the operation's price, plus 25%.

**Submission** runs these checks before anything is sent:

- `preVerificationGas` covers the exact recomputation for the real signature.
- `maxFeePerGas` is at least the current base fee.
- `eth_estimateGas` of `handleOps` from the executor passes against `latest`. That is the real
  EntryPoint and the real state, so a transaction that would revert is never sent. Failures map to
  Alto's codes: `-32500` validation, `-32501` paymaster, `-32503` time range, `-32507` signature,
  `-32602` nonce.

The transaction is priced at the operation's own `maxFeePerGas` and `maxPriorityFeePerGas`. The
EntryPoint then reimburses the executor at exactly the price it paid, with `preVerificationGas`
covering the gas it does not meter. The integration test asserts that the executor is never out
of pocket.

**Executor lanes.** Each executor key holds at most one transaction in flight, so its nonce never
has a gap. Several keys (comma-separated) give several parallel lanes, and operations wait for a
free lane. A transaction unmined after `BUNDLER_RESUBMIT_TIMEOUT_SECONDS` is re-simulated and
re-priced (+15%), up to `BUNDLER_MAX_REPLACEMENTS` times. After that, or as soon as it stops
validating, the nonce is cancelled with a zero-value self-transfer, and the operation is reported
dropped. If the original is mined first instead, its receipt is still found.

**Ordering.** The next nonce of an operation still in flight (same sender and key) is accepted and
held until its predecessor lands. A second operation with the same sender and nonce is refused, as
Alto did. A resubmission of an operation it already has returns the same hash.

## What it does not do

- **No ERC-7562 validation tracing** (Alto's `--safe-mode`). That tracing protects a shared
  mempool from operations that pass simulation and fail on chain. Here each operation is simulated
  against the real EntryPoint immediately before its own transaction, so the RPC needs
  `eth_call` state overrides but never `debug_traceCall`. One consequence: nothing in Giano's own
  stack checks that account and paymaster validation stays ERC-7562-compliant, which is what a
  public bundler would require.
- **No stake or reputation checks**, and no bundling of several operations into one transaction.
- **No utility key.** Nothing is deployed at boot and executors are not refilled automatically:
  fund them, and watch `giano_bundler_executor_balance_wei`.
- **One replica per executor key.** Lanes are tracked in memory. ECS (no ALB, 0%/100%) and the Helm
  chart (`Recreate`) stop the old task before starting the new one.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `BUNDLER_RPC_URL` | — | Required. Must support `eth_call` state overrides. |
| `BUNDLER_EXECUTOR_PRIVATE_KEYS` | — | Required. Comma-separated; one lane each. Must be funded. |
| `BUNDLER_ENTRYPOINT` | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | Exactly one, v0.7. |
| `BUNDLER_PORT` / `BUNDLER_HOST` | `4337` / `0.0.0.0` | |
| `BUNDLER_CHAIN_TYPE` | `auto` | `default` or `op-stack` to override detection. |
| `BUNDLER_MAX_BLOCK_RANGE` | `2000` | Receipt lookback for operations this process did not submit. |
| `BUNDLER_RESUBMIT_TIMEOUT_SECONDS` | `30` | |
| `BUNDLER_MAX_REPLACEMENTS` | `3` | |
| `BUNDLER_POLL_INTERVAL_MS` | `1000` | |
| `BUNDLER_LOG_LEVEL` | `info` | |
| `GIANO_DEV_MODE` | `false` | Must be `true` to start with the well-known Anvil key. |

For a drop-in upgrade, Alto's `ALTO_RPC_URL`, `ALTO_EXECUTOR_PRIVATE_KEYS`, `ALTO_ENTRYPOINTS` and
`ALTO_PORT` are still read, with a deprecation warning. `ALTO_SAFE_MODE` and
`ALTO_UTILITY_PRIVATE_KEY` are accepted and ignored.

## Development

```sh
pnpm -F @appliedblockchain/giano-bundler test       # unit + anvil integration (needs `anvil` on PATH)
pnpm -F @appliedblockchain/giano-bundler typecheck
pnpm -F @appliedblockchain/giano-bundler generate   # regenerate src/generated/simulations.ts
docker build -f services/bundler/Dockerfile -t ghcr.io/appliedblockchain/giano-bundler .
```

The integration suite starts its own anvil. It installs the EntryPoint the way the e2e devnet
does, deploys a SimpleAccount factory and a VerifyingPaymaster, and drives the JSON-RPC surface as
wallet-api does. It covers deployment by the first operation, sponsorship, rejections,
idempotency, lookups after a restart, and re-pricing and cancellation with automine off. The e2e
suite exercises the real path: GianoSmartWallet, WebAuthn and the production paymaster.
