# @appliedblockchain/giano-wallet-api

## 0.2.0

### Minor Changes

- 6552edc: Two JSON-RPC relays so a wallet origin never dials a node or a bundler. `POST /v1/bundler/:chainId`
  (session-bound): `eth_sendUserOperation` through the same policy, audit-log, idempotency and
  rate-limit pipeline as `POST /v1/userops`; `eth_estimateUserOperationGas` bound to the session
  wallet; receipt lookups forwarded; `eth_chainId` / `eth_supportedEntryPoints` answered from
  configuration. `POST /v1/rpc/:chainId` (tenant-bound by `Origin`): read-only allowlisted `eth_*`
  methods forwarded to the configured node, so a keyed provider URL stays server-side. New env
  `BUNDLER_RELAY_RATE_LIMIT_PER_MINUTE` (600) and `RPC_RELAY_RATE_LIMIT_PER_MINUTE` (3000); new
  metrics `giano_bundler_relay_requests_total` and `giano_rpc_relay_requests_total`. Additive — no
  existing endpoint or variable changes.

### Patch Changes

- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
  - @appliedblockchain/giano-contracts@3.0.0
