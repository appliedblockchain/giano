# @appliedblockchain/giano-wallet-kit

## 1.0.0

### Major Changes

- 6552edc: A wallet origin no longer needs a route to a node or a bundler: a chain entry needs only its
  `chainId`. `rpcUrl` defaults to wallet-api's read relay, `${walletApiUrl}/v1/rpc/${chainId}`
  (tenant-bound, read-only allowlist), and `bundlerUrl` to wallet-api's bundler relay,
  `${walletApiUrl}/v1/bundler/${chainId}` — the ERC-4337 surface viem's bundler client speaks, behind
  the session, with `eth_sendUserOperation` going through the same policy, audit and idempotency
  pipeline as `POST /v1/userops`. Explicit `rpcUrl` / `bundlerUrl` still dial a node or bundler directly.

  **Breaking:** `bundlerOptions` takes the session-token getter as a required fifth argument, and the
  new `sessionHttp` transport attaches the wallet-api session bearer to every bundler call. Both
  relays require wallet-api at or above the version that ships them.

### Minor Changes

- 42753c8: New package: the wallet SDK ("the kit") — the framework-agnostic orchestration a Giano wallet
  origin is built from (WALLET-SDK-REQUIREMENTS.md). One package now holds what wallet-web and the
  BYO reference each re-implemented by hand: config validation, the per-chain runtimes (fee-before-
  paymaster, sponsorship pre-flight, one shared wallet-api injection), the transport host with its
  single-slot consent gate, and the headless wallet-management controller (chain-before-registry,
  per-chain index re-reads, fingerprint recompute, the last-owner guard). A React adapter ships
  behind `@appliedblockchain/giano-wallet-kit/react`; the core is framework-free. Both Giano wallet
  UIs now build on it (WK-30, WK-31).

### Patch Changes

- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
  - @appliedblockchain/giano-contracts@3.0.0
  - @appliedblockchain/giano-wallet-core@3.0.0
  - @appliedblockchain/giano-wallet-transport@3.0.0
