# @appliedblockchain/giano-wallet-kit

## 3.0.0

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

- 42753c8: New package: the wallet SDK ("the kit") — the framework-agnostic orchestration a Giano wallet
  origin is built from (WALLET-SDK-REQUIREMENTS.md). One package now holds what wallet-web and the
  BYO reference each re-implemented by hand: config validation, the per-chain runtimes (fee-before-
  paymaster, sponsorship pre-flight, one shared wallet-api injection), the transport host with its
  single-slot consent gate, and the headless wallet-management controller (chain-before-registry,
  per-chain index re-reads, fingerprint recompute, the last-owner guard). A React adapter ships
  behind `@appliedblockchain/giano-wallet-kit/react`; the core is framework-free. Both Giano wallet
  UIs now build on it (WK-30, WK-31).

### Patch Changes

- b6a635f: Pin Giano siblings exactly in published tarballs. Inter-package dependencies move from `workspace:^`
  to `workspace:*`, which pnpm rewrites at pack time to the sibling's exact version rather than a
  caret range — so installing one of the six installs that release, not a resolution across two.
- 5b8b279: Verify paymaster sponsorship signatures using ECDSA recovery without inspecting or calling the signer during ERC-4337 validation. ERC-1271 sponsorship signers are no longer supported; existing contract signers must be replaced with ECDSA keys.

  Fix the raw prepare/sign/send user-operation flow across wallet popups, require consent for raw signing and authenticated reads, and preserve RainbowKit wallet metadata.

- Updated dependencies [b6a635f]
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [5b8b279]
- Updated dependencies [62a5d2c]
- Updated dependencies [fcd51ea]
- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
  - @appliedblockchain/giano-wallet-core@3.0.0
  - @appliedblockchain/giano-contracts@3.0.0
  - @appliedblockchain/giano-tx-describe@3.0.0
  - @appliedblockchain/giano-wallet-transport@3.0.0
