# @appliedblockchain/giano-wallet-web

## 1.0.0

### Major Changes

- 6552edc: **Breaking (image contract):** nginx now proxies only `/api` and `/.well-known/webauthn`. The
  `/rpc`, `/rpc-b`, `/bundler` and `/bundler-b` locations are gone, and `GIANO_RPC_UPSTREAM`,
  `GIANO_RPC_B_UPSTREAM`, `GIANO_BUNDLER_UPSTREAM` and `GIANO_BUNDLER_B_UPSTREAM` are ignored. The
  SPA reads through wallet-api's `/api/v1/rpc/<chainId>` relay and submits through
  `/api/v1/bundler/<chainId>`, so `GIANO_RPC_URL` and `GIANO_BUNDLER_URL` are no longer required
  (and `GIANO_CHAINS` entries need no `rpcUrl`/`bundlerUrl`); set them only to dial a node or bundler
  directly. A deployment that pointed `GIANO_RPC_URL` at `/rpc` must drop it. Requires a wallet-api
  that serves the two relays.

### Patch Changes

- Updated dependencies [42753c8]
- Updated dependencies [42753c8]
- Updated dependencies [6552edc]
- Updated dependencies [42753c8]
  - @appliedblockchain/giano-contracts@3.0.0
  - @appliedblockchain/giano-wallet-kit@1.0.0
