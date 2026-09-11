---
'@appliedblockchain/giano-wallet-kit': minor
---

A wallet origin no longer needs a route to a node or a bundler: a chain entry needs only its
`chainId`. `rpcUrl` defaults to wallet-api's read relay, `${walletApiUrl}/v1/rpc/${chainId}`
(tenant-bound, read-only allowlist), and `bundlerUrl` to wallet-api's bundler relay,
`${walletApiUrl}/v1/bundler/${chainId}` — the ERC-4337 surface viem's bundler client speaks, behind
the session, with `eth_sendUserOperation` going through the same policy, audit and idempotency
pipeline as `POST /v1/userops`. The kit's bundler transport (`sessionHttp`) attaches the wallet-api
session bearer to every call, read at call time; `bundlerOptions` takes the session getter as a
fifth argument. Explicit `rpcUrl` / `bundlerUrl` still dial a node or bundler directly.
