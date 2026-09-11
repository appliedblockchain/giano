---
'@appliedblockchain/giano-wallet-kit': major
---

A wallet origin no longer needs a route to a node or a bundler: a chain entry needs only its
`chainId`. `rpcUrl` defaults to wallet-api's read relay, `${walletApiUrl}/v1/rpc/${chainId}`
(tenant-bound, read-only allowlist), and `bundlerUrl` to wallet-api's bundler relay,
`${walletApiUrl}/v1/bundler/${chainId}` — the ERC-4337 surface viem's bundler client speaks, behind
the session, with `eth_sendUserOperation` going through the same policy, audit and idempotency
pipeline as `POST /v1/userops`. Explicit `rpcUrl` / `bundlerUrl` still dial a node or bundler directly.

**Breaking:** `bundlerOptions` takes the session-token getter as a required fifth argument, and the
new `sessionHttp` transport attaches the wallet-api session bearer to every bundler call. Both
relays require wallet-api at or above the version that ships them.
