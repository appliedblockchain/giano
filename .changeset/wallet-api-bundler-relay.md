---
'@appliedblockchain/giano-wallet-kit': minor
---

A wallet origin no longer needs a route to a bundler. `bundlerUrl` is optional per chain and
defaults to wallet-api's JSON-RPC bundler relay, `${walletApiUrl}/v1/bundler/${chainId}` — the
same ERC-4337 surface viem's bundler client already speaks, served by wallet-api behind the
session: `eth_sendUserOperation` goes through the identical policy, audit and idempotency
pipeline as `POST /v1/userops`, `eth_estimateUserOperationGas` is bound to the session's wallet,
receipts are forwarded. The kit's bundler transport (`sessionHttp`) attaches the wallet-api
session bearer to every call, read at call time. `bundlerOptions` takes the session getter as a
fifth argument. An explicit `bundlerUrl` still dials a bundler directly, for development.
