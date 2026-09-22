---
'@appliedblockchain/giano-paymaster-admin': major
---

**Breaking (image contract):** `GIANO_RPC_UPSTREAM` is gone, and every absolute `rpcUrl` is now
proxied through the console's own origin — one nginx location per chain, `/rpc/<chainId>`, with the
keyed URL held server-side and `/rpc/<chainId>` written into `config.json`. A provider key in an
`rpcUrl` previously reached every browser that opened the console, and its origin was named in the
CSP header. `GIANO_RPC_PROXY=false` restores the old behaviour for a node that must be dialled
directly. A deployment that pointed `GIANO_RPC_URL` at its own `/rpc` with the node in
`GIANO_RPC_UPSTREAM` should now point `GIANO_RPC_URL` at the node itself.

**Breaking (config shape):** a deployment's `label` is now `name` and its `paymasterAddress` is now
`sponsorshipPaymaster`, matching the chain descriptor in `packages/contracts/chains.ts`. A
deployment can therefore give `GIANO_DEPLOYMENTS` the same value `wallet-api` reads as
`GIANO_CHAINS` and author its chain list once; the container keeps the keys the console reads and
drops the rest of a descriptor rather than publishing them to the browser. `GIANO_CSP_CONNECT_SRC`
is derived from the array when unset, so it no longer has to be maintained per chain.
