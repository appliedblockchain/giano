---
'@appliedblockchain/giano-paymaster-sdk': patch
---

Read the paymaster's logs in windows the RPC will serve, starting at the deployment block.

`getTenantSlugs` and `getSponsorships` asked for `earliest`..`latest` in a single `eth_getLogs`.
Hosted endpoints refuse that — Base Sepolia answers `eth_getLogs is limited to a 10,000 range`
(-32614) — so the admin console's tenant roster and history panel failed outright on every chain
but a local devnet.

Both now walk the range a window at a time, starting at 9,000 blocks and halving on rejection so a
node with a tighter cap is discovered rather than configured. Registrations are cached between
calls: a scan that reached block N only reads above N next time, which is what keeps a console
polling every fifteen seconds from re-walking the deployment's whole history.

Where the walk starts is the new `deploymentBlock` client option (`--deployment-block` on the CLI).
It is not derivable — finding it needs `eth_getCode` at a historical block, which the endpoints
that impose the range cap are the least likely to serve — so without it a log read on a public
chain throws `LogRangeUnboundedError` naming the option, instead of issuing thousands of requests
that scan a chain to find a deployment.
