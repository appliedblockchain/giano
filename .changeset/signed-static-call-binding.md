---
"@appliedblockchain/giano-contracts": minor
"@appliedblockchain/giano-wallet-core": minor
---

Bind the `signedStaticCall` signature to the call it authorises. Before, the owner signed only the function selector and `signedAt`. Anyone who saw one signature could make any read as the wallet for 30 minutes, for example a view that answers only `msg.sender == wallet`.

`AuthenticatedStaticCaller` now hashes the selector, `signedAt`, the target and `keccak256(data)`. The new `staticCallHash(target, data, signedAt)` view returns this hash. `signedStaticCall` also rejects a `signedAt` later than `block.timestamp`, with the new `SignatureNotYetValid` error. Before, a future `signedAt` made a signature last longer than the 30-minute lifetime. Deploy this as a new wallet implementation; the storage layout does not change.

In `giano-wallet-core`, `signStaticCallPermission` now takes `{ target, data, signedAt? }`. `signedAt` defaults to 30 seconds before the latest block timestamp. The contract rejects a future `signedAt`, so the SDK does not use the local clock, and the margin covers an RPC node that is a block or two behind. The new `staticCallHash` export returns the same hash as the contract. `signed_eth_call` keeps one signature per (account, target, calldata) instead of one signature for every read, and checks `to` and `data` before it asks for a signature.

The signed message changes. This SDK works only with wallets that run the new implementation, and older SDKs fail against it.
