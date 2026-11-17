---
"@appliedblockchain/giano-contracts": minor
"@appliedblockchain/giano-paymaster-sdk": patch
---

Read the proxy implementation without `eth_getStorageAt` (Silent Data, H6).

`proxyImplementation` now falls back to the proxy's latest `Upgraded` event when the RPC refuses the method `eth_getStorageAt`. Any other storage-read error, such as a timeout or a rate limit, is raised as before. When the fallback fails too, the error carries the storage-read error as `cause`.

The fallback reads logs in spans of at most 9,000 blocks, counted inclusively. The walk stops at the optional `fromBlock` (such as the proxy's deployment block). One read sends at most `maxChunks` requests (default 1,000, a non-negative safe integer); at the limit it throws, and the next read through the same client continues the search further back. The result is kept per client, proxy and `fromBlock`, up to a checkpoint 64 blocks behind the head, so a later read on the same client reads only the newer blocks, and a reorganisation cannot leave a removed upgrade behind.

`proxyImplementation` takes an optional third argument, `{ fromBlock, maxChunks }`. `proxyImplementationWithSource` returns `{ implementation, source }`, where `source` is `"slot"` or `"logs"`: an answer from the logs is not verified against the implementation slot, and wallet-api's chain check and giano-doctor report it as a warning. New exports: `proxyImplementationWithSource`, `implementationFromUpgradedLogs`, `isMethodRefusedError`, `UPGRADED_TOPIC`, `UPGRADED_LOG_CHUNK`, `UPGRADED_LOG_MAX_CHUNKS` and the type `UpgradedLogWalkOptions`. giano-doctor and the paymaster SDK's `readImplementationSlot` use the same fallback.
