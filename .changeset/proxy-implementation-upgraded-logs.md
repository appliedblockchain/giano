---
"@appliedblockchain/giano-contracts": minor
"@appliedblockchain/giano-paymaster-sdk": patch
---

Read the proxy implementation without `eth_getStorageAt` (Silent Data, H6).

`proxyImplementation` falls back to the proxy's latest `Upgraded` event when the RPC refuses `eth_getStorageAt`. It reads logs in spans of at most 10,000 blocks. New exports: `proxyImplementation`, `implementationFromUpgradedLogs`, `UPGRADED_TOPIC`, `UPGRADED_LOG_CHUNK`. giano-doctor and the paymaster SDK's `readImplementationSlot` use the same fallback.
