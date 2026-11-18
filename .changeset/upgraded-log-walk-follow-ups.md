---
"@appliedblockchain/giano-contracts": minor
"@appliedblockchain/giano-paymaster-sdk": minor
---

Reading a proxy's implementation from its `Upgraded` logs, on an RPC that refuses `eth_getStorageAt`, is now bounded by the proxy's deployment block and keeps its progress after a failed request (H6).

Contracts: the deploy CLI records the deployment block of each contract it deploys (`blockNumber` in `deployments/<chainId>.json`). The registry gains an optional `sponsorshipPaymasterDeployBlock`, and the deploy tooling and giano-doctor start the log search there. When an `eth_getLogs` request fails, `proxyImplementationWithSource` keeps the blocks already searched, and the next read through the same client continues below them. A search that stops at `maxChunks` throws the new `UpgradedLogWalkLimitError`; `isUpgradedLogWalkLimitError` tells it from a failed request. giano-doctor uses `proxyImplementationWithSource`, and no longer reports an empty implementation slot that it did not read.

Contracts: the new `waitForReceipt` waits for a transaction receipt as viem's `waitForTransactionReceipt` does. When the RPC refuses the full block (`eth_getBlockByNumber` with `true`) that viem's replacement check asks for, as the Silent Data gateway does, it waits again without that check. `isFullBlockRequestError` tells that failure from any other. The deploy CLI uses it for every receipt it waits for. On an RPC that returns full blocks nothing changes.

Paymaster SDK: the `wait()` of every write uses `waitForReceipt`, so a console write on Silent Data no longer fails after the transaction was mined. `readImplementationWithSource` sends at most `IMPLEMENTATION_LOG_REQUESTS_PER_READ` (100) `eth_getLogs` requests per read, and takes an optional `{ fromBlock, maxChunks }`. The client config gains `deployBlock`, which `fromRegistry` sets from the registry.
