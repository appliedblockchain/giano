---
"@appliedblockchain/giano-contracts": patch
---

`getSignatureLifetime()` in `AuthenticatedStaticCaller` is now `pure` instead of `view`. It returns a constant and reads no state. The ABI in `generated.ts` now says `stateMutability: 'pure'`. Calls to it work as before. The wallet and factory bytecode differs from contract release `v3`, so a later release must include this change before it is deployed. Contract addresses do not change.
