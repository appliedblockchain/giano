---
"@appliedblockchain/giano-wallet-kit": patch
---

An owner change no longer stops at a chain whose paymaster does not have the tenant registered or enabled: that chain is refused and the remaining chains are still applied. Tenant-wide refusals still stop the run. When chains refuse for different reasons, the reported refusal is a tenant-wide one over a chain-scoped one. The `refused` management flow now carries the refusal's `ruleResults`.
