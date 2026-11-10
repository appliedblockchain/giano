---
"@appliedblockchain/giano-paymaster-sdk": minor
---

`GianoPaymasterClient.getAdminEvents({ range, kinds, timelock, tenantId })` reads the privileged changes to the paymaster and, given its address, its timelock, in one window of blocks: role changes, fees, parameters, signers, pause, upgrades, tenant registration, state and funds, and the timelock's schedule, execute, cancel, delay and role events. Each comes decoded (roles by name, timelock calls decoded), newest first, with its block time, transaction sender and actor, and the window returns `older` to page back like `getSponsorships`. `PAYMASTER_ADMIN_EVENTS` and `TIMELOCK_ADMIN_EVENTS` list what is read; a test fails when the contracts gain an event in neither list nor the excluded ones.

The list includes the paymaster's stake changes (the EntryPoint's `StakeLocked`, `StakeUnlocked` and `StakeWithdrawn` for it). The actor is the timelock for a paymaster change it executed and for its own delay changes, a funding's `from`, and never the EntryPoint. On a tenant's page, a `Cancelled` of an operation that changed the tenant is kept. A `FunctionDelayChange` names its function only when its target is the paymaster.
