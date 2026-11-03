## Purpose

Defines how the paymaster SDK reads the privileged changes to a paymaster and its timelock (who changed a role, a fee, a parameter, a signer, the pause state, the code or a tenant, and the timelock's operations) as one decoded, windowed list, so the history of every change is reconstructible from events alone.

## ADDED Requirements

### Requirement: The SDK reads privileged events as one decoded list
`GianoPaymasterClient` SHALL offer `getAdminEvents({ range?, kinds?, timelock?, tenantId? })`. It SHALL return the privileged events of the paymaster and, when a timelock address is given, of its timelock, decoded and merged newest first:

| Source | Events |
| --- | --- |
| Paymaster | `RoleGranted`, `RoleRevoked`, `FeeChanged`, `TenantFeeChanged`, `ParamChanged`, `Paused`, `Unpaused`, `SignerAdded`, `SignerRemoved`, `Upgraded`, `TenantRegistered`, `TenantEnabledChanged`, `TenantFunded`, `TenantWithdrawn`, `TenantWithdrawAddressChanged`, `FeesWithdrawn` |
| Timelock | `CallScheduled`, `CallExecuted`, `Cancelled`, `MinDelayChange`, `FunctionDelayChange`, `RoleGranted`, `RoleRevoked` |
| EntryPoint, for the paymaster's stake | `StakeLocked`, `StakeUnlocked`, `StakeWithdrawn` |

Each entry SHALL carry:
- its kind and decoded arguments, with role names rather than role hashes;
- the block, the block time and the transaction hash;
- who made the change: the account the event names (a role change's sender, a pause's account, an enable's actor, a funding's `from`), the timelock for a paymaster change it executed and for its own delay changes, otherwise the account that called the contract (a Safe, or the sender), never the EntryPoint.

The read SHALL be a window with an `older` range to continue from, like `getSponsorships`, and SHALL stay within the platform relay's log-query bounds. It SHALL ask the node only for the admin events' topics. `kinds` SHALL narrow the list at the node. `tenantId` SHALL narrow it to that tenant's events and the timelock calls whose arguments name it. A block or transaction that cannot be read SHALL leave that entry's time or sender empty, not fail the list.

#### Scenario: Role granted through the timelock
- **WHEN** an executed timelock operation granted `FEE_COLLECTOR_ROLE`
- **THEN** the list holds a `RoleGranted` entry naming `FEE_COLLECTOR_ROLE`, the grantee and the timelock as sender, and a `CallExecuted` entry for the operation

#### Scenario: Fee changed through the timelock from a Safe
- **WHEN** a Safe sends the timelock's `execute`, which changes the default fee
- **THEN** the `FeeChanged` entry names the timelock as who made the change, not the Safe

#### Scenario: Stake withdrawn
- **WHEN** a STAKE_ADMIN_ROLE holder withdraws the paymaster's stake
- **THEN** the list holds a `StakeWithdrawn` entry naming the holder, the amount and where it went

#### Scenario: One tenant's events
- **WHEN** the caller passes a tenant's id, and a timelock call that sets that tenant's fee was scheduled
- **THEN** the list holds that tenant's events and the `CallScheduled` entry, and no other tenant's

#### Scenario: Paging back
- **WHEN** the caller passes the returned `older` range
- **THEN** the next older window is returned, until `older` is absent

### Requirement: Who did what is reconstructible from the events alone
Every paymaster write that changes a role, a fee, a parameter, a signer, the pause state, the implementation, a tenant's registration, enabled state or withdrawal address, or moves funds, SHALL be represented in `getAdminEvents` by at least one entry. The SDK's tests SHALL check this against the paymaster ABI, so that a new privileged event that is not decoded fails the build.

#### Scenario: New event added to the contract
- **WHEN** a contract release adds a privileged event the SDK does not decode
- **THEN** the SDK's test suite fails, naming the event
