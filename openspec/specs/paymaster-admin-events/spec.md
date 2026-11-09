# paymaster-admin-events Specification

## Purpose

Defines how the paymaster SDK reads the privileged changes to a paymaster and its timelock (who changed a role, a fee, a parameter, a signer, the pause state, the code or a tenant, and the timelock's operations) as one decoded, windowed list, so the history of every change is reconstructible from events alone.

## Requirements

### Requirement: The SDK reads privileged events as one decoded list
`GianoPaymasterClient` SHALL offer `getAdminEvents({ range?, kinds?, timelock?, tenantId? })`. It SHALL return the privileged events of the paymaster and, when a timelock address is given, of its timelock, decoded and merged newest first.

#### Scenario: Role granted through the timelock
- **WHEN** an executed timelock operation granted `FEE_COLLECTOR_ROLE`
- **THEN** the list holds a `RoleGranted` entry naming `FEE_COLLECTOR_ROLE`, the grantee and the timelock as sender, and a `CallExecuted` entry for the operation

### Requirement: The SDK reads the paymaster's admin events
`getAdminEvents` SHALL return these events of the paymaster:

| Source | Events |
| --- | --- |
| Paymaster | `RoleGranted`, `RoleRevoked`, `FeeChanged`, `TenantFeeChanged`, `ParamChanged`, `Paused`, `Unpaused`, `SignerAdded`, `SignerRemoved`, `Upgraded`, `TenantRegistered`, `TenantEnabledChanged`, `TenantFunded`, `TenantWithdrawn`, `TenantWithdrawAddressChanged`, `FeesWithdrawn` |

#### Scenario: Tenant funded
- **WHEN** a tenant was funded on the paymaster
- **THEN** the list holds a `TenantFunded` entry

### Requirement: The SDK reads the timelock's admin events when given one
When a timelock address is given, `getAdminEvents` SHALL also return these events of the timelock:

| Source | Events |
| --- | --- |
| Timelock | `CallScheduled`, `CallExecuted`, `Cancelled`, `MinDelayChange`, `FunctionDelayChange`, `RoleGranted`, `RoleRevoked` |

#### Scenario: Minimum delay changed
- **WHEN** a timelock address is given and the timelock's minimum delay was changed
- **THEN** the list holds a `MinDelayChange` entry

### Requirement: The SDK reads the paymaster's stake changes from the EntryPoint
`getAdminEvents` SHALL also return the EntryPoint's events about the paymaster's stake, read filtered on the paymaster as `account`:

| Source | Events |
| --- | --- |
| EntryPoint, for the paymaster's stake | `StakeLocked`, `StakeUnlocked`, `StakeWithdrawn` |

#### Scenario: Stake withdrawn
- **WHEN** a STAKE_ADMIN_ROLE holder withdraws the paymaster's stake
- **THEN** the list holds a `StakeWithdrawn` entry naming the holder, the amount and where it went

### Requirement: Each admin event says who made the change
Each entry SHALL carry:
- its kind and decoded arguments, with role names rather than role hashes;
- the block, the block time and the transaction hash;
- who made the change: the account the event names (a role change's sender, a pause's account, an enable's actor, a funding's `from`), the timelock for a paymaster change it executed and for its own delay changes, otherwise the account that called the contract (a Safe, or the sender), never the EntryPoint.

#### Scenario: Change sent through a Safe
- **WHEN** an event names no account and its transaction was sent to a Safe rather than to the emitting contract
- **THEN** the entry names the Safe as who made the change

#### Scenario: Fee changed through the timelock from a Safe
- **WHEN** a Safe sends the timelock's `execute`, which changes the default fee
- **THEN** the `FeeChanged` entry names the timelock as who made the change, not the Safe

### Requirement: Admin events are read in bounded windows
The read SHALL be a window with an `older` range to continue from, like `getSponsorships`, and SHALL stay within the platform relay's log-query bounds. It SHALL ask the node only for the admin events' topics. A block or transaction that cannot be read SHALL leave that entry's time or actor empty, not fail the list.

#### Scenario: Paging back
- **WHEN** the caller passes the returned `older` range
- **THEN** the next older window is returned, until `older` is absent

#### Scenario: Block not readable
- **WHEN** the block of one entry cannot be read
- **THEN** that entry's time is empty, and the rest of the list is returned

### Requirement: Admin events can be narrowed by kind and tenant
`kinds` SHALL narrow the list at the node. `tenantId` SHALL narrow it to that tenant's events, the timelock calls whose arguments name it, and the `Cancelled` of those operations.

#### Scenario: One tenant's events
- **WHEN** the caller passes a tenant's id, and a timelock call that sets that tenant's fee was scheduled
- **THEN** the list holds that tenant's events and the `CallScheduled` entry, and no other tenant's

### Requirement: Who did what is reconstructible from the events alone
Every paymaster write that changes a role, a fee, a parameter, a signer, the pause state, the implementation, a tenant's registration, enabled state or withdrawal address, or moves funds, SHALL be represented in `getAdminEvents` by at least one entry. The SDK's tests SHALL check this against the paymaster ABI, so that a new privileged event that is not decoded fails the build.

#### Scenario: New event added to the contract
- **WHEN** a contract release adds a privileged event the SDK does not decode
- **THEN** the SDK's test suite fails, naming the event
