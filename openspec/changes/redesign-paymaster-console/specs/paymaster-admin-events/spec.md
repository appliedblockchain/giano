## ADDED Requirements

### Requirement: The SDK reads privileged events as one decoded list
`GianoPaymasterClient` SHALL offer `getAdminEvents({ range?, kinds? })`. It SHALL return the privileged events of the paymaster and, when a timelock address is given, of its timelock, decoded and merged newest first:

| Source | Events |
| --- | --- |
| Paymaster | `RoleGranted`, `RoleRevoked`, `FeeChanged`, `TenantFeeChanged`, `ParamChanged`, `Paused`, `Unpaused`, `SignerAdded`, `SignerRemoved`, `Upgraded`, `TenantRegistered`, `TenantEnabledChanged`, `TenantFunded`, `TenantWithdrawn`, `TenantWithdrawAddressChanged`, `FeesWithdrawn` |
| Timelock | `CallScheduled`, `CallExecuted`, `Cancelled`, `MinDelayChange`, `FunctionDelayChange`, `RoleGranted`, `RoleRevoked` |

Each entry SHALL carry:
- its kind and decoded arguments, with role names rather than role hashes;
- the block, the block time and the transaction hash;
- the transaction's sender.

The read SHALL be a window with an `older` range to continue from, like `getSponsorships`, and SHALL stay within the platform relay's log-query bounds. `kinds` SHALL narrow the list.

#### Scenario: Role granted through the timelock
- **WHEN** an executed timelock operation granted `FEE_COLLECTOR_ROLE`
- **THEN** the list holds a `RoleGranted` entry naming `FEE_COLLECTOR_ROLE`, the grantee and the timelock as sender, and a `CallExecuted` entry for the operation

#### Scenario: Paging back
- **WHEN** the caller passes the returned `older` range
- **THEN** the next older window is returned, until `older` is absent

### Requirement: Who did what is reconstructible from the events alone
Every paymaster write that changes a role, a fee, a parameter, a signer, the pause state, the implementation, a tenant's registration, enabled state or withdrawal address, or moves funds, SHALL be represented in `getAdminEvents` by at least one entry. The SDK's tests SHALL check this against the paymaster ABI, so that a new privileged event that is not decoded fails the build.

#### Scenario: New event added to the contract
- **WHEN** a contract release adds a privileged event the SDK does not decode
- **THEN** the SDK's test suite fails, naming the event
