## ADDED Requirements

### Requirement: One tab bar with a URL per tab and per tenant
The console SHALL show one tab bar: Overview, Tenants, Paymaster, Roles, Timelock, Activity, Health and Admins. Admins SHALL be shown only when `platformApi` is `true`.

Each tab SHALL have its own path:

| Tab | Path |
| --- | --- |
| Overview | `/` |
| Tenants | `/tenants` |
| Paymaster | `/paymaster` |
| Roles | `/roles` |
| Timelock | `/timelock` |
| Activity | `/activity` |
| Health | `/health` |
| Admins | `/admins` |

Each tenant SHALL have its own path, `/tenants/<slug>`, or `/tenants/<id>` for a tenant with no registry row.

Every tab SHALL be a link: opening it in a new browser tab, reloading, or using Back and Forward SHALL land on the same tab. An unknown path SHALL show a "no such page" view with a link to Overview.

The selected deployment SHALL NOT be part of the URL.

#### Scenario: Reload keeps the tab
- **WHEN** an operator on `/timelock` reloads the page and signs in again
- **THEN** the console opens on the Timelock tab

#### Scenario: Tenant link
- **WHEN** an operator opens `/tenants/byo` on a deployment where `byo` exists
- **THEN** the console opens the `byo` tenant page

#### Scenario: Unknown path
- **WHEN** an operator opens `/settings`
- **THEN** the console shows that there is no such page, with a link to Overview

#### Scenario: Console without platform API
- **WHEN** `platformApi` is false
- **THEN** the tab bar shows Overview, Tenants, Paymaster, Roles, Timelock, Activity and Health, and no Admins tab

### Requirement: Light and dark colour modes
The console SHALL offer a light and a dark colour mode, with a toggle in the header. The first visit SHALL follow the browser's `prefers-color-scheme`. A choice made with the toggle SHALL be remembered in `localStorage`. The page SHALL render in the chosen mode from the first paint, with no flash of the other.

#### Scenario: Remembered choice
- **WHEN** an operator switches to dark mode and reloads
- **THEN** the console renders dark from the first paint

### Requirement: A write the wallet cannot make is shown disabled, naming the role
Every control that sends a paymaster or timelock transaction SHALL be shown whether or not the connected wallet may use it. When it may not, the control SHALL be disabled and SHALL name the missing role, or say that no wallet is connected. No such control SHALL be hidden because of a missing role.

#### Scenario: No role
- **WHEN** a connected wallet without `PAUSER_ROLE` opens the Paymaster tab
- **THEN** the Pause control is shown disabled and says it needs `PAUSER_ROLE`

### Requirement: Timelocked operations offer Send or Propose in context
For every operation in the SDK's `TIMELOCKED_OPERATIONS`, the control where that operation belongs SHALL resolve to:
- **Send**, when the connected wallet holds the operation's role;
- **Propose**, when it does not and the deployment has a `timelockAddress`. This opens the proposal dialog with the call filled in;
- **disabled**, otherwise. The control names the role and says that no timelock is configured.

| Operation | Where it belongs |
| --- | --- |
| Tenant fee override | the tenant page |
| Withdrawal address | the tenant page |
| Default fee | the Paymaster tab |
| Upgrade | the Paymaster tab |
| Role grant, revoke and renounce | the Roles tab |

Propose controls and every other timelocked element SHALL be marked with the timelock colour and a clock icon.

#### Scenario: Fee override proposed from the tenant page
- **WHEN** a wallet without `FEE_ADMIN_ROLE` opens a tenant page on a deployment with a timelock
- **THEN** the fee override control reads *Propose*, and submitting it opens the proposal dialog with a `setTenantFee` call for that tenant

#### Scenario: Fee override sent on a devnet
- **WHEN** a wallet holding `FEE_ADMIN_ROLE` sets a tenant fee override on a deployment with no timelock
- **THEN** the control reads *Send* and the wallet is asked to send `setTenantFee`

### Requirement: Destructive chain writes ask for confirmation
Each of the following SHALL ask for confirmation in a dialog that names its effect before the wallet is asked to sign:
- pause;
- revoke a role;
- remove a signer;
- disable a tenant;
- withdraw from the treasury;
- withdraw stake;
- execute a timelock operation;
- cancel a timelock operation.

#### Scenario: Revoking your own role
- **WHEN** an operator revokes `ROLE_ADMIN` from the connected address
- **THEN** the confirmation says the wallet will lose the ability to grant and revoke roles, and nothing is sent until it is confirmed

### Requirement: Inputs are validated before the wallet is asked
Every address and amount field SHALL validate its value as it is typed. It SHALL state the problem under the field, and SHALL keep its submit control disabled while the value is invalid:
- **Address:** `0x` followed by 40 hex characters, with a valid checksum when mixed-case.
- **Amount:** a positive decimal in the chain's native currency, no greater than its stated maximum.
- **Penalty:** no more than 5000 basis points.

#### Scenario: Short address
- **WHEN** an operator types a 39-character hex address into a grant field
- **THEN** the field says the address has 39 hex characters instead of 40, and Grant is disabled

### Requirement: Failures are stated where they happened
Every failed read or write SHALL be stated where it happened: inline for reads and for form submissions, and as a toast for other writes. No failure SHALL leave the page unchanged without a message. A read that failed SHALL offer a retry, and SHALL NOT show a loading indicator after it failed.

#### Scenario: Failed timelock read
- **WHEN** the first read of the timelock fails
- **THEN** the Timelock tab states the error and offers to try again, and no spinner remains

### Requirement: The timelock is operable from the console
The Timelock tab SHALL list the timelock's operations with a Pending, Done, Cancelled or All filter, reading back at least as far as its longest function delay.

The console SHALL let a connected wallet do each of the following directly, and SHALL offer the matching Safe batch download when the wallet does not hold the role:

| Action | Role | Applies to |
| --- | --- | --- |
| Schedule | `PROPOSER_ROLE` | a proposal |
| Execute | `EXECUTOR_ROLE`, or anyone when executors are open | a ready operation |
| Cancel | `CANCELLER_ROLE` | a pending operation |

The proposal dialog SHALL:
- accept more than one call;
- accept a salt, a delay no shorter than the operation's minimum, and a predecessor;
- show the resulting operation id and the calldata.

The console SHALL offer proposals for:
- `updateDelay`;
- `setFunctionDelay`;
- granting and revoking the timelock's PROPOSER, CANCELLER and EXECUTOR roles.

#### Scenario: Role rotation
- **WHEN** an operator proposes granting `FEE_ADMIN_ROLE` to a new address and revoking it from the old one
- **THEN** the dialog builds one operation with both calls, and executing it applies both together

#### Scenario: Execute a ready operation
- **WHEN** an operation is ready, executors are open, and the operator confirms *Execute*
- **THEN** the wallet sends `executeBatch`, and the operation is listed as done once it confirms

### Requirement: Queued changes are marked where they will land
When the timelock has a pending operation that changes something, that thing SHALL carry a marker saying a change is queued. The marker SHALL say when the change is ready, or that it is ready now, and link to the operation in the Timelock tab. This applies to:
- a tenant's fee override or withdrawal address;
- the default fee;
- a role;
- the implementation.

#### Scenario: Withdrawal address change queued
- **WHEN** a `setTenantWithdrawAddress` operation for `byo` is waiting
- **THEN** the `byo` row and the withdrawal address on its page show the change as queued, with the time it is ready

### Requirement: The Paymaster tab covers the stake lifecycle and upgrades
The Paymaster tab SHALL offer:
- add stake;
- unlock stake, showing the unstake delay in human units;
- withdraw stake once unlocked, showing when it unlocks as a date and time.

It SHALL show the current implementation address, read from the ERC-1967 implementation slot. It SHALL offer *Propose upgrade* for `upgradeToAndCall`, following the Send or Propose rule.

#### Scenario: Stake unlocking
- **WHEN** the stake has been unlocked and its delay has not passed
- **THEN** the Paymaster tab shows when withdrawal becomes possible, and Withdraw stake is disabled until then

### Requirement: The Overview shows what needs attention
The Overview SHALL list first the conditions that need an operator, each linking to where it is fixed:
- a tenant in deficit;
- a registered tenant with no balance;
- a registry tenant not registered on the selected chain;
- a tenant whose registry state and on-chain state disagree;
- a timelock operation that is ready;
- the paymaster paused;
- the solvency invariant failing.

Below them it SHALL show:
- the deposit, tenant balances, treasury and stake;
- solvency;
- configuration, including the implementation;
- the queued changes.

Tenants SHALL be named by slug wherever one is known.

#### Scenario: Unregistered tenant
- **WHEN** a registry tenant has no roster entry on the selected chain
- **THEN** the Overview lists it as not registered, by slug, with a link to its tenant page
