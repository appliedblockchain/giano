# paymaster-console Specification

## Purpose
The paymaster console (`services/paymaster-admin`) is an operator's view of a Giano sponsorship paymaster and, where the deployment enables the platform API, of wallet-api's tenant registry and platform admins. This capability covers its navigation, header and theme, the rules every write follows — shown disabled with the reason, Send or Propose for a timelocked change, confirmation before a destructive one, validation at the input, failures stated where they happen — and what each tab offers.

## Requirements

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

#### Scenario: Console without platform API
- **WHEN** `platformApi` is false
- **THEN** the tab bar shows Overview, Tenants, Paymaster, Roles, Timelock, Activity and Health, and no Admins tab

### Requirement: Every tab and tenant is a link that survives reload
Each tenant SHALL have its own path, `/tenants/<slug>`, or `/tenants/<id>` for a tenant with no registry row.

Every tab SHALL be a link: opening it in a new browser tab, reloading, or using Back and Forward SHALL land on the same tab. The current tab SHALL be marked with `aria-current="page"`. An unknown path SHALL show a "no such page" view with a link to Overview.

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

### Requirement: Tabs show their counts and a Health badge
The Tenants tab SHALL show the number of tenants, and the Timelock tab the number of pending operations, once each is known. The Health tab SHALL carry a labelled badge when any check warns or fails.

#### Scenario: Pending operations counted
- **WHEN** the timelock has three pending operations
- **THEN** the Timelock tab reads *Timelock 3*

### Requirement: The header says where the console is and as whom
On every page the header SHALL show:
- the deployment, as a select when more than one is configured, with its name and chain id;
- the paymaster address, labelled and copyable;
- where the platform API is configured and a session exists: the platform admin id, the time left in minutes, and a control that shows the address and offers *Sign out*;
- the colour-mode toggle.

#### Scenario: More than one deployment
- **WHEN** more than one deployment is configured
- **THEN** the header shows the deployment as a select, with its name and chain id

### Requirement: The header shows the wallet and its paymaster roles
On every page the header SHALL show the wallet: *Connect wallet* when none is connected, or the connection state and the number of paymaster roles it holds, with a control that shows the full address, the network and the roles, and offers *Disconnect*.

Disconnecting SHALL also end the platform admin session, because the session was signed by that wallet, and the control SHALL say so.

#### Scenario: Disconnect while signed in
- **WHEN** a signed-in operator disconnects the wallet
- **THEN** the wallet is disconnected, the session ends, and the sign-in page is shown

### Requirement: A status line under the header shows the console's state
Under the header, a status line SHALL show:
- the health summary, linking to the Health tab;
- whether the solvency invariant holds;
- *paused* when the paymaster is paused;
- the number of queued timelock changes, linking to the Timelock tab, when there are any;
- the time and block of the last refresh, and a refresh control.

#### Scenario: Status line on a paused paymaster
- **WHEN** the paymaster is paused
- **THEN** the status line says it is paused and sponsoring nothing, on every tab

#### Scenario: Queued changes in the status line
- **WHEN** the timelock has a pending operation
- **THEN** the status line reads *1 change queued* and links to the Timelock tab

### Requirement: Light and dark colour modes
The console SHALL offer a light and a dark colour mode, with a toggle in the header. The first visit SHALL follow the browser's `prefers-color-scheme`. A choice made with the toggle SHALL be remembered in `localStorage`. The page SHALL render in the chosen mode from the first paint, with no flash of the other. The console's Content-Security-Policy SHALL NOT be loosened to do this.

#### Scenario: Remembered choice
- **WHEN** an operator switches to dark mode and reloads
- **THEN** the console renders dark from the first paint

### Requirement: Known addresses are named
Wherever the console shows an address, it SHALL add a name when it knows one:
- *you*, for the connected wallet;
- *the timelock*, for the deployment's `timelockAddress`;
- *the paymaster*, for the paymaster proxy;
- the label given for that address in the deployment's optional `addresses` configuration.

The full address SHALL always be available to read and copy beside the name.

#### Scenario: Connected wallet named
- **WHEN** the console shows the connected wallet's address
- **THEN** the address is named *you*, and the full address is available to read and copy beside the name

### Requirement: A Safe address shows its threshold and owner count
An address configured with `kind: "safe"` SHALL also show the Safe's threshold and owner count, read from the Safe, as *3 of 5*. A failed Safe read SHALL show the label without the threshold.

#### Scenario: Safe as proposer
- **WHEN** the deployment's `addresses` configuration labels `0x5afe…0f9a` as `Safe` with `kind: "safe"`, and that Safe has a threshold of 3 and five owners
- **THEN** every place showing that address reads *Safe · 3 of 5*, beside the full address

### Requirement: Transactions link to the deployment's explorer
Each deployment's configuration MAY name an `explorerUrl`. When it does, every transaction hash the console shows SHALL link to `<explorerUrl>/tx/<hash>`, and every address to `<explorerUrl>/address/<address>`, opening in a new tab. When it does not, hashes and addresses SHALL be shown in full and copyable, with no link.

A configured `explorerUrl` that is not an `https:` URL, or `http:` on localhost, SHALL be refused at config load.

#### Scenario: No explorer on a devnet
- **WHEN** the selected deployment has no `explorerUrl`
- **THEN** transaction hashes in Activity are shown in full with a copy control, and no link

### Requirement: Values are exact, labelled and never colour alone
- Amounts SHALL be shown in the native currency of the selected chain, named by the chain's currency symbol, not a fixed "ETH".
- An abbreviated value (a shortened address, a rounded amount) SHALL have its exact value available on the page to read and copy, not only in a `title` tooltip.
- A status SHALL be stated in words beside any colour that marks it.

#### Scenario: Native currency
- **WHEN** the selected chain's native currency is `POL`
- **THEN** balances, fees and amount fields are labelled in POL

### Requirement: Controls, badges and rows are accessible
- Every icon-only control SHALL have an accessible name, and every badge that carries meaning SHALL be readable by a screen reader.
- Every table row that opens something SHALL be reachable and operable by keyboard.

#### Scenario: Row opened by keyboard
- **WHEN** an operator moves through a table with the keyboard
- **THEN** every row that opens something can be reached and opened without a pointer

### Requirement: The console works at phone width
Every page SHALL be usable at 390 px wide with no horizontal scroll of the page: the header wraps, the tab bar scrolls sideways within itself, and wide tables scroll within their own box.

#### Scenario: Tenants on a phone
- **WHEN** the Tenants tab is opened at 390 px
- **THEN** the page does not scroll sideways, and the tenant table scrolls within its box

### Requirement: One refresh for everything on screen
Every chain and platform API read on screen SHALL be refreshed together: by the refresh control, and every `refreshSeconds` while the browser tab is visible. A read that costs one request per tenant SHALL instead run on demand (the Health tab's ledger comparison, D22). Polling SHALL stop while the browser tab is hidden, and SHALL refresh once when it becomes visible again.

#### Scenario: Hidden tab
- **WHEN** the console's browser tab is in the background for ten minutes
- **THEN** no chain read is made in that time, and one refresh runs when the tab is shown again

### Requirement: A refresh keeps what is loaded and misses no block
A refresh SHALL NOT discard older pages an operator has already loaded, and SHALL read every block since the last one, however long the gap.

A `refreshSeconds` other than 0 or a whole number of seconds from 1 to 86400 SHALL be refused at config load.

#### Scenario: Refresh after older pages were loaded
- **WHEN** an operator has loaded older pages and a refresh runs
- **THEN** the older pages stay loaded, and every block since the last refresh is read

### Requirement: A write the wallet cannot make is shown disabled, naming the role
Every control that sends a paymaster or timelock transaction SHALL be shown whether or not the connected wallet may use it. When it may not, the control SHALL be disabled and SHALL name the missing role, or say that no wallet is connected. No such control SHALL be hidden because of a missing role.

#### Scenario: No role
- **WHEN** a connected wallet without `PAUSER_ROLE` opens the Paymaster tab
- **THEN** the Pause control is shown disabled and says it needs `PAUSER_ROLE`

#### Scenario: No wallet
- **WHEN** no wallet is connected
- **THEN** every write control is disabled and says a wallet must be connected

### Requirement: Timelocked operations offer Send or Propose in context
For every operation in the SDK's `TIMELOCKED_OPERATIONS`, the control where that operation belongs SHALL resolve to:
- **Send**, when the connected wallet holds the operation's role;
- **Propose**, when it does not and the deployment has a `timelockAddress`. This opens the proposal dialog with the call filled in;
- **disabled**, otherwise. The control names the role and says that no timelock is configured.

#### Scenario: Fee override proposed from the tenant page
- **WHEN** a wallet without `FEE_ADMIN_ROLE` opens a tenant page on a deployment with a timelock
- **THEN** the fee override control reads *Propose*, and submitting it opens the proposal dialog with a `setTenantFee` call for that tenant

#### Scenario: Fee override sent on a devnet
- **WHEN** a wallet holding `FEE_ADMIN_ROLE` sets a tenant fee override on a deployment with no timelock
- **THEN** the control reads *Send* and the wallet is asked to send `setTenantFee`

#### Scenario: No timelock and no role
- **WHEN** a wallet without `UPGRADER_ROLE` opens the Paymaster tab on a deployment with no timelock
- **THEN** *Propose upgrade* is disabled and says it needs `UPGRADER_ROLE` and that no timelock is configured

### Requirement: Each timelocked operation's control is where the operation belongs
The control for each operation in `TIMELOCKED_OPERATIONS` SHALL be where this table places it:

| Operation | Where it belongs |
| --- | --- |
| Tenant fee override, and clearing it | the tenant page |
| Withdrawal address | the tenant page |
| Default fee | the Paymaster tab |
| Upgrade | the Paymaster tab |
| Role grant, revoke and renounce | the Roles tab |

#### Scenario: Default fee on the Paymaster tab
- **WHEN** an operator looks for the control that changes the default fee
- **THEN** it is on the Paymaster tab

### Requirement: Timelocked elements are marked
Propose controls and every other timelocked element SHALL be marked with the timelock colour and a clock icon.

#### Scenario: Propose control marked
- **WHEN** a control reads *Propose*
- **THEN** it is marked with the timelock colour and a clock icon

### Requirement: Destructive chain writes ask for confirmation
Each of the following SHALL ask for confirmation in a dialog that names its effect before the wallet is asked to sign:
- pause;
- revoke a role;
- remove a signer;
- disable a tenant;
- change a tenant's withdrawal address, naming the new address;
- withdraw from the treasury;
- unlock stake;
- withdraw stake;
- execute a timelock operation;
- cancel a timelock operation;
- upgrade the paymaster, when sent rather than proposed;
- renounce a role.

#### Scenario: Revoking your own role
- **WHEN** an operator revokes `ROLE_ADMIN` from the connected address
- **THEN** the confirmation says the wallet will lose the ability to grant and revoke roles, and nothing is sent until it is confirmed

#### Scenario: Unlocking stake
- **WHEN** an operator unlocks the stake
- **THEN** the confirmation says bundlers stop accepting the paymaster as soon as it is unlocked

### Requirement: Inputs are validated before the wallet is asked
Every address and amount field SHALL validate its value as it is typed. It SHALL state the problem under the field, and SHALL keep its submit control disabled while the value is invalid:
- **Address:** `0x` followed by 40 hex characters, with a valid checksum when mixed-case.
- **Penalty:** no more than 5000 basis points.
- **Gas and delays:** a non-negative whole number.

#### Scenario: Short address
- **WHEN** an operator types a 39-character hex address into a grant field
- **THEN** the field says the address has 39 hex characters instead of 40, and Grant is disabled

### Requirement: Amounts are positive, and 0 only where it is a value
An amount field SHALL accept as valid only:
- **Amount:** a positive decimal in the chain's native currency, no greater than its stated maximum. 0 is accepted where it is a value: a fee (the default fee or a tenant's override), where it means free, and Add stake when stake is already locked, where it locks it again or raises only the delay.

#### Scenario: Free fee
- **WHEN** an operator enters 0 as a tenant's fee override
- **THEN** the field accepts it, and its submit control is enabled

### Requirement: A field is cleared after its write succeeds
A field SHALL be cleared after its write succeeds, unless it was changed while the write was pending: what was typed since belongs to the operator.

#### Scenario: Write succeeds
- **WHEN** a write succeeds and its field was not changed while it was pending
- **THEN** the field is cleared

#### Scenario: Typed while pending
- **WHEN** an operator changes a field while its write is pending, and the write succeeds
- **THEN** the field keeps what was typed

### Requirement: Failures are stated where they happened
Every failed read or write SHALL be stated where it happened: inline for reads and for form submissions, and as a toast for other writes. No failure SHALL leave the page unchanged without a message. A read that failed SHALL offer a retry, and SHALL NOT show a loading indicator after it failed. A failed refresh SHALL keep the last good data on screen, marked as stale.

#### Scenario: Failed timelock read
- **WHEN** the first read of the timelock fails
- **THEN** the Timelock tab states the error and offers to try again, and no spinner remains

### Requirement: A write is confirmed only by a successful receipt
A write SHALL be reported as confirmed only when its receipt says it succeeded. A transaction mined but reverted SHALL be reported as a failure, with its hash.

#### Scenario: Reverted write
- **WHEN** a write's transaction is mined but reverts
- **THEN** the console says it failed, with the transaction hash, and does not say it was confirmed

### Requirement: The Paymaster tab covers every paymaster setting
The Paymaster tab SHALL show one card per area, each naming the role it needs, whether that role is timelocked, and whether the connected wallet holds it:

| Card | Role | Offers |
| --- | --- | --- |
| Sponsorship signing keys | `SIGNER_ADMIN_ROLE` | list, add, remove |
| Pricing | `FEE_ADMIN_ROLE` (timelocked) | the default fee; Send or Propose a new one |
| Operational parameters | `PARAM_ADMIN_ROLE` | post-op gas allowance; unused-gas penalty |
| Pause | `PAUSER_ROLE` | pause and unpause |

#### Scenario: Unpause
- **WHEN** the paymaster is paused and the wallet holds `PAUSER_ROLE`
- **THEN** the Pause card offers *Unpause*

### Requirement: The Stake card shows when the stake can be withdrawn
The Paymaster tab SHALL also show a Stake card, naming the role it needs, whether that role is timelocked, and whether the connected wallet holds it:

| Card | Role | Offers |
| --- | --- | --- |
| Stake | `STAKE_ADMIN_ROLE` | add, unlock, withdraw |

The Stake card SHALL show the locked amount, the unstake delay in human units, and, once unlocked, when withdrawal becomes possible as a date and time. *Withdraw stake* SHALL be disabled until then.

#### Scenario: Stake unlocking
- **WHEN** the stake has been unlocked and its delay has not passed
- **THEN** the Paymaster tab shows when withdrawal becomes possible, and Withdraw stake is disabled until then

### Requirement: The Treasury card withdraws what has accrued
The Paymaster tab SHALL also show a Treasury card, naming the role it needs, whether that role is timelocked, and whether the connected wallet holds it:

| Card | Role | Offers |
| --- | --- | --- |
| Treasury | `FEE_COLLECTOR_ROLE` | withdraw to an address, with *Max* |

The Treasury card SHALL state what has accrued, and *Max* SHALL fill that amount.

#### Scenario: Treasury max
- **WHEN** an operator with `FEE_COLLECTOR_ROLE` clicks *Max*
- **THEN** the amount field holds exactly the accrued treasury

### Requirement: The Upgrade card shows the implementation and upgrades it
The Paymaster tab SHALL also show an Upgrade card, naming the role it needs, whether that role is timelocked, and whether the connected wallet holds it:

| Card | Role | Offers |
| --- | --- | --- |
| Upgrade | `UPGRADER_ROLE` (timelocked) | the current implementation; Send or Propose `upgradeToAndCall` |

The Upgrade card SHALL read the current implementation from the ERC-1967 implementation slot, and SHALL accept an optional call to run after the upgrade.

#### Scenario: Current implementation
- **WHEN** an operator opens the Paymaster tab
- **THEN** the Upgrade card shows the implementation read from the ERC-1967 implementation slot

### Requirement: The Roles tab lists every role with its holders
The Roles tab SHALL list every paymaster role with:
- whether it is timelocked, and its delay when it is;
- its holders, each named under the known-addresses rule;
- what the role may and may not do, from the SDK's role table;
- any queued change to it, with *Execute* when it is ready and the wallet may execute.

#### Scenario: Timelocked role listed
- **WHEN** an operator opens the Roles tab on a deployment with a timelock
- **THEN** each timelocked role says it is timelocked and gives its delay, beside its holders and what it may and may not do

### Requirement: The Roles tab flags holders that should not hold a role
The Roles tab SHALL flag a timelocked role held by anything other than the timelock. It SHALL say whether `DEFAULT_ADMIN_ROLE` is held by anybody, and SHALL offer to revoke it from a holder, following the write rules.

#### Scenario: Timelocked role outside the timelock
- **WHEN** `UPGRADER_ROLE` is held by an address other than the timelock on a deployment with a timelock
- **THEN** that holder is flagged on the Roles tab

#### Scenario: Default admin held
- **WHEN** an address holds `DEFAULT_ADMIN_ROLE`
- **THEN** the Roles tab warns that it should be held by nobody and offers to revoke it

### Requirement: The Roles tab shows every role and changes them under the write rules
Grant and revoke SHALL follow the Send or Propose rule. *Propose a role change* SHALL offer grant, revoke, and rotate; a rotation SHALL put the grant and the revoke in one operation. Renounce SHALL be offered on the connected wallet's own roles and sent by it, since only a holder can renounce; it SHALL be styled so it cannot be mistaken for Revoke.

#### Scenario: Renounce your own role
- **WHEN** the connected wallet holds a role
- **THEN** the Roles tab offers *Renounce* on it, sent by that wallet and styled apart from *Revoke*

### Requirement: The Timelock tab shows the timelock and who may act on it
The Timelock tab SHALL show:
- the timelock's address and minimum delay;
- who may propose, cancel and execute, checked with `hasRole` against the timelock itself, the paymaster, the connected wallet, and the addresses in the deployment's `addresses` configuration. The tab SHALL say that the timelock cannot list its holders, so only those addresses are checked;
- what the connected wallet may do on the timelock;
- the function delays, each with *Propose change*.

#### Scenario: Timelock roles checked
- **WHEN** an operator opens the Timelock tab
- **THEN** it shows the timelock's address and minimum delay, who may propose, cancel and execute among the checked addresses, and says that only those addresses are checked

### Requirement: The Timelock tab lists operations in full
The Timelock tab SHALL list the timelock's operations with a Pending, Done, Cancelled or All filter. Each operation SHALL show:
- its decoded calls;
- its full id;
- who scheduled it and when;
- its delay, salt and predecessor;
- when it is ready;
- its schedule and execute transactions.

An operation past its ready time that the chain still reports as waiting SHALL say it is executable from the chain's next block.

#### Scenario: Ready time passed on a waiting chain
- **WHEN** an operation is past its ready time and the chain still reports it as waiting
- **THEN** the operation says it is executable from the chain's next block

### Requirement: The Timelock tab reads far enough back, once
The Timelock tab SHALL read back at least as far as its longest function delay, and say which blocks were read.

A later refresh SHALL read only the blocks not yet read.

#### Scenario: Refresh after the first read
- **WHEN** the Timelock tab refreshes after its first read
- **THEN** it reads only the blocks not yet read, and says which blocks were read

### Requirement: The timelock is operable from the console
The console SHALL let a connected wallet do each of the following directly, and SHALL offer the matching Safe batch download when the wallet does not hold the role:

| Action | Role | Applies to |
| --- | --- | --- |
| Schedule | `PROPOSER_ROLE` | a proposal |
| Execute | `EXECUTOR_ROLE`, or anyone when executors are open | a ready operation |
| Cancel | `CANCELLER_ROLE` | a pending operation |

#### Scenario: Execute a ready operation
- **WHEN** an operation is ready, executors are open, and the operator confirms *Execute*
- **THEN** the wallet sends `executeBatch`, and the operation is listed as done once it confirms

### Requirement: The proposal dialog builds the operation
The proposal dialog SHALL:
- accept more than one call;
- accept a salt, a delay no shorter than the operation's minimum, and a predecessor chosen from pending operations;
- show the resulting operation id, when it would be ready if scheduled now, and whether it is already scheduled;
- copy the schedule, execute and cancel calldata.

#### Scenario: Role rotation
- **WHEN** an operator proposes granting `FEE_ADMIN_ROLE` to a new address and revoking it from the old one
- **THEN** the dialog builds one operation with both calls, and executing it applies both together

#### Scenario: Delay too short
- **WHEN** an operator sets a delay shorter than the operation's function delay
- **THEN** the delay field says the minimum, and no batch or schedule is offered

### Requirement: The console proposes changes to the timelock itself
The console SHALL offer proposals for:
- `updateDelay`;
- `setFunctionDelay`;
- granting and revoking the timelock's PROPOSER, CANCELLER and EXECUTOR roles.

#### Scenario: Minimum delay change
- **WHEN** an operator wants to change the timelock's minimum delay
- **THEN** the console offers to propose an `updateDelay` call

### Requirement: Queued changes are marked where they will land
When the timelock has a pending operation that changes something, that thing SHALL carry a marker saying a change is queued. The marker SHALL say what it changes to and when it is ready, or that it is ready now, and link to the operation in the Timelock tab. This applies to:
- a tenant's fee override or withdrawal address;
- the default fee;
- a role;
- the implementation;
- a timelock delay or timelock role.

#### Scenario: Withdrawal address change queued
- **WHEN** a `setTenantWithdrawAddress` operation for `byo` is waiting
- **THEN** the `byo` row and the withdrawal address on its page show the change as queued, with the time it is ready

### Requirement: The Overview shows what needs attention
The Overview SHALL list first the conditions that need an operator, each linking to where it is fixed:
- a tenant in deficit;
- a registered tenant with no balance;
- a registry tenant not registered on the selected chain;
- a tenant whose registry state and on-chain state disagree;
- a timelock operation that is ready;
- a bundler executor with no balance, or too little for 10 submissions;
- the paymaster paused;
- the solvency invariant failing.

#### Scenario: Unregistered tenant
- **WHEN** a registry tenant has no roster entry on the selected chain
- **THEN** the Overview lists it as not registered, by slug, with a link to its tenant page

#### Scenario: Nothing needs attention
- **WHEN** no condition applies
- **THEN** the Overview says nothing needs attention, and shows no empty list

### Requirement: Many conditions of one kind are shown as one line
When more than three conditions are of one kind, they SHALL be shown as one line that says how many, names the first three, newest first, each linking to its tenant page, and says how many more.

#### Scenario: Five tenants in deficit
- **WHEN** five tenants are in deficit
- **THEN** the Overview shows one line that says five, names the three newest, each linking to its tenant page, and says two more

### Requirement: The Overview summarises funds, solvency, configuration and queued changes
Below the conditions, the Overview SHALL show:
- the deposit, tenant balances, treasury and stake;
- solvency, with the slack between the deposit and what it owes;
- configuration, including the implementation;
- the queued changes.

Tenants SHALL be named by slug wherever one is known.

#### Scenario: Summary below the conditions
- **WHEN** an operator opens the Overview
- **THEN** below the conditions it shows the deposit, tenant balances, treasury and stake, solvency with its slack, the configuration with the implementation, and the queued changes

### Requirement: Usage is shown where wallet-api serves it
Where wallet-api serves `GET /v1/platform/usage`, the Overview SHALL also show the last seven days' usage, with refusals split by whose they are to fix, and each tenant page the same for that tenant. Where it does not, the usage card SHALL be absent, not a placeholder.

#### Scenario: No usage endpoint
- **WHEN** wallet-api does not serve `GET /v1/platform/usage`
- **THEN** the Overview shows no usage card and no placeholder for one

### Requirement: Activity shows settlements and admin events
The Activity tab SHALL list settled sponsorships, newest first, each with:
- time and block;
- tenant, by slug;
- account;
- outcome;
- gas, fee and overhead, each on its own;
- the tenant's balance after;
- the transaction.

Where the SDK provides `getAdminEvents`, the tab SHALL also list the admin events, newest first, each saying who did what and when, with its transaction.

#### Scenario: Admin events listed
- **WHEN** the SDK provides `getAdminEvents`
- **THEN** Activity lists the admin events, newest first, each saying who did what and when, with its transaction

### Requirement: Activity filters, totals, pages back and exports
The Activity tab SHALL filter by tenant, outcome and account, and SHALL show totals for what is loaded. *Look further back* SHALL load the next older window, with no fixed cap on rows. *Export CSV* SHALL download the loaded rows. A failed read SHALL be stated, not shown as an empty list.

#### Scenario: Tenant filter
- **WHEN** an operator filters Activity by `byo`
- **THEN** only `byo`'s settlements are listed, and the totals are `byo`'s

#### Scenario: Read failure
- **WHEN** the settlement read fails
- **THEN** Activity states the error and offers to retry, and does not say there is no activity

### Requirement: Health groups the checks and says what to do
The Health tab SHALL show the SDK's health report grouped as Funds, Keys and roles, and Registry and chain. Each check SHALL show its level in words, its figures, and, when it warns or fails, what to do with a link to where it is done.

#### Scenario: Warning check
- **WHEN** a check warns
- **THEN** the Health tab shows it under its group with its level in words, its figures, and what to do, with a link to where it is done

### Requirement: Health shows a check still being read, never as a pass
A check whose input has not been read yet (the implementation, a configured timelock, the ledger comparison, the chains) SHALL be shown as still being read, never left out, and a failed read SHALL be a warning. The summary SHALL say every check passes only once nothing is still being read.

#### Scenario: Timelock still being read
- **WHEN** the deployment configures a timelock and the console has not read it yet
- **THEN** Health shows the timelock as still being read, without the no-timelock warning, and does not say every check passes

### Requirement: Registry and chain checks compare the registry with the chain
Where the platform API is configured, the Registry and chain group SHALL add:
- every on-chain tenant has a registry row;
- wallet-api's ledger matches the chain for every tenant, with the lag in blocks.

A registry tenant not yet registered on chain SHALL be listed under Needs attention on the Overview, not as a failed check.

#### Scenario: Ledger behind the chain
- **WHEN** wallet-api's ledger for `byo` differs from the chain
- **THEN** the ledger check warns, naming `byo`, both figures and the lag in blocks

### Requirement: Keys and roles checks the release and the timelock
Keys and roles SHALL include whether the implementation is a contracts release and, where the deployment names its timelock, whether the timelock alone holds the timelocked roles and whether any delay is below the published value (paymaster-health-checks). A configured timelock not yet read SHALL give no timelock verdict, rather than "no timelock configured".

#### Scenario: Delay below the published value
- **WHEN** the deployment publishes an hour for `upgradeToAndCall` and its timelock waits 2 seconds
- **THEN** Keys and roles fails the delays check, naming `upgradeToAndCall`, 2s and 1h

### Requirement: The published timelock delays come from the deployment's configuration
The published delays SHALL come from the deployment's optional `timelockDelays` configuration, every delay or none; without it, Health SHALL say the delays were not compared.

#### Scenario: No published delays
- **WHEN** the deployment has no `timelockDelays` configuration
- **THEN** Health says the delays were not compared

### Requirement: Health shows each served chain where wallet-api reports it
Where wallet-api serves `GET /v1/platform/chains`, the tab SHALL show a Chains section with one row per served chain, judging head age and watcher lag against thresholds kept beside the SDK's, the watcher's from wallet-api's own limit. A local devnet that mines on demand SHALL have its head age shown, not judged. Where it reports the bundler's executors, the section SHALL list each with its balance and the submissions that balance pays for at the chain's gas price, failing under 10 and warning under 100, and SHALL flag a stuck lane: one held past the bundler's limit, or a transaction the bundler is not working on.

#### Scenario: Executor running dry
- **WHEN** an executor's balance pays for 40 submissions at the chain's gas price
- **THEN** the Chains section warns for that executor, naming its address and the 40 submissions

### Requirement: Registry and chain checks use wallet-api's drift result
Where wallet-api serves `GET /v1/platform/drift`, the Registry and chain group SHALL use its result, including whether each tenant's on-chain state matches its registry status. Each of these parts SHALL be absent, not a placeholder, where wallet-api does not serve its endpoint (`GET /v1/platform/chains` for the Chains section, `GET /v1/platform/drift` for the drift result).

#### Scenario: Drift reported
- **WHEN** wallet-api serves `GET /v1/platform/drift` and a tenant's on-chain state does not match its registry status
- **THEN** the Registry and chain group reports that mismatch from the drift result

#### Scenario: Neither endpoint served
- **WHEN** wallet-api serves neither `GET /v1/platform/chains` nor `GET /v1/platform/drift`
- **THEN** Health shows no Chains section and no placeholder for either part

### Requirement: Admins shows who may sign in and what changed
The Admins tab SHALL list the platform admins with id, address, who added them and when. It SHALL offer *Add an admin* with field-level validation of the id and the address, and *Remove* with confirmation. It SHALL NOT offer to remove yourself or the last admin, and SHALL say why. It SHALL state that removing an admin ends their sessions at once. It SHALL list the change history, newest first.

#### Scenario: Invalid address
- **WHEN** a platform admin types an address with 39 hex characters
- **THEN** the field says so and *Add admin* is disabled

#### Scenario: Remove yourself
- **WHEN** a platform admin views their own row
- **THEN** Remove is not offered and the row says an admin cannot remove themselves

### Requirement: Admins shows sign-ins and sessions where wallet-api returns them
Where wallet-api returns sign-in data, each admin SHALL show their last sign-in and number of active sessions, and the Admins tab SHALL list the signed-in admin's own sessions from the last 30 days, with *End* on every open one but the session in use.

#### Scenario: Own sessions
- **WHEN** wallet-api returns sign-in data and the signed-in admin has two open sessions
- **THEN** both are listed, and only the one not in use offers *End*
