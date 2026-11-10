# platform-console-tenants Specification

## Purpose

Defines what a signed-in platform admin sees and can do in the console's Platform area Tenants tab. It shows the backend tenant registry joined to the paymaster's on-chain roster, so a tenant that exists in one place and not the other is visible, and it gives every tenant operation of the platform API a guided flow, with the on-chain follow-up steps where they belong.

## Requirements

### Requirement: One tenant list joins the registry and the on-chain roster
The Tenants tab SHALL show one list. It SHALL contain the registry tenants from the platform API, newest first, joined by tenant id to the paymaster roster of the selected deployment's chain.

Tenants on the roster that match no registry row SHALL be listed in the same list, by id, marked as having no registry row.

Where the platform API is not configured, the list SHALL be the roster alone, by id, and the tenant page SHALL show the on-chain half only.

#### Scenario: Fixture tenants on the e2e stack
- **WHEN** a platform admin opens the Tenants tab on the two-tenant e2e stack
- **THEN** `stock` and `byo` are listed as active and *registered · enabled*

#### Scenario: Roster-only tenant
- **WHEN** the paymaster roster holds a tenant id that no registry row has
- **THEN** that id is listed, marked as having no registry row

### Requirement: Each tenant row shows its state, funds and next step
For each tenant the list SHALL show:
- slug, wallet origin and lifecycle status;
- the on-chain state: *registered · enabled*, *registered · disabled* or *not registered*;
- balance and deficit;
- the fee in effect (*default* or the override);
- the number of users;
- any queued timelock change;
- the next on-chain step, when there is one: *Register on chain* for a tenant not registered, *Fund* for one in deficit.

#### Scenario: Registry-only tenant
- **WHEN** a tenant was created through the platform API and never registered on-chain
- **THEN** its row reads *not registered* and its page offers *Register on <chain>*

### Requirement: The tenant list can be searched and filtered, and states totals
The list SHALL offer:
- search by slug, name, id or origin;
- a filter by state: all, active, suspended, needs attention;
- a control to include deleted tenants.

Under the list it SHALL state the totals on the selected chain: what is held, for how many tenants, and the total deficit. It SHALL also state whether any on-chain tenant lacks a registry row.

#### Scenario: Search by origin
- **WHEN** a platform admin searches the list by a tenant's wallet origin
- **THEN** that tenant is listed

### Requirement: Tenant rows open the tenant page, and one failed source keeps the other's rows
Each row SHALL be reachable by keyboard and SHALL open that tenant's page. Refreshing SHALL re-read both sources. A failure to read either source SHALL be stated, and the rows from the other source kept.

#### Scenario: Registry read fails
- **WHEN** the platform API read fails and the roster read succeeds
- **THEN** the list states the failure and keeps the roster's rows

### Requirement: The tenant page shows one tenant in full
Selecting a tenant SHALL open its page at `/tenants/<slug>`. The page SHALL show:
- every registry field, with its lifecycle state and version;
- the sponsorship policy as structured fields, not raw JSON;
- its admin keys by label, hash prefix, creator and creation time, never key material;
- user and credential counts, and the last user operation time.

#### Scenario: Admin keys listed
- **WHEN** a platform admin opens a tenant page
- **THEN** its admin keys are listed by label, hash prefix, creator and creation time, with no key material

### Requirement: The tenant page shows the tenant on chain and in the ledger
The tenant page SHALL show:
- its on-chain state on the selected chain: registration, enabled, balance, deficit, fee, withdrawal address, and the block it was read at;
- whether wallet-api's ledger agrees with that on-chain state; when it does not, both figures and the ledger's lag in blocks;
- for each other configured chain: registration and enabled state, read through `/v1/platform/rpc/<chainId>`, and the ledger's balance.

#### Scenario: Ledger disagrees with the chain
- **WHEN** wallet-api's ledger balance for the tenant differs from the paymaster's on the selected chain
- **THEN** the on-chain card shows both balances and how many blocks the ledger is behind

#### Scenario: Other deployments
- **WHEN** a tenant is registered on Ethereum Sepolia and not on the e2e devnet, and both are configured
- **THEN** the tenant page lists Ethereum Sepolia as *registered · enabled* with its balance, and the devnet as *not registered*

### Requirement: The tenant page shows the tenant's activity and history
The tenant page SHALL show:
- its recent sponsorships on the selected chain, with transaction links;
- its history, newest first, each entry with the before and after values it changed, and a control that loads older entries;
- its admin events on the selected chain (registration, funding, withdrawals, enabled state, fee, withdrawal address, and timelock calls that change them), listed apart from the registry's history, with a control that reads older blocks.

#### Scenario: History paging
- **WHEN** a tenant has more than 50 history entries and the platform admin asks for older entries
- **THEN** the next page is appended, until the API reports no further page

#### Scenario: Edit shown as a diff
- **WHEN** a tenant's display name was changed
- **THEN** its history entry shows the old and the new display name

### Requirement: The tenant page says which settings belong to the tenant
The tenant page SHALL show that sponsorship rules, transaction mappings and passkey origins belong to the tenant, are set with its admin keys through the admin API, and are not edited here.

Branding SHALL be labelled as stored but not yet used by any UI.

#### Scenario: Tenant-owned settings
- **WHEN** a platform admin opens a tenant page
- **THEN** it says the tenant's sponsorship rules, transaction mappings and passkey origins are set with its admin keys through the admin API, and offers no editor for them

### Requirement: Platform admins create tenants and receive their keys once
*Create tenant* SHALL offer these fields:
- slug, wallet origin and display name;
- expected, dApp and CORS origins;
- open registration;
- admin-key labels;
- sponsorship policy;
- branding;
- an optional fixed id.

On success the console SHALL show the generated admin keys once, each with a copy control, and say that they will not be shown again. Closing the dialog before every key has been copied SHALL ask for confirmation.

#### Scenario: Keys are not shown again
- **WHEN** the platform admin closes the keys view and reopens the tenant
- **THEN** the tenant page lists the keys by label and hash prefix only

#### Scenario: Closing before copying
- **WHEN** the platform admin closes the keys view without copying every key
- **THEN** the console asks for confirmation before closing

### Requirement: Create tenant leaves validation to the API
*Create tenant* SHALL submit its fields unchanged, and the API's validation is the only validation. A `400` SHALL show each issue against the field its path names. A `409` SHALL name the conflicting field or origin, and the tenant holding it.

#### Scenario: Invalid input
- **WHEN** the platform admin submits an expected origin outside the wallet origin's host
- **THEN** the issue is shown on the expected-origins field and no tenant is created

### Requirement: Create tenant offers to register the tenant on chain
After a successful create, the console SHALL offer *Register on <chain>*, which calls `registerTenant(id, withdrawAddress, slug)` through the connected wallet. That step requires `TENANT_ADMIN_ROLE` and is skipped when declined. The dialog SHALL state that:
- the wallet origin still has to be served;
- the tenant has no sponsorship rules until one of the shown keys is used to set them.

#### Scenario: Create and register
- **WHEN** a platform admin holding `TENANT_ADMIN_ROLE` creates a tenant and accepts *Register on <chain>*
- **THEN** the keys are shown once, the registration is submitted through the wallet, and the tenant's row then reads *registered · enabled*

### Requirement: Edits are optimistic and conflicts are shown
*Edit* SHALL be offered only for active, platform-admin-managed tenants. It SHALL prefill the mutable fields and send the tenant's version as `If-Match`. On `412`, the console SHALL reload the tenant, show that someone else changed it, and keep the platform admin's unsaved input available to re-apply. Identity fields SHALL be shown read-only.

#### Scenario: Concurrent edit
- **WHEN** the tenant changed between opening the editor and saving
- **THEN** the save is refused, the tenant page shows the current values, and the platform admin's input is kept

### Requirement: Lifecycle actions follow the tenant's state and owner
The tenant page SHALL offer only the actions that the tenant's state allows:

| Tenant | Offered |
| --- | --- |
| active | edit, issue key, revoke key, suspend |
| suspended | resume, revoke key, delete |
| deleted | none |

Suspend SHALL require a reason.

Delete SHALL require typing the slug and SHALL say that the slug, wallet origin and RP ID can never be used again. A `409` SHALL show the reason it names, and for funds the per-chain balance, deficit and block it returned.

#### Scenario: Delete confirmation
- **WHEN** a platform admin deletes a suspended tenant and types its slug
- **THEN** the tenant is deleted and leaves the default list; it is still shown when deleted tenants are included

#### Scenario: Delete refused for funds
- **WHEN** delete returns 409 `tenant-has-funds`
- **THEN** the dialog shows each chain's balance, deficit and block, and the tenant is unchanged

### Requirement: Suspend and resume offer the matching on-chain step
After a successful suspend, the console SHALL offer `setTenantEnabled(id, false)` on the selected chain where the tenant is *registered · enabled*, and explain that it closes the window in which earlier authorisations stay valid. It SHALL name every other configured chain where the tenant is still *registered · enabled*, since a write there needs the console switched to that deployment. Resume SHALL do the reverse for chains where the tenant is *registered · disabled*.

#### Scenario: Suspend and disable on-chain
- **WHEN** a platform admin with `TENANT_ADMIN_ROLE` suspends a tenant that is enabled on the selected chain and accepts the follow-up
- **THEN** the registry shows the tenant suspended and, after the transaction confirms, *registered · disabled*

### Requirement: Admin keys are issued once and revoked with care
*Issue key* SHALL take a label and show the generated key once, with a copy control. *Revoke* SHALL ask for confirmation. A `409 last-admin-key` SHALL be explained as the tenant's last key while registration is closed.

#### Scenario: Revoke the last key
- **WHEN** a platform admin revokes the only key of a tenant with closed registration
- **THEN** the console shows that the last key of a closed tenant cannot be revoked, and the key remains listed

### Requirement: On-chain steps need the role and never block the API action
A control the wallet cannot use SHALL be shown disabled, naming the role. A timelocked action SHALL offer *Propose* when a timelock is configured and the wallet lacks the role.

An on-chain follow-up to an API action SHALL run only after the API action completed. The API action SHALL NOT be rolled back if the on-chain step is declined or fails.

#### Scenario: No role
- **WHEN** a signed-in platform admin without `TENANT_ADMIN_ROLE` creates a tenant
- **THEN** the tenant is created and the *Register on <chain>* step is shown disabled, naming the missing role

#### Scenario: Withdrawal address proposed
- **WHEN** a platform admin without `WITHDRAW_ADDRESS_ADMIN_ROLE` changes a tenant's withdrawal address on a deployment with a timelock
- **THEN** the proposal dialog opens with a `setTenantWithdrawAddress` call for that tenant

### Requirement: Tenant on-chain actions follow the console's write rules
Every on-chain action on the tenant page SHALL follow the console's write rules:

| Action | Role | Timelocked |
| --- | --- | --- |
| Register | `TENANT_ADMIN_ROLE` | no |
| Disable or enable | `TENANT_ADMIN_ROLE` | no |
| Fund | none | no |
| Fee override | `FEE_ADMIN_ROLE` | yes |
| Clear the fee override | `FEE_ADMIN_ROLE` | yes |
| Withdrawal address | `WITHDRAW_ADDRESS_ADMIN_ROLE` | yes |

#### Scenario: Fund needs no role
- **WHEN** a connected wallet that holds no paymaster role opens a tenant page
- **THEN** *Fund* is enabled, and is sent directly rather than proposed
