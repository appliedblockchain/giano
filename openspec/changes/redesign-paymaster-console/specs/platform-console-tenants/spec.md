## RENAMED Requirements

- FROM: `### Requirement: The registry is shown joined to the on-chain roster`
- TO: `### Requirement: One tenant list joins the registry and the on-chain roster`
- FROM: `### Requirement: The tenant drawer shows one tenant in full`
- TO: `### Requirement: The tenant page shows one tenant in full`

## MODIFIED Requirements

### Requirement: One tenant list joins the registry and the on-chain roster
The Tenants tab SHALL show one list. It SHALL contain the registry tenants from the platform API, newest first, joined by tenant id to the paymaster roster of the selected deployment's chain. For each tenant it SHALL show:
- slug, wallet origin and lifecycle status;
- the on-chain state: *registered · enabled*, *registered · disabled* or *not registered*;
- balance and deficit;
- the fee in effect (*default* or the override);
- any queued timelock change.

Tenants on the roster that match no registry row SHALL be listed in the same list, by id, marked as having no registry row.

The list SHALL offer:
- search by slug, id or origin;
- a filter by state;
- a control to include deleted tenants.

Each row SHALL be reachable by keyboard and SHALL open that tenant's page. Refreshing SHALL re-read both sources. A failure to read either source SHALL be stated, and the rows from the other source kept.

#### Scenario: Fixture tenants on the e2e stack
- **WHEN** a platform admin opens the Tenants tab on the two-tenant e2e stack
- **THEN** `stock` and `byo` are listed as active and *registered · enabled*

#### Scenario: Registry-only tenant
- **WHEN** a tenant was created through the platform API and never registered on-chain
- **THEN** its row reads *not registered* and its page offers *Register on <chain>*

#### Scenario: Roster-only tenant
- **WHEN** the paymaster roster holds a tenant id that no registry row has
- **THEN** that id is listed, marked as having no registry row

### Requirement: The tenant page shows one tenant in full
Selecting a tenant SHALL open its page at `/tenants/<slug>`. The page SHALL show:
- every registry field, with its lifecycle state, owner and version;
- the sponsorship policy as structured fields, not raw JSON;
- its admin keys by label, hash prefix, creator and creation time, never key material;
- user and credential counts, and the last user operation time;
- its on-chain state on the selected chain: registration, enabled, balance, deficit, fee, withdrawal address;
- its ledger position on each other configured chain;
- its recent sponsorships on the selected chain, with transaction links;
- its history, newest first, each entry with the before and after values it changed, and a control that loads older entries.

Branding SHALL be labelled as stored but not yet used by any UI.

#### Scenario: History paging
- **WHEN** a tenant has more than 50 history entries and the platform admin asks for older entries
- **THEN** the next page is appended, until the API reports no further page

#### Scenario: Edit shown as a diff
- **WHEN** a tenant's display name was changed
- **THEN** its history entry shows the old and the new display name

### Requirement: Platform admins create tenants and receive their keys once
*Create tenant* SHALL offer these fields:
- slug, wallet origin and display name;
- expected, dApp and CORS origins;
- open registration;
- admin-key labels;
- sponsorship policy;
- branding;
- an optional fixed id.

It SHALL submit them unchanged, and the API's validation is the only validation. A `400` SHALL show each issue against the field its path names. A `409` SHALL name the conflicting field or origin, and the tenant holding it.

On success the console SHALL show the generated admin keys once, each with a copy control, and say that they will not be shown again. Closing the dialog before every key has been copied SHALL ask for confirmation.

It SHALL then offer *Register on <chain>*, which calls `registerTenant(id, withdrawAddress, slug)` through the connected wallet. That step requires `TENANT_ADMIN_ROLE` and is skipped when declined. The dialog SHALL state that:
- the wallet origin still has to be served;
- the tenant has no sponsorship rules until one of the shown keys is used to set them.

#### Scenario: Create and register
- **WHEN** a platform admin holding `TENANT_ADMIN_ROLE` creates a tenant and accepts *Register on <chain>*
- **THEN** the keys are shown once, the registration is submitted through the wallet, and the tenant's row then reads *registered · enabled*

#### Scenario: Invalid input
- **WHEN** the platform admin submits an expected origin outside the wallet origin's host
- **THEN** the issue is shown on the expected-origins field and no tenant is created

#### Scenario: Keys are not shown again
- **WHEN** the platform admin closes the keys view and reopens the tenant
- **THEN** the tenant page lists the keys by label and hash prefix only

#### Scenario: Closing before copying
- **WHEN** the platform admin closes the keys view without copying every key
- **THEN** the console asks for confirmation before closing

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

Suspend SHALL require a reason. After a successful suspend, the console SHALL offer `setTenantEnabled(id, false)` on every configured chain where the tenant is *registered · enabled*, and explain that it closes the window in which earlier authorisations stay valid. Resume SHALL offer the reverse on every chain where the tenant is *registered · disabled*.

Delete SHALL require typing the slug and SHALL say that the slug, wallet origin and RP ID can never be used again. A `409` SHALL show the reason it names, and for funds the per-chain balance, deficit and block it returned.

#### Scenario: Suspend and disable on-chain
- **WHEN** a platform admin with `TENANT_ADMIN_ROLE` suspends a tenant that is enabled on the selected chain and accepts the follow-up
- **THEN** the registry shows the tenant suspended and, after the transaction confirms, *registered · disabled*

#### Scenario: Delete confirmation
- **WHEN** a platform admin deletes a suspended tenant and types its slug
- **THEN** the tenant is deleted and leaves the default list; it is still shown when deleted tenants are included

#### Scenario: Delete refused for funds
- **WHEN** delete returns 409 `tenant-has-funds`
- **THEN** the dialog shows each chain's balance, deficit and block, and the tenant is unchanged

### Requirement: On-chain steps need the role and never block the API action
Every on-chain action on the tenant page SHALL follow the console's write rules:

| Action | Role | Timelocked |
| --- | --- | --- |
| Register | `TENANT_ADMIN_ROLE` | no |
| Disable or enable | `TENANT_ADMIN_ROLE` | no |
| Fund | none | no |
| Fee override | `FEE_ADMIN_ROLE` | yes |
| Clear the fee override | `FEE_ADMIN_ROLE` | yes |
| Withdrawal address | `WITHDRAW_ADDRESS_ADMIN_ROLE` | yes |

A control the wallet cannot use SHALL be shown disabled, naming the role. A timelocked action SHALL offer *Propose* when a timelock is configured and the wallet lacks the role.

An on-chain follow-up to an API action SHALL run only after the API action completed. The API action SHALL NOT be rolled back if the on-chain step is declined or fails.

#### Scenario: No role
- **WHEN** a signed-in platform admin without `TENANT_ADMIN_ROLE` creates a tenant
- **THEN** the tenant is created and the *Register on <chain>* step is shown disabled, naming the missing role

#### Scenario: Withdrawal address proposed
- **WHEN** a platform admin without `WITHDRAW_ADDRESS_ADMIN_ROLE` changes a tenant's withdrawal address on a deployment with a timelock
- **THEN** the proposal dialog opens with a `setTenantWithdrawAddress` call for that tenant
