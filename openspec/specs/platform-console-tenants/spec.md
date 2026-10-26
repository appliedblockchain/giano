# platform-console-tenants Specification

## Purpose

Defines what a signed-in platform admin sees and can do in the console's Platform area Tenants tab. It shows the backend tenant registry joined to the paymaster's on-chain roster, so a tenant that exists in one place and not the other is visible, and it gives every tenant operation of the platform API a guided flow, with the on-chain follow-up steps where they belong.

## Requirements

### Requirement: The registry is shown joined to the on-chain roster
The Tenants tab SHALL list the registry tenants from the platform API, newest first, with a filter that also shows deleted tenants. For each it SHALL show:
- slug, id, status, wallet origin and user count;
- for the selected deployment's chain, an on-chain column read from the paymaster roster and matched on tenant id: *registered · enabled*, *registered · disabled* or *not registered*.

Tenants on the roster that match no registry row SHALL be listed in their own group, by id. Refreshing SHALL re-read both sources.

#### Scenario: Fixture tenants on the e2e stack
- **WHEN** a platform admin opens the Tenants tab on the two-tenant e2e stack
- **THEN** `stock` and `byo` are listed as active and *registered · enabled*

#### Scenario: Registry-only tenant
- **WHEN** a tenant was created through the platform API and never registered on-chain
- **THEN** its on-chain column reads *not registered*

#### Scenario: Roster-only tenant
- **WHEN** the paymaster roster holds a tenant id that no registry row has
- **THEN** that id appears in the group of on-chain tenants with no registry row

### Requirement: The tenant drawer shows one tenant in full
Selecting a tenant SHALL open a drawer showing:
- every field, with its lifecycle state, owner and version;
- its admin keys by label, hash prefix, creator and creation time, never key material;
- user and credential counts, and the last user operation time;
- the per-chain ledger position;
- its history, newest first, with a control that loads older entries.

Branding SHALL be labelled as stored but not yet used by any UI.

#### Scenario: History paging
- **WHEN** a tenant has more than 50 history entries and the platform admin asks for older entries
- **THEN** the next page is appended, until the API reports no further page

### Requirement: Platform admins create tenants and receive their keys once
*Create tenant* SHALL offer these fields: slug, wallet origin, display name, expected, dApp and CORS origins, open registration, admin-key labels and an optional fixed id. It SHALL submit them unchanged, and the API's validation is the only validation. A `400` SHALL show each issue against the field its path names. A `409` SHALL name the conflicting field or origin, and the tenant holding it.

On success the console SHALL show the generated admin keys once, each with a copy control, and say that they will not be shown again. It SHALL then offer *Register on <chain>*, which calls `registerTenant(id, withdrawAddress, slug)` through the connected wallet. That step requires `TENANT_ADMIN_ROLE` and is skipped when declined. The dialog SHALL state that:
- the wallet origin still has to be served;
- the tenant has no sponsorship rules until one of the shown keys is used to set them.

#### Scenario: Create and register
- **WHEN** a platform admin holding `TENANT_ADMIN_ROLE` creates a tenant and accepts *Register on <chain>*
- **THEN** the keys are shown once, the registration is submitted through the wallet, and the tenant's on-chain column then reads *registered · enabled*

#### Scenario: Invalid input
- **WHEN** the platform admin submits an expected origin outside the wallet origin's host
- **THEN** the issue is shown on the expected-origins field and no tenant is created

#### Scenario: Keys are not shown again
- **WHEN** the platform admin closes the keys view and reopens the tenant
- **THEN** the drawer lists the keys by label and hash prefix only

### Requirement: Edits are optimistic and conflicts are shown
*Edit* SHALL be offered only for active, platform-admin-managed tenants. It SHALL prefill the mutable fields and send the tenant's version as `If-Match`. On `412`, the console SHALL reload the tenant, show that someone else changed it, and keep the platform admin's unsaved input available to re-apply. Identity fields SHALL be shown read-only.

#### Scenario: Concurrent edit
- **WHEN** the tenant changed between opening the editor and saving
- **THEN** the save is refused, the drawer shows the current values, and the platform admin's input is kept

### Requirement: Lifecycle actions follow the tenant's state and owner
The drawer SHALL offer only the actions that the tenant's state allows:

| Tenant | Offered |
| --- | --- |
| active | edit, issue key, revoke key, suspend |
| suspended | resume, revoke key, delete |
| deleted | none |

Suspend SHALL require a reason. After a successful suspend of a tenant that is *registered · enabled* on the selected chain, the console SHALL offer `setTenantEnabled(id, false)` and explain that it closes the window in which earlier authorisations stay valid. Resume SHALL offer the reverse for a *registered · disabled* tenant.

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

### Requirement: Admin keys are issued once and revoked with care
*Issue key* SHALL take a label and show the generated key once, with a copy control. *Revoke* SHALL ask for confirmation. A `409 last-admin-key` SHALL be explained as the tenant's last key while registration is closed.

#### Scenario: Revoke the last key
- **WHEN** a platform admin revokes the only key of a tenant with closed registration
- **THEN** the console shows that the last key of a closed tenant cannot be revoked, and the key remains listed

### Requirement: On-chain steps need the role and never block the API action
Every on-chain follow-up (register, disable, enable) SHALL be enabled only when the connected address holds `TENANT_ADMIN_ROLE` on the selected chain, as the console already reads it. Without the role, the step SHALL be shown disabled, with the reason. The API action that preceded it SHALL already have completed and SHALL NOT be rolled back if the on-chain step is declined or fails.

#### Scenario: No role
- **WHEN** a signed-in platform admin without `TENANT_ADMIN_ROLE` creates a tenant
- **THEN** the tenant is created and the *Register on <chain>* step is shown disabled, naming the missing role
