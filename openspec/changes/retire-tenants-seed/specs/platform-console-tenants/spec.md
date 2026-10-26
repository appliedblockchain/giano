## MODIFIED Requirements

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
