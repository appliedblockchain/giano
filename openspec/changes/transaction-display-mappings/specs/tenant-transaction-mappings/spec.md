## Purpose

Lets a tenant publish, through its admin key, the ERC-7730 transaction mappings that explain its contracts to wallet users, per chain and per contract, and lets the tenant's wallet origin fetch the effective mapping set for a chain when a transaction is under review.

## ADDED Requirements

### Requirement: Mappings are tenant-scoped, per chain and per contract
The service SHALL store at most one mapping per `(tenant, chain, contract address)`. Contract addresses SHALL be normalised to lowercase on write. A tenant's admin key SHALL only ever read or change that tenant's mappings; another tenant's mapping SHALL be indistinguishable from a missing one.

#### Scenario: Cross-tenant isolation
- **WHEN** tenant B's admin key requests or deletes a mapping that exists for tenant A
- **THEN** the response is 404 not-found, and tenant A's mapping is unchanged

#### Scenario: Same contract on two chains
- **WHEN** a tenant writes a mapping for contract X on chain 8453 and another for contract X on chain 84532
- **THEN** both are stored independently and each is served only for its own chain

### Requirement: Admin can create or replace a mapping
`PUT /v1/admin/tx-mappings/:contract?chainId=…` with an ERC-7730 descriptor as the body SHALL validate the descriptor and, when valid, store it, replacing any existing mapping for that key. The chain SHALL be selected as for other admin routes: required when several chains are served, implied when one is. Validation SHALL reject, with one issue per violation each carrying a JSON path and message and no partial write: a descriptor that fails ERC-7730 validation; a descriptor whose deployments do not include the requested `(chainId, contract)`; a body larger than 64 KiB; a `:contract` that is not a 20-byte hex address.

#### Scenario: Valid write
- **WHEN** an admin PUTs a valid descriptor bound to the requested chain and contract
- **THEN** the response is 200 with the stored descriptor and an `updatedAt` timestamp, and a subsequent read returns it

#### Scenario: Descriptor not bound to the requested contract
- **WHEN** the descriptor's deployments list a different address, or the same address on another chain only
- **THEN** the response is 400 with an issue at the deployments path explaining the mismatch, and nothing is stored

#### Scenario: Invalid descriptor
- **WHEN** the descriptor references a parameter path that does not exist in the function ABI
- **THEN** the response is 400 with the issue path and message, and nothing is stored

#### Scenario: Replace
- **WHEN** an admin PUTs a second descriptor for a key that already has one
- **THEN** the new descriptor replaces the old one atomically, and the old one is retained in history

### Requirement: Admin can list, read and delete mappings
`GET /v1/admin/tx-mappings?chainId=…` SHALL list the tenant's mappings for the chain (contract, descriptor, `updatedAt`). `GET /v1/admin/tx-mappings/:contract?chainId=…` SHALL return one. `DELETE /v1/admin/tx-mappings/:contract?chainId=…` SHALL remove one and return 204, or 404 when absent.

#### Scenario: List is per chain
- **WHEN** a tenant has mappings on two chains and lists with `chainId` of one
- **THEN** only that chain's mappings are returned

#### Scenario: Delete
- **WHEN** an admin deletes an existing mapping
- **THEN** the response is 204, the mapping no longer appears in lists or reads, and the deletion is recorded in history

### Requirement: Every change is recorded in history
Each successful write or delete SHALL append a history entry with the tenant, chain, contract, action, the descriptor written (or none for a delete), the time, and a hash of the admin key that made the change, never the key itself. `GET /v1/admin/tx-mappings/history?chainId=…` SHALL return the tenant's entries for the chain, newest first, paginated.

#### Scenario: Audit trail
- **WHEN** an admin writes, replaces, then deletes a mapping
- **THEN** history lists three entries in reverse order, each attributed to the admin key's hash, and the middle entry carries the first descriptor

### Requirement: The wallet origin reads the effective mapping set
`GET /v1/tx-mappings?chainId=…` SHALL return the requesting tenant's mappings for that chain as a list of descriptors plus the latest `updatedAt`. The tenant SHALL be resolved from the request's Origin header when present, as for ceremony routes, and otherwise from the Host header, as for the well-known WebAuthn document, because a same-origin GET through the wallet's own proxy carries no Origin. No session SHALL be required, because the mapping set is not user-specific and the review screen must not depend on session restore timing. A request that names no registered tenant by either header SHALL be refused with 403. The chain SHALL be selected as on other chain-scoped routes: 400 when unsupported.

#### Scenario: Wallet fetches mappings by Origin
- **WHEN** a request arrives with a registered tenant Origin and a served `chainId`
- **THEN** the response is 200 with every stored, currently valid descriptor for that tenant and chain

#### Scenario: Wallet fetches mappings by Host
- **WHEN** a request arrives with no Origin and a Host whose hostname is a registered tenant's wallet host
- **THEN** the response is 200 with that tenant's descriptors

#### Scenario: Unknown caller
- **WHEN** a request arrives with an unregistered Origin, or with no Origin and an unregistered Host
- **THEN** the response is 403 unknown-tenant and no mapping is disclosed

#### Scenario: No mappings yet
- **WHEN** the tenant has stored nothing for the chain
- **THEN** the response is 200 with an empty list, not 404

### Requirement: A stored mapping that no longer validates is skipped, not served
Descriptors SHALL be re-validated when read for serving. One that fails (for example after the validation rules tighten) SHALL be omitted from the served set and logged with its key, and SHALL still appear in the admin list marked invalid, so an operator can fix it while users are never shown a description built from a descriptor the service no longer trusts.

#### Scenario: Stale descriptor
- **WHEN** a stored descriptor fails current validation
- **THEN** the wallet-facing read omits it, a warning is logged naming tenant, chain and contract, and the admin list returns it with a validity flag and issues

### Requirement: OpenAPI document reflects the routes
The service's committed OpenAPI document SHALL include the new routes with their schemas, and the existing drift check SHALL pass.

#### Scenario: Drift gate
- **WHEN** the OpenAPI drift check runs after the routes are added
- **THEN** it passes, and the document lists the six new operations
