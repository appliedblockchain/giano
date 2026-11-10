## Purpose

Defines how platform admins read sponsorship usage per chain and tenant from the decisions and settlements wallet-api records: what was allowed and refused and why, what settled, and what it cost, without reading the chain.

## ADDED Requirements

### Requirement: Platform admins read sponsorship usage across tenants
`GET /v1/platform/usage?chainId=<id>&since=<time>&until=<time>` SHALL require a platform admin session. `since` and `until` SHALL default to the last seven days and SHALL span at most 90 days. It SHALL return, for that chain and range, in total and per tenant by slug:
- sponsorship decisions allowed and refused, refusals by reason, and refusals by whose they are to fix: the tenant's own rules (its own switch included), its funds, the platform (an outage or its emergency stop), or other;
- operations settled, and of those reverted;
- gas sponsored, platform fees and overhead, in wei as decimal strings.

It SHALL be computed from the sponsorship decisions and settlements wallet-api already records, and SHALL NOT read the chain.

#### Scenario: Last seven days
- **WHEN** a platform admin requests usage for chain 84532 with no range
- **THEN** the response covers the last seven days, with totals and one entry per tenant that had a decision or a settlement

Settlements for a tenant id the deployment does not know SHALL be reported apart and SHALL NOT be counted in the total.

#### Scenario: Platform refusals apart from a tenant's
- **WHEN** a tenant's operations were refused for a contract outside its rules, others while the tenant had sponsorship switched off, and others while sponsorship was temporarily unavailable
- **THEN** the first two count under the tenant's rules and the third under the platform

#### Scenario: Another deployment's settlements
- **WHEN** the paymaster is shared and settled an operation for a tenant this deployment does not know
- **THEN** that settlement is reported apart and is not in the total

#### Scenario: Range too long
- **WHEN** the range spans more than 90 days
- **THEN** the response is 400, naming the limit

### Requirement: Usage queries stay cheap
A usage query over the maximum range SHALL be answered from indexed columns. If the existing indexes do not cover it, the change SHALL add one in a migration. The endpoint SHALL be rate limited with the other platform admin calls.

#### Scenario: Maximum range on a busy deployment
- **WHEN** usage is requested for 90 days
- **THEN** the query plan uses an index on the decision and settlement times
