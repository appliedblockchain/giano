## Purpose

Defines a tenant's sponsorship rules as individual records that the tenant's backend can add, change and remove one at a time, and the versioned settings that sit beside them. This lets a tenant that deploys contracts at run time allow each new contract without rewriting its whole configuration.

## ADDED Requirements

### Requirement: A rule allows calls to one contract
A sponsorship rule SHALL belong to one tenant and one chain. It SHALL have:
- an `id`, assigned by wallet-api;
- a `contract` address, stored in lower case;
- `functions`: `"all"`, or a non-empty list of selectors or function signatures, stored as selectors;
- an optional `clientReference` of 1 to 128 characters from `A-Z a-z 0-9 . _ : -`;
- an optional `expiresAt`;
- `createdAt` and `updatedAt`.

A tenant and chain SHALL have at most one rule per contract. A rule is active when it has no `expiresAt`, or when its `expiresAt` is later than the time of the request.

#### Scenario: A signature is stored as its selector
- **WHEN** a tenant creates a rule with `functions: ["transfer(address,uint256)"]`
- **THEN** the stored rule lists `0xa9059cbb`

#### Scenario: A rule is per chain
- **WHEN** a tenant creates a rule on chain A
- **THEN** a call to that contract on chain B is not allowed by it

### Requirement: The tenant creates a rule with one request
`POST /v1/admin/sponsorship/rules` SHALL create one rule for the authenticated tenant on the selected chain, without reading or replacing the tenant's other rules. It SHALL respond `201` with the rule. It SHALL refuse:
- an invalid body, with `400` and per-field issues;
- an `expiresAt` that is not in the future, with `400`;
- a contract that already has an active rule, with `409 duplicate-contract` and the existing rule's `id`.

An expired rule for the same contract SHALL NOT block the create.

#### Scenario: Two creates at the same time
- **WHEN** a tenant's backend creates rules for two different contracts in two concurrent requests
- **THEN** both rules exist afterwards

#### Scenario: Same contract twice
- **WHEN** a tenant creates a rule for a contract that already has an active rule
- **THEN** the response is `409 duplicate-contract` and names the existing rule

### Requirement: A repeated client reference does not add a second rule
When a create names a `clientReference` that an existing rule of the same tenant and chain already has, wallet-api SHALL NOT create a second rule:
- when the `contract`, the `functions` and the `expiresAt` match, it SHALL respond `200` with the existing rule;
- otherwise it SHALL respond `409 client-reference-conflict` with the existing rule.

#### Scenario: A retried create
- **WHEN** a tenant's backend sends the same create, with the same `clientReference`, twice
- **THEN** the first response is `201`, the second is `200` with the same rule `id`, and one rule exists

#### Scenario: A reference reused for another contract
- **WHEN** a create names an existing `clientReference` with a different `contract`
- **THEN** the response is `409 client-reference-conflict`

### Requirement: The tenant reads its rules
`GET /v1/admin/sponsorship/rules` SHALL list the tenant's rules on the selected chain, newest first, a page at a time, with a cursor for the next page. By default it SHALL list only active rules. It SHALL accept the filters `contract`, `clientReference` and `includeExpired=true`. `GET /v1/admin/sponsorship/rules/:id` SHALL return one rule. A rule of another tenant, or of another chain, SHALL be answered `404`.

#### Scenario: Find a rule by reference
- **WHEN** a tenant lists its rules with `clientReference=milestone-42`
- **THEN** the response holds only the rule with that reference

#### Scenario: Another tenant's rule
- **WHEN** a tenant requests a rule `id` that belongs to another tenant
- **THEN** the response is `404`

### Requirement: The tenant changes or removes one rule
`PATCH /v1/admin/sponsorship/rules/:id` SHALL change only `functions` and `expiresAt`, where `expiresAt: null` removes the expiry. A body that names `contract` or `clientReference` SHALL be refused with `400`, because those fields cannot change. `DELETE /v1/admin/sponsorship/rules/:id` SHALL remove the rule and respond `204`. Both SHALL respond `404` for a rule the tenant does not have on that chain.

#### Scenario: Narrow a rule
- **WHEN** a tenant patches a rule from `functions: "all"` to `functions: ["release()"]`
- **THEN** later calls to other functions of that contract are refused with `function-not-allowed`

#### Scenario: Remove a rule
- **WHEN** a tenant deletes a rule
- **THEN** later calls to that contract are refused with `contract-not-allowed`

### Requirement: Active rules are capped per tenant and chain
wallet-api SHALL refuse a create that would make a tenant's active rules on one chain exceed `SPONSORSHIP_MAX_RULES_PER_CHAIN`, with `409 rule-limit-reached`. The limit SHALL hold under concurrent creates. Expired rules SHALL NOT count toward the limit.

#### Scenario: At the limit
- **WHEN** a tenant has as many active rules as the limit and creates another
- **THEN** the response is `409 rule-limit-reached` and no rule is added

#### Scenario: Expired rules free their place
- **WHEN** a tenant at the limit has one rule expire, and then creates a rule
- **THEN** the response is `201`

### Requirement: Only active rules allow calls
The sponsorship rules engine SHALL allow a call to an application contract only when an active rule of the session's tenant, on the operation's chain, names that contract and permits the call's selector. An expired rule SHALL be treated as absent. Wallet management SHALL still need no rule. A tenant with sponsorship enabled and no active rule SHALL still be refused with `no-sponsorship-config`, wallet management included.

#### Scenario: A rule added before the contract exists
- **WHEN** a tenant creates a rule for an address that a factory will deploy to, and a user's operation then deploys the contract and later calls it
- **THEN** the call to the deployed contract is sponsored

#### Scenario: An expired rule
- **WHEN** a rule's `expiresAt` has passed
- **THEN** a call to its contract is refused with `contract-not-allowed`

### Requirement: A decision records the rules that allowed it
Every sponsorship decision SHALL record the `id` of each rule that allowed one of its calls. `GET /v1/admin/sponsorship/decisions` SHALL return them as `ruleIds`. A decision with no application call, such as wallet management, SHALL record an empty list.

#### Scenario: A batch over two contracts
- **WHEN** an allowed operation calls two contracts that two rules allow
- **THEN** its decision lists both rule IDs

### Requirement: Every rule change is recorded and attributed
wallet-api SHALL record every creation, change and removal of a rule, including the removal of an expired rule by wallet-api, with:
- the rule as it was after the change, or before a removal;
- the action;
- the time;
- a hash of the admin key that made it, or none for a removal by wallet-api.

`GET /v1/admin/sponsorship/rules/events` SHALL list these records for the selected chain, newest first, a page at a time.

#### Scenario: Who removed a rule
- **WHEN** a tenant deletes a rule with an admin key
- **THEN** the events list a `deleted` record with that rule and the key's hash

### Requirement: Settings writes are versioned
The settings (`enabled`, `maxCostPerTxWei`, `walletManagement` and `lowBalanceThresholdWei`) SHALL carry a `version`, which every settings write increments. A tenant with no settings has version `0`. `GET /v1/admin/sponsorship` SHALL return the `version` in the body and as `ETag: "<version>"`. A `PUT` or `PATCH` with `If-Match: "<version>"` that does not match the stored version SHALL be refused with `412 version-mismatch`, with the current version in the body. A write without `If-Match` SHALL be accepted and is deprecated. Enabling sponsorship SHALL require `maxCostPerTxWei`, and SHALL NOT require any rule.

#### Scenario: Two edits from the same version
- **WHEN** two writes carry the same `If-Match` version
- **THEN** one succeeds, and the other receives `412` with the new version

#### Scenario: Enable before adding rules
- **WHEN** a tenant with no rules enables sponsorship with a cap
- **THEN** the write succeeds, and operations are refused with `no-sponsorship-config` until a rule is active

### Requirement: The allowlist field keeps working for one minor release
For compatibility, and as deprecated behaviour, the legacy rules are the rules with neither a `clientReference` nor an `expiresAt`, because the `allowlist` field cannot express either:
- `GET /v1/admin/sponsorship` SHALL return `config.allowlist`, built from the legacy rules;
- a `PUT` or `PATCH` whose body has `allowlist` SHALL replace the legacy rules with its entries, in the same transaction as the settings, and record each change as a rule event;
- such a write SHALL be refused with `400` when one of its contracts already has a rule that is not a legacy rule, or when it would exceed the rule limit;
- a settings write without `allowlist` SHALL NOT change any rule;
- rules that are not legacy rules SHALL NOT be changed by it.

#### Scenario: An existing script
- **WHEN** a script reads the configuration, adds an entry to `allowlist` and writes it back with `PUT`
- **THEN** the new contract has a rule, and the rules created with a `clientReference` or an `expiresAt` are unchanged

#### Scenario: Existing allowlists survive the upgrade
- **WHEN** wallet-api starts on a database whose settings hold an `allowlist`
- **THEN** each entry is a rule with no `clientReference`, and the same operations are sponsored as before
