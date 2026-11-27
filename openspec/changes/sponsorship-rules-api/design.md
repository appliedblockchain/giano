## Context

A tenant's sponsorship configuration is one JSON value per tenant and chain, in `tenant_sponsorship.config`. Its `allowlist` array is the only way to name a contract. Every write goes through `PUT` or `PATCH /v1/admin/sponsorship`. `PATCH` merges top-level fields, so it also replaces the whole array. Every write appends the full value to `tenant_sponsorship_history`.

`sponsorship-service.ts` reads the value once per decision. It passes the value to `evaluateSponsorship` in `sponsorship-rules.ts`, a pure function that both the pre-approval check and the signing path use. The decision, with every rule result, goes to `sponsorship_decisions`.

The tenant platform API already uses optimistic versioning: `PATCH /v1/platform/tenants/:slug` requires `If-Match` and answers `412 version-mismatch`.

See proposal.md for why rules become records.

## Goals / Non-Goals

**Goals:**
- One request adds, changes or removes one rule, and concurrent requests never lose each other's changes.
- The rules engine stays a pure function. All reads happen in the service before evaluation.
- An upgrade sponsors exactly what it sponsored before, and a rollback to the previous release keeps the rules that existed before the upgrade working.

**Non-Goals:**
- Rules that match contracts by factory, by code or by deployment event. See Decisions D1.
- A console UI for rules. The paymaster console does not edit tenant allowlists today.
- Changes to the relay policy (`USEROP_ALLOWED_TARGETS`). G6 owns it.
- A fix for G40, which should land before a tenant depends on run-time rules. Rules widen the set of targets a tenant pays for, so the check that the sender runs the canonical wallet matters more.

## Decisions

### D1. Rules name exact addresses; the tenant adds them

A rule names one contract address. A tenant that deploys contracts at run time adds a rule for each one, before the deployment, because the address is predictable (`CREATE2`, or `cloneDeterministic`).

Alternatives considered:
- **The factory confirms it made the contract** (a view such as `isGroup(address)`). This needs the tenant's factory to implement our interface and keep a record. It also proves nothing when the factory is permissionless: "deployed by the factory" does not mean "deployed for this tenant".
- **Match the code** (a fingerprint, or "an EIP-1167 clone of this implementation"). Anyone can deploy a clone of the same implementation with their own storage, including the token it moves.
- **Match the factory's creation event**, with an optional deployer. wallet-api would have to search logs arbitrarily far back for each new target. That is slow, depends on the RPC provider, and breaks when a provider limits log ranges.

### D2. One table, one row per rule

`tenant_sponsorship_rules` has these columns:
- `id uuid`;
- `tenant_id`, `chain_id`;
- `contract text`, lower case;
- `functions jsonb` (`"all"` or a list of selectors);
- `client_reference text null`;
- `expires_at timestamptz null`;
- `created_at`, `updated_at`;
- `created_by_key_hash`, `updated_by_key_hash`.

Constraints:
- `UNIQUE (tenant_id, chain_id, contract)`;
- a partial `UNIQUE (tenant_id, chain_id, client_reference) WHERE client_reference IS NOT NULL`;
- an index on `(tenant_id, chain_id, expires_at)` for counting and purging.

The unique keys enforce "one rule per contract" and "one rule per reference" in the database, so concurrent creates cannot both pass a check-then-insert.

The alternative was to keep the array and edit it with `jsonb` operators under a row lock. It has no uniqueness per element and no index by contract, and every change would still rewrite the whole value and its history row.

### D3. An expired rule is absent, and wallet-api removes it lazily

Evaluation and the cap filter on `expires_at IS NULL OR expires_at > $now`. A partial unique index cannot use `now()`, so the contract key is a plain unique key. The create transaction does this:
- it deletes any expired rule for the same contract first, so the expired rule does not block the new one;
- it deletes up to 500 other expired rules of the same tenant and chain;
- it records each removal as an `expired-removed` event with no key hash.

Expired rules of a tenant that never creates again stay in the table, are listed only with `includeExpired=true`, and cost nothing at evaluation. A scheduled purge would remove them too, but it needs a job and a lock in every replica. Removal at create time is enough for the case that grows: a tenant that adds rules all the time.

### D4. The cap holds under concurrency through a per-tenant lock

A create, the deprecated `allowlist` write, and a `PATCH` that removes an expiry each take `pg_advisory_xact_lock` on a key derived from `(tenant_id, chain_id)`. They then count active rules and insert. Creates for different tenants do not wait on each other.

Alternatives considered:
- `SERIALIZABLE` isolation needs a retry loop around every write.
- A counter column on `tenant_sponsorship` needs that row to exist before the first rule, and it drifts when rules expire.

`SPONSORSHIP_MAX_RULES_PER_CHAIN` defaults to 1000. A tenant that deploys one escrow per payment, with expiries, stays far below it. A tenant without expiries hits it and has to clean up, which is the purpose of the cap.

### D5. Idempotency by client reference

A create with a `clientReference` first looks up that reference. Because creates hold the lock from D4, a lookup followed by an insert cannot race another create for the same tenant. The unique index is the backstop.

The comparison covers `contract`, the normalised `functions` (as sets) and `expiresAt`:
- if they are equal, the response is `200` with the existing rule;
- if not, the response is `409 client-reference-conflict`.

A retry after the rule's `expiresAt` has passed is refused with `400`, because its `expiresAt` is no longer in the future. A tenant that retries that late is creating a new rule anyway.

### D6. The engine gets only the rules it needs, with their IDs

Before evaluating, the service:
- decodes the targets (the engine's own `decodeInnerCalls`);
- reads the active rules for those targets in one indexed query;
- reads whether the tenant has any active rule, with an `EXISTS` query.

The evaluation input changes in two ways:
- `config.allowlist` becomes `rules: { id, contract, functions }[]`;
- `hasActiveRules` is added, to keep `no-sponsorship-config` for a tenant with no rules.

The engine returns `ruleIds`, the rules that matched an application call, in call order with no repeats. `sponsorship_decisions.rule_ids uuid[] NOT NULL DEFAULT '{}'` stores them.

Reading every rule would not scale to the cap. Reading rules inside the engine would break D-pure: the pre-approval check and the signing path must stay one implementation.

### D7. Settings versions follow the tenant precedent, but `If-Match` stays optional

`tenant_sponsorship.version integer NOT NULL DEFAULT 0`, and the migration sets existing rows to `1`.
- A write with `If-Match: "n"` updates `WHERE version = n`. For `n = 0` it inserts with `ON CONFLICT DO NOTHING`.
- When no row changes, the response is `412` with the current version.
- A write without `If-Match` increments unconditionally.

Platform tenant writes require the header (`428`). Here, requiring it would break every existing provisioning script and tenant backend at once. So the header is optional and deprecated-when-absent for one minor release, and the README announces that it becomes required.

### D8. `allowlist` stays in the stored settings as a mirror

The stored settings keep an `allowlist` array that mirrors the legacy rules: those with neither a `clientReference` nor an `expiresAt`, which is what the old field could express. A rule with an expiry is left out because the previous release would sponsor it forever after a rollback. Evaluation never reads it. Every write that changes a legacy rule rewrites the mirror in the same transaction: the deprecated `PUT`/`PATCH` field, and a rules-API create, change or delete that adds or removes a legacy rule.

This does two things:
- `GET` returns the deprecated field without a join;
- a rollback to the previous release still sponsors every contract that was allowed before the upgrade.

Rules with a `clientReference` or an `expiresAt` are not in the mirror. They stop working during a rollback, and they work again when the new release returns. A tenant with only referenced rules and sponsorship enabled fails the old release's "non-empty allowlist" check during a rollback, and the old release reads that as deny-all. That is the safe direction.

The mirror and the deprecated field are removed together in the next minor.

### D9. Rule events are their own table

`tenant_sponsorship_rule_events` has these columns:
- `id`;
- `tenant_id`, `chain_id`;
- `rule_id`, not a foreign key, because a deleted rule keeps its events;
- `action`, one of `created`, `updated`, `deleted` and `expired-removed`;
- `rule jsonb`;
- `created_at`;
- `created_by_key_hash`.

`tenant_sponsorship_history` keeps recording full settings values, mirror included. Writing a full settings snapshot for every rule change would make that history grow with every escrow.

### D10. The test fixture is an escrow factory

`GianoTestEscrowFactory`:
- deploys `GianoTestEscrow` clones with solady's `LibClone.cloneDeterministic`, which is the standard EIP-1167 proxy;
- `predictEscrowAddress(salt)` returns the address a clone will have;
- `createEscrow(salt)` is permissionless and emits `EscrowCloneCreated`;
- it keeps no record.

This matches the tenant's real pattern. The fixture artifact refuses immutables, so the implementation address is a storage variable set in the constructor. The unmerged `GianoTestGroupFactory` fixture is removed.

The e2e test:
- predicts an escrow address;
- creates a rule for it with a `clientReference` and an `expiresAt`;
- deploys the escrow through the factory, under sponsorship;
- calls the escrow, under sponsorship;
- checks that the decision names the rule;
- then checks that a deleted or expired rule refuses the next call.

## Risks / Trade-offs

- **[Two paths write legacy rules during the deprecation window]** → Both run in one transaction under the D4 lock and rewrite the mirror there. Unit tests cover each path against the mirror.
- **[A tenant backend creates the rule but the deployment fails]** → The rule names an empty address, and it allows nothing until code exists there. An `expiresAt` removes it. The same salt can be retried.
- **[A rule names an address before anyone deploys there]** → When the factory is permissionless and the salt is not bound to the caller, someone else can deploy first at the predicted address, with their own initial state, and the tenant's rule then sponsors calls to that contract. The fixture binds the salt to the caller, and the README tells tenants to do the same or to check the deployed contract before relying on the rule. Short expiries limit the window.
- **[Migration number collides with open PRs]** (#366 and the PS-1 stack add `0014`/`0015`) → Renumber to the next free number just before merge. The runner tracks files by name, so the number only needs to be unique and ordered.
- **[Evaluation gains a query]** → One indexed `IN` query plus an `EXISTS`, replacing the JSON parse of the whole allowlist. Both queries run with the balance read.
- **[`sponsorship-service.ts` conflicts with #358 and #366]** → The change to the service is limited to `getConfig` and the evaluation input. Rebase after they merge.

## Migration Plan

1. The migration:
   - creates the two tables;
   - adds `tenant_sponsorship.version` (existing rows set to `1`) and `sponsorship_decisions.rule_ids`;
   - inserts one rule, with no reference and no expiry, for every `allowlist` entry in every row, recorded as `created` events with no key hash.

   It leaves `config.allowlist` in place as the D8 mirror.
2. Deploy wallet-api with the migration. It is additive, so the previous release still runs against the migrated database.
3. Move `e2e/devnet/provision-sponsorship.mjs`, `deploy/contracts/provision-sponsorship.sh` and `packages/contracts/scripts/rehearse.ts` to the rules API, with `If-Match`.
4. Rollback: deploy the previous release and leave the database as it is. See D8 for what keeps working. Re-deploying the new release needs no data fix-up.

## Open Questions

- The default for `SPONSORSHIP_MAX_RULES_PER_CHAIN` (1000) and the purge batch (500) are first guesses. They can change after the first tenant runs on dev, without changing the API.
