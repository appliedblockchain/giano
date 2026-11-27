## Why

Some tenants deploy contracts at run time. One deploys an escrow contract for every payment, as an EIP-1167 clone made by a permissionless factory. The sponsorship allowlist names fixed contract addresses, so calls to a contract deployed after the tenant wrote its allowlist are refused (`contract-not-allowed`). The e2e test `e2e/tests/deployed-contracts.spec.ts` shows this.

The tenant can add each new address today, but only by rewriting the whole configuration: `PUT` and `PATCH /v1/admin/sponsorship` replace the `allowlist` array. Two writes at the same time can lose one rule, and the array has no limit. A tenant backend that adds a rule for every escrow needs to add one rule, without reading and rewriting the others.

The escrow addresses are deterministic: the factory can predict them before it deploys. So the tenant's backend can add the rule before the deployment, and the user never waits.

## What Changes

- A new rules resource, per tenant and chain: `POST`, `GET`, `PATCH` and `DELETE /v1/admin/sponsorship/rules`. A rule has:
  - an `id`;
  - a `contract`;
  - `functions` (`"all"` or a list);
  - an optional `clientReference`: a create that repeats a reference returns the existing rule instead of adding a second one;
  - an optional `expiresAt`: after that time the rule no longer allows anything.
- Rules move out of the settings into their own table. A migration copies every stored `allowlist` entry into a rule.
- The settings (`enabled`, `maxCostPerTxWei`, `walletManagement`, `lowBalanceThresholdWei`) stay on `GET`, `PUT` and `PATCH /v1/admin/sponsorship`. They now carry a `version`. A write with `If-Match: "<version>"` that does not match the stored version is refused with `412`.
- A cap on the number of active rules per tenant and chain (`SPONSORSHIP_MAX_RULES_PER_CHAIN`). A create over the cap is refused with `409`.
- Every sponsorship decision records the IDs of the rules that allowed its calls.
- Compatibility for one minor release:
  - `PUT` and `PATCH` still accept `allowlist` and replace the legacy rules (no `clientReference` and no `expiresAt`) with it;
  - `GET` still returns `allowlist`, built from the legacy rules;
  - a write without `If-Match` is still accepted.

  These are deprecated, and the README says so.
- The relay's `USEROP_ALLOWED_TARGETS` is not changed. A deployment that serves such a tenant sets it to `"any"` (G6, #357), and the tenant's rules decide which targets are sponsored.
- The test fixture becomes the escrow pattern:
  - a permissionless factory of EIP-1167 clones with `predictEscrowAddress`;
  - the e2e test adds the rule at the predicted address before the deployment;
  - the test then checks the sponsored call, the expiry and the deletion.

## Capabilities

### New Capabilities

- `sponsorship-rules`: the tenant's sponsorship rules as individual records, and the settings beside them. It covers:
  - the CRUD API, idempotent creates, expiry and the cap;
  - the versioned settings writes;
  - how evaluation uses active rules;
  - recording the rule IDs on each decision;
  - the deprecated `allowlist` field.

### Modified Capabilities

None. `sponsorship-self-calls` still holds: wallet management needs no rule.

## Impact

- `services/wallet-api`:
  - a migration: the new `tenant_sponsorship_rules` and `tenant_sponsorship_rule_events` tables, a `version` column on `tenant_sponsorship`, and a `rule_ids` column on `sponsorship_decisions`;
  - `src/db/schema.ts`, `services/sponsorship-config.ts`, `services/sponsorship-rules.ts`, `services/sponsorship-service.ts`, `routes/admin-sponsorship.ts` and `config.ts`;
  - `openapi/openapi.json`, the README and tests.
- `packages/contracts`: the `GianoTestGroupFactory` fixture is replaced by `GianoTestEscrowFactory` (with `GianoTestEscrow`). It is not merged yet, so no deployed chain holds it.
- `e2e`:
  - `tests/deployed-contracts.spec.ts`;
  - `tests/sponsorship.spec.ts` (`withConfig` moves to the rules API);
  - `devnet/provision-sponsorship.mjs`.
- `deploy/contracts/provision-sponsorship.sh` and `packages/contracts/scripts/rehearse.ts` keep working through the deprecated `allowlist` field. They move to the rules API in this change.
- Open PRs:
  - #366 (migration `0014_chain_relay_policy`) and the PS-1 stack (#348 `0014`, #351 `0015`) also add migrations. This change takes the next free number when it merges.
  - #358 and #366 touch `sponsorship-service.ts`.
- Specs: `specs/PAYMASTER-SPECS.md` and `specs/INTEGRATION.md` describe the allowlist as an array in the settings. They are updated.
