## 1. Escrow fixture and the finding (branch `feat/ps4-sponsor-deployed-contracts`)

- [x] 1.1 Replace `GianoTestGroupFactory.sol` with `GianoTestEscrowFactory.sol`:
  - `GianoTestEscrowFactory`: solady `LibClone.cloneDeterministic`, permissionless `createEscrow(bytes32 salt)` with the salt bound to the caller, `predictEscrowAddress(address payer, bytes32 salt)`, `EscrowCloneCreated` event, implementation in storage;
  - `GianoTestEscrow`: `initialize(payer)`, `confirm()`, `release()`.
- [x] 1.2 Update the `FIXTURE_CONTRACTS` entry and `fixtures/README.md`, run `pnpm gen:fixtures` and `pnpm gen:abis`, and update the changeset.
- [x] 1.3 Rewrite `e2e/tests/deployed-contracts.spec.ts` on today's API: the deployment through the allow-listed factory is sponsored, the call to the new escrow is refused with `contract-not-allowed`, and it is sponsored once the escrow's address is in the allowlist.
- [x] 1.4 Run `forge test`, `pnpm test:deploy`, `gen:fixtures --check`, the e2e spec, lint and typecheck.

## 2. Storage and evaluation (wallet-api)

- [ ] 2.1 Migration:
  - create `tenant_sponsorship_rules` and `tenant_sponsorship_rule_events`;
  - add `tenant_sponsorship.version` (existing rows set to 1) and `sponsorship_decisions.rule_ids`;
  - copy every stored `allowlist` entry into a rule, with a `created` event.
- [ ] 2.2 Add the tables and columns to `src/db/schema.ts`.
- [ ] 2.3 In `sponsorship-config.ts`:
  - split the settings schema from a rule schema (contract, functions, clientReference, expiresAt);
  - settings no longer require a non-empty allowlist, and still accept `allowlist` as a deprecated input;
  - add `SPONSORSHIP_MAX_RULES_PER_CHAIN` to `config.ts`.
- [ ] 2.4 In `sponsorship-rules.ts`:
  - evaluate against `rules` (with IDs) and `hasActiveRules` instead of `config.allowlist`;
  - return `ruleIds`;
  - update the unit tests, including wallet management with no rules and `no-sponsorship-config` with no active rule.
- [ ] 2.5 In `sponsorship-service.ts`:
  - read the active rules for the operation's targets and the `EXISTS` check before evaluation;
  - store `rule_ids` on the decision;
  - test that an expired rule is ignored.
- [ ] 2.6 Return `ruleIds` from `GET /v1/admin/sponsorship/decisions`.

## 3. Rules API and versioned settings (wallet-api)

- [ ] 3.1 Add a rules repository: create (with the per-tenant advisory lock, the cap, lazy removal of expired rules, and the client-reference lookup), list (cursor, filters), get, patch and delete, each recording a rule event and rewriting the allowlist mirror when a rule with no reference changes.
- [ ] 3.2 Add the routes `POST`, `GET`, `GET /:id`, `PATCH /:id` and `DELETE /:id` under `/v1/admin/sponsorship/rules`, and `GET /v1/admin/sponsorship/rules/events`, with zod schemas and the error codes from the spec (`duplicate-contract`, `client-reference-conflict`, `rule-limit-reached`).
- [ ] 3.3 Version the settings:
  - `GET` returns `version` and an `ETag`;
  - `PUT` and `PATCH` honour `If-Match` (`412 version-mismatch`);
  - the deprecated `allowlist` input replaces the rules with no reference in the same transaction.
- [ ] 3.4 Add API tests for:
  - concurrent creates (no lost rule, the cap holds);
  - a retried create returning `200`, and a reference conflict;
  - an expired rule not blocking a create;
  - patch and delete, including `404` across tenants and chains;
  - `412` on a stale `If-Match`;
  - the deprecated allowlist round trip leaving referenced rules alone;
  - the migration copying an existing allowlist.
- [ ] 3.5 Regenerate `openapi/openapi.json` and pass the drift check.
- [ ] 3.6 Document the rules API, the deprecations and the predict-then-allow pattern in the wallet-api README, `specs/PAYMASTER-SPECS.md` and `specs/INTEGRATION.md`.

## 4. Callers and end-to-end coverage

- [ ] 4.1 Move `e2e/devnet/provision-sponsorship.mjs`, `deploy/contracts/provision-sponsorship.sh` and `packages/contracts/scripts/rehearse.ts` to the rules API, writing settings with `If-Match`.
- [ ] 4.2 Move `withConfig` in `e2e/tests/sponsorship.spec.ts` (and `e2e/tests/demo/operations.spec.ts` if it writes the allowlist) to the rules API.
- [ ] 4.3 Extend `e2e/tests/deployed-contracts.spec.ts` to the escrow pattern:
  - predict the address;
  - create a rule with a `clientReference` and an `expiresAt`;
  - deploy and call under sponsorship;
  - check that the decision lists the rule;
  - check that a delete refuses the next call;
  - check that an expired rule refuses it.
- [ ] 4.4 Run the full wallet-api tests, typecheck, lint and the e2e sponsorship specs, then open the stack's PRs with a changeset for every published package touched.
