# Tasks

## 1. Storage

- [ ] 1.1 `migrations/0014_chain_relay_policy.sql`: `chain_relay_policy` and `chain_relay_policy_history`.
- [ ] 1.2 `src/db/schema.ts`: the two tables.

## 2. Resolution and seed

- [ ] 2.1 `src/services/chain-policy.ts`: stored-policy schema, seed values (design D3), field-by-field resolution with sources and problems (D2, D4), seeding and reads.
- [ ] 2.2 `config.ts`: a chain's `policy` carries only overrides; `USEROP_MAX_*` without defaults; drop the production boot refusals (D4).
- [ ] 2.3 `app.ts`: seed after the database is ready; log every problem at error level.

## 3. Relay

- [ ] 3.1 `userop-policy.ts`: `chain-policy` rule, first.
- [ ] 3.2 `userop-relay.ts`: read the chain's row for each operation (D6) and resolve it; log `chain-policy` refusals at error level.

## 4. Platform API

- [ ] 4.1 `src/routes/platform-chain-policies.ts`: list, replace (with `If-Match`), history.
- [ ] 4.2 OpenAPI regenerated.

## 5. Console

- [ ] 5.1 `lib/platform-api.ts`: types and calls.
- [ ] 5.2 `lib/chain-policy.ts`: form conversion and validation.
- [ ] 5.3 `platform/RelayPolicyTab.tsx` and the `/relay-policy` route.

## 6. Tests and docs

- [ ] 6.1 wallet-api: seed, precedence, production and non-production undecided fields, broken row, API validation and versioning, relay applying an edit.
- [ ] 6.2 paymaster-admin: form conversion.
- [ ] 6.3 README "Relay policy", `specs/MULTICHAIN_SPECS.md` §9.5, `deploy/docker-compose.reference.yml`.

## 7. Archive

- [ ] 7.1 Archive after `userop-policy-defaults`, which creates the `userop-relay-policy` spec this change modifies.
