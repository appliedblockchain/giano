# Tasks

## 1. Shared chain schema

- [x] 1.1 `packages/contracts/chains.ts`: `chainPolicySchema` accepts `"any"` for `allowedTargets`/`allowedPaymasters`, and `maxPreVerificationGas`, `maxPaymasterVerificationGas`, `maxPaymasterPostOpGas`.
- [x] 1.2 Changeset for `@appliedblockchain/giano-contracts` (minor).

## 2. wallet-api policy

- [x] 2.1 `PolicyUserOp` carries `paymasterVerificationGasLimit` and `paymasterPostOpGasLimit`; `PolicyConfig` carries the three new caps and an optional tenant-policy error.
- [x] 2.2 `evaluatePolicy`: `tenant-policy` first, then the three new caps (design D3, D5).
- [x] 2.3 `userop-relay.ts`: pass the paymaster gas limits; log a `tenant-policy` refusal at error level.

## 3. Defaults and config

- [x] 3.1 `src/services/chain-fee-caps.ts`: known-chain fee caps and the fallback (design D2).
- [x] 3.2 `config.ts`: fee env vars without a default; new gas-cap env vars; `"any"` in `USEROP_ALLOWED_*`; per-chain fee resolution; production refusals for an unstated allowlist and a fallback fee cap.

## 4. Tenant policy

- [x] 4.1 `tenants.ts`: allowlist `"any" | non-empty list`; the three new caps; legacy `[]` read as `"any"` (also before a patch is validated); `mergePolicy` reports a parse failure instead of falling back.
- [x] 4.2 Regenerate `openapi/openapi.json`.
- [x] 4.3 `services/paymaster-admin/src/lib/policy.ts`: send `"any"`, read `"any"` and legacy `[]`, the three new cap fields.

## 5. Tests

- [x] 5.1 `test/userop-policy.test.ts` (each new rule, `tenant-policy`), `test/userop-policy-config.test.ts` (the fee-cap table, `"any"`, the production refusals), and an `api.test.ts` case for a corrupt stored policy.
- [x] 5.2 `test/tenants.test.ts`: `[]` refused on write, `"any"` accepted, legacy `[]` read as `"any"`, unparseable policy fails closed.
- [x] 5.3 paymaster-admin `policy.test.ts`.

## 6. Docs

- [x] 6.1 wallet-api README: "Relay policy" section (purpose, one line per rule, factory decision, suggested alert); env table.
- [x] 6.2 `deploy/docker-compose.reference.yml`: fee caps no longer pinned to 500 gwei; allowlists stated.
- [x] 6.3 `specs/MULTICHAIN_SPECS.md` §9.5: allowlist values and the inheritance the code implements.

## 7. Follow-ups (not in this change)

- [ ] 7.1 A Datadog monitor on fee-cap rejections, once wallet-api's Prometheus metrics reach Datadog.
- [ ] 7.2 A per-chain `preVerificationGas` default, after measuring real values on each chain.
