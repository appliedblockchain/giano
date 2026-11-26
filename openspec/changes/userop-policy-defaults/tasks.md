# Tasks

## 1. Shared chain schema

- [ ] 1.1 `packages/contracts/chains.ts`: `chainPolicySchema` accepts `"any"` for `allowedTargets`/`allowedPaymasters`, and `maxPreVerificationGas`, `maxPaymasterVerificationGas`, `maxPaymasterPostOpGas`.
- [ ] 1.2 Changeset for `@appliedblockchain/giano-contracts` (minor).

## 2. wallet-api policy

- [ ] 2.1 `PolicyUserOp` carries `paymasterVerificationGasLimit` and `paymasterPostOpGasLimit`; `PolicyConfig` carries the three new caps and an optional tenant-policy error.
- [ ] 2.2 `evaluatePolicy`: `tenant-policy` first, then the three new caps (design D3, D5).
- [ ] 2.3 `userop-relay.ts`: pass the paymaster gas limits; log a `tenant-policy` refusal at error level.

## 3. Defaults and config

- [ ] 3.1 `src/services/chain-fee-caps.ts`: known-chain fee caps and the fallback (design D2).
- [ ] 3.2 `config.ts`: fee env vars without a default; new gas-cap env vars; `"any"` in `USEROP_ALLOWED_*`; per-chain fee resolution; production refusals for an unstated allowlist and a fallback fee cap.

## 4. Tenant policy

- [ ] 4.1 `tenants.ts`: allowlist `"any" | non-empty list`; the three new caps; legacy `[]` read as `"any"` (also before a patch is validated); `mergePolicy` reports a parse failure instead of falling back.
- [ ] 4.2 Regenerate `openapi/openapi.json`.
- [ ] 4.3 `services/paymaster-admin/src/lib/policy.ts`: send `"any"`, read `"any"` and legacy `[]`, the three new cap fields.

## 5. Tests

- [ ] 5.1 `test/userop-policy.test.ts`: each new rule, `tenant-policy`, the fee-cap table, the config refusals.
- [ ] 5.2 `test/tenants.test.ts`: `[]` refused on write, `"any"` accepted, legacy `[]` read as `"any"`, unparseable policy fails closed.
- [ ] 5.3 paymaster-admin `policy.test.ts`.

## 6. Docs

- [ ] 6.1 wallet-api README: "Relay policy" section (purpose, one line per rule, factory decision, suggested alert); env table.
- [ ] 6.2 `deploy/docker-compose.reference.yml`: fee caps no longer pinned to 500 gwei; allowlists stated.
- [ ] 6.3 `specs/MULTICHAIN_SPECS.md` §9.5: allowlist values and the inheritance the code implements.

## 7. Follow-ups (not in this change)

- [ ] 7.1 A Datadog monitor on fee-cap rejections, once wallet-api's Prometheus metrics reach Datadog.
- [ ] 7.2 A per-chain `preVerificationGas` default, after measuring real values on each chain.
