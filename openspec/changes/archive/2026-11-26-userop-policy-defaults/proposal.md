## Why

Before wallet-api relays a UserOperation to the bundler it runs `evaluatePolicy` (`services/wallet-api/src/services/userop-policy.ts`) and records every rule's verdict on the `userop_log` row. Ticket G6 found the policy open by default:

- The only fee cap is a chain-agnostic 500 gwei, which never fires on Base or any other L2.
- `preVerificationGas`, `paymasterVerificationGasLimit` and `paymasterPostOpGasLimit` are paid for by the bundler or the paymaster and are not checked at all.
- A tenant policy that cannot be parsed falls back to `{}` (`mergePolicy` in `services/wallet-api/src/services/tenants.ts`), so the deployment defaults apply, including open allowlists. A broken policy loosens the relay.
- An open allowlist is not a recorded choice. An absent allowlist and an empty list both mean "any address", and nothing distinguishes "decided to allow any" from "never decided".
- Nobody wrote down what the policy is for, so nobody can say whether a rule is missing.

Tenants are now runtime rows written through the platform admin API (`/v1/platform/tenants`), so the same rules must hold on that write path and on the read path the relay uses.

## What Changes

- **Purpose.** The wallet-api README gains a "Relay policy" section: what the policy protects (the shared bundler and its executor balance, each tenant, Giano as an operator), and one line per rule naming the threat it addresses. The policy is not there to lock wallets down.
- **Per-chain fee caps.** wallet-api carries realistic default fee caps for the public chains it knows (Ethereum, Sepolia, OP Mainnet, Base, Base Sepolia). A chain descriptor's own caps still win. `USEROP_MAX_FEE_PER_GAS` and `USEROP_MAX_PRIORITY_FEE_PER_GAS` lose their built-in default: when set they apply to every chain without its own cap; when unset a known chain uses its default, and any other chain the old 500 gwei fallback. A production deployment refuses to boot when a served chain would get that fallback.
- **Every paid gas field bounded.** `PolicyUserOp` carries the paymaster gas limits, and three new rules cap `preVerificationGas`, `paymasterVerificationGasLimit` and `paymasterPostOpGasLimit` (new env defaults `USEROP_MAX_PRE_VERIFICATION_GAS`, `USEROP_MAX_PAYMASTER_VERIFICATION_GAS`, `USEROP_MAX_PAYMASTER_POST_OP_GAS`; overridable per chain descriptor and per tenant like the existing caps). `factory`/`factoryData` stay uncapped, with the reason recorded (design D4).
- **Fail closed on a broken tenant policy.** A stored tenant policy that does not parse refuses that tenant's relays under a new first rule, `tenant-policy`. The refusal is audit-logged, logged at error level, and counted in `giano_userop_policy_rejections_total{rule="tenant-policy"}`.
- **Explicit allowlists.** An allowlist is `"any"` or a non-empty address list, in the tenant policy (`perChain[chainId]`), in a chain descriptor's `walletApi.policy`, and in `USEROP_ALLOWED_TARGETS` / `USEROP_ALLOWED_PAYMASTERS`. The admin API refuses an empty list in a tenant policy. A stored empty list (written before this change) still reads as `"any"`. A production deployment refuses to boot unless every served chain states both allowlists.
- **BREAKING (admin API):** `PATCH`/`POST /v1/platform/tenants` refuse `allowedTargets: []` and `allowedPaymasters: []`; send `"any"`. The paymaster console sends `"any"` for "Any address".
- **BREAKING (production config):** `GIANO_DEPLOYMENT_CLASS=production` requires both allowlists stated for every served chain, and fee caps from somewhere other than the generic fallback.
- `@appliedblockchain/giano-contracts`: `chainPolicySchema` accepts `"any"` for the allowlists and the three new caps (a widening, so a minor release).

**Non-goals.**
- Refusing to boot because of a tenant row. Tenants are runtime data; see design D6.
- A Datadog monitor for fee-cap rejections. Datadog does not ingest wallet-api's Prometheus metrics today; the suggested alert is documented and the monitor is a follow-up.
- A factory allowlist (design D4).
- Changing the sponsorship rules (`sponsorship-rules.ts`), which are a separate check on what a tenant pays for.

## Capabilities

### New Capabilities
- `userop-relay-policy`: what the relay policy checks before a UserOperation reaches the bundler, where its caps and allowlists come from, and how it fails.

### Modified Capabilities

None. No current OpenSpec spec covers the relay policy.

## Impact

- **Code:** `services/wallet-api/src/services/{userop-policy,userop-relay,tenants}.ts`, `services/wallet-api/src/config.ts`, a new `services/wallet-api/src/services/chain-fee-caps.ts`, `services/wallet-api/src/app.ts`; `packages/contracts/chains.ts`; `services/paymaster-admin/src/lib/policy.ts`.
- **API:** `services/wallet-api/openapi/openapi.json` (tenant policy shape).
- **Docs:** `services/wallet-api/README.md`, `deploy/docker-compose.reference.yml`, `specs/MULTICHAIN_SPECS.md` §9.5.
- **Release:** a changeset for `@appliedblockchain/giano-contracts` (minor). wallet-api and paymaster-admin are not published.
