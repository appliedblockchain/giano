## Context

Builds on `userop-policy-defaults` (G6). After G6, a chain's relay policy resolves as: the `USEROP_*` deployment defaults, then the chain descriptor's `walletApi.policy`, then the tenant's policy, then the tenant's `perChain[chainId]`. Fee caps fall back to a table of known chains (`chain-fee-caps.ts`), then to 500 gwei. A `production` deployment refuses to boot when a chain's allowlists are not stated or it would use the 500 gwei fallback.

## Decisions

### D1: One row per chain, with a version and a history

`chain_relay_policy (chain_id PK, policy jsonb, version, updated_at, updated_by)` and an append-only `chain_relay_policy_history (chain_id, action, actor, platform_admin_session_id, before, after, created_at)`. `action` is `seed` or `update`. `actor` uses the tenant history's format (`platform-admin:<id>:<address>`, or `system:seed`). A write needs `If-Match` with the version, so two platform admins editing the same chain cannot silently overwrite each other; the tenant registry already works this way.

The stored policy has the shape of a chain descriptor's `walletApi.policy` (`chainPolicySchema` in `@appliedblockchain/giano-contracts`), except that an empty allowlist is refused on write, as it is for tenants. One shape for both places means an override and a stored value are the same kind of thing.

### D2: Precedence, field by field

For each field of a chain's policy:

1. the chain descriptor's `walletApi.policy` field (`GIANO_CHAINS`),
2. else the matching env var when set (`USEROP_MAX_*`, and `USEROP_ALLOWED_*` for the single-chain shorthand),
3. else the stored row's field,
4. else the field is *undecided* (D4).

The tenant's policy and its `perChain` entry still apply on top, as before. The descriptor wins over the env var because it is specific to the chain. Overrides keep working, so an existing deployment behaves as before until its overrides are removed.

The `USEROP_MAX_*` gas caps lose their built-in defaults: a default would always override the stored value, and the console could never change it. Their defaults move into the seed (D3).

### D3: Seeded at boot, never overwritten

When wallet-api starts, it inserts a row for every served chain that has none (`INSERT … ON CONFLICT DO NOTHING`, so replicas starting together are safe) and records a `seed` entry for each row it inserted. The seed holds only values that are safe:

| Field | Seed |
| --- | --- |
| `maxCallGas`, `maxVerificationGas` | 5,000,000 |
| `maxPreVerificationGas` | 10,000,000 |
| `maxPaymasterVerificationGas`, `maxPaymasterPostOpGas` | 1,000,000 |
| `maxFeePerGas`, `maxPriorityFeePerGas` | the chain's entry in `chain-fee-caps.ts`; left out for a chain it does not list |
| `allowedTargets` | `"any"`: the relay policy does not restrict what a wallet does with its own funds (README, "Relay policy") |
| `allowedPaymasters` | `[<the chain's Giano sponsorship paymaster>]`; left out for a chain without one |

The paymaster seed is the only one stricter than today's default. It matches what every compose file already configures (`deploy/docker-compose.{e2e,chain}.yml` relay only Giano's paymaster), and an operation without a paymaster still passes the rule. Seeding happens after the migrations, in wallet-api rather than in a migration, because the served chains are runtime configuration. A seed that cannot be written (no table, no database) stops the boot with the database error: a relay without its policy must not start.

### D4: An undecided field fails per chain, and loudly

- **Outside production**, an undecided field uses today's permissive behaviour: the 500 gwei fee fallback, or no allowlist restriction. The console shows the field as a fallback.
- **In production**, every operation on the chain is refused under the rule `chain-policy`, whose detail names the chain, the field, and where to set it. The other chains keep working.
- **A stored row that does not parse** (edited by hand) refuses the chain's operations under `chain-policy` in every deployment class, like a broken tenant policy (G6 D5).

wallet-api logs every problem at error level when it starts. The relay logs each `chain-policy` refusal at error level, records it on `userop_log`, and counts it in `giano_userop_policy_rejections_total{rule="chain-policy"}`. The platform API and the console list the problems per chain.

This replaces G6's production boot refusals. Those protected the same thing, but one chain's gap stopped every chain, and the fix was a secret edit and a redeploy. With the seed, every chain wallet-api knows is decided before the first operation. A chain it does not know shows its gap in the console, where a platform admin closes it without a deploy.

### D5: Overridden fields are visible and locked in the console

The API reports, per field, the stored value, the override and its source (`GIANO_CHAINS` or the env var's name), and the effective value. The console shows the effective value with its source and disables the input for an overridden field, so nobody edits a value that would not apply. A `PUT` stores what it is given, overridden or not, so removing an override later exposes a deliberate value.

### D6: The relay reads the row for each operation

One primary-key read per operation, beside the `userop_log` writes the relay already makes. An edit applies on the next operation on every replica, with no cache to invalidate. If the read fails, the operation fails with the relay's existing database error; it does not fall back to anything.

## Risks / Trade-offs

- **The paymaster seed is stricter than today's open default.** A deployment that relies on a third-party paymaster on a chain with a Giano paymaster would have those operations refused under `paymaster-allowlist` after upgrading. The refusal names the paymaster, and the fix is one console edit. No compose file or environment in this repository does that.
- **Production no longer refuses to boot for an undecided field.** The gap moves from boot to the first operation on that chain. It is logged at boot, shown in the console, and every refusal names the field, so it is not silent.
