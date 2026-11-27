## Why

The relay policy for a chain (gas and fee caps, target and paymaster allowlists) is deployment configuration today: each chain's `walletApi.policy` in `GIANO_CHAINS`, or the `USEROP_*` env vars. On AWS `GIANO_CHAINS` is a secret maintained by hand in 1Password, so changing a chain's allowlist means editing a secret and restarting every service, with no audit trail beyond the vault's. A platform admin can edit a tenant's policy in the console, but not the chain defaults that every tenant inherits.

The `userop-policy-defaults` change (G6) also made a `production` wallet-api refuse to boot until every served chain states both allowlists and has a fee cap from somewhere other than the 500 gwei fallback. That is the right rule with the wrong failure: one undecided chain takes the whole relay down, and fixing it needs a secret edit and a redeploy.

## What Changes

- **Chain relay policy in the database.** A new table `chain_relay_policy` holds one row per chain: the caps and allowlists, a version, who changed it last and when. Every write is recorded in `chain_relay_policy_history`.
- **Safe defaults, seeded at boot.** wallet-api writes a row for every served chain that has none. The gas caps get today's defaults. The fee caps get wallet-api's known value for the chain, when it has one. `allowedTargets` is `"any"`. `allowedPaymasters` is the chain's own Giano sponsorship paymaster, when it has one. An existing row is never overwritten.
- **Env vars become overrides.** A chain descriptor's `walletApi.policy` and the `USEROP_*` env vars, when set, override the stored value field by field. They lose their built-in defaults, so an unset variable no longer hides the stored value.
- **Every failure is explicit, per chain.** A field nothing decides is *undecided*. Outside production it falls back to the permissive behaviour wallet-api has today, and the console says so. In production every operation on that chain is refused under a new rule, `chain-policy`, naming the chain and the field. A stored row that does not parse refuses the chain's operations in every deployment class. Each refusal is audit-logged and counted in `giano_userop_policy_rejections_total{rule="chain-policy"}`, and every problem is logged at error level when wallet-api starts.
- **BREAKING (production config):** wallet-api no longer refuses to boot for an unstated allowlist or a fallback fee cap. The seeded row decides both for every chain wallet-api knows. For a chain it does not know, the gap refuses that chain's operations instead of stopping the service.
- **Platform API.** `GET /v1/platform/chain-policies` lists each served chain's stored policy, its overrides, the effective policy and its problems. `PUT /v1/platform/chain-policies/:chainId` replaces the stored policy, with `If-Match` on the version. `GET /v1/platform/chain-policies/:chainId/history` lists the changes.
- **Console.** A *Relay policy* tab, for platform admins, shows every served chain: each field's effective value and where it comes from (stored, overridden by `GIANO_CHAINS` or an env var, or a fallback), and any problem. A platform admin edits the stored policy from there. Overridden fields are shown but cannot be edited.

**Non-goals.**
- Moving tenant policy anywhere; it is already in the database and edited from the console.
- Editing the rest of a chain's descriptor (RPC, bundler, addresses) from the console.
- A cache of the chain policy. The relay reads the row for each operation, so an edit applies at once on every replica (design D6).

## Capabilities

### New Capabilities
- `platform-console-relay-policy`: viewing and editing each chain's relay policy from the platform console and API.

### Modified Capabilities
- `userop-relay-policy`: chain defaults come from the database, env vars override them, and an undecided field refuses that chain's operations in production instead of stopping the service.

## Impact

- **Code:** `services/wallet-api/src/services/chain-policy.ts` (new), `src/routes/platform-chain-policies.ts` (new), `src/config.ts`, `src/app.ts`, `src/services/userop-relay.ts`, `src/services/userop-policy.ts`, `src/db/schema.ts`, `migrations/0014_chain_relay_policy.sql`; `services/paymaster-admin/src/platform/RelayPolicyTab.tsx` (new), `src/lib/chain-policy.ts` (new), `src/lib/platform-api.ts`, `src/lib/router.tsx`, `src/App.tsx`.
- **API:** `services/wallet-api/openapi/openapi.json`.
- **Deploy:** `deploy/docker-compose.reference.yml` no longer sets the `USEROP_*` caps or requires the allowlists. AWS sets none of them. A `GIANO_CHAINS` entry with a `walletApi.policy` keeps working as an override.
- **Docs:** `services/wallet-api/README.md` ("Relay policy"), `specs/MULTICHAIN_SPECS.md` §9.5.
- **Release:** wallet-api and paymaster-admin are not published; no package API changes.
