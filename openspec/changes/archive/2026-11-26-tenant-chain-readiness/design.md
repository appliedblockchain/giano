## Context

The G11 card predates H5. Validated against `main` at 41106c70:

| Ticket item | State before this change |
| --- | --- |
| R1, one id for both halves | Done. The server generates the tenant UUID (`tenants.id`, `defaultRandom()`), the paymaster keys on its 16 bytes, and the console's *Register on <chain>* step passes that id. A fixed `id` is accepted only for a tenant already registered on chain. |
| R1, "not yet sponsorable" is visible | Partial. The console shows *not registered* and the next step. Sponsorship refuses an unregistered tenant as `insufficient-balance`, and authorises a disabled one. |
| R2, suspend and resume | Done (`tenant-lifecycle`). Only active tenants resolve, so one check covers ceremonies, relay, sponsorship, RPC and admin keys. |
| R3, offboarding | Partial. Suspend, the console's on-chain disable step, the tenant's `withdrawTenant` and the tombstone delete exist. No runbook. |
| R4, operator tier | Done (platform admins, `/v1/platform/*`, `tenant_history`, `platform_admin_history`). |
| R5, drift | Done for drift (`tenant-chain-drift`, `giano_paymaster_drifted_tenants`, `giano-doctor`). A tenant present only in the registry is not reported. No alert. |

## Decisions

### D1: The paymaster record is read per decision, not cached in the ledger

The decision already reads `feeFor` and the paymaster's parameters. Reading the tenant's record instead of `feeFor` (`PaymasterReader.tenant`, which returns the fee too) adds one `getTenant` call per decision. The alternative, an `enabled` column in `paymaster_tenants` kept by the watcher, needs a migration and a new event, and is wrong for as long as the watcher lags. The chain is the authority, and a disable must take effect on the next decision.

### D2: The check runs only for a tenant that has sponsorship switched on

A tenant whose configuration is off, missing or unparseable keeps its current reason (`sponsorship-disabled` or `no-sponsorship-config`): that is the first thing to fix. For a tenant whose configuration is on, the on-chain record is checked before the rules, so an unregistered tenant is not told it has run out of credit.

### D3: The reason stays `sponsorship-disabled`, under its own rule name

A new reason would need a new JSON-RPC code, new wallet copy and a release of the published wallet packages, as in `restrict-sponsored-self-calls` D5. `sponsorship-disabled` tells the user the truth ("fee sponsorship is switched off for this application"). The decision log records the rule `paymaster-tenant`, with a detail of `not registered on the paymaster` or `disabled on the paymaster`, so the tenant and platform admins can tell it from the tenant's own switch.

Usage counts `sponsorship-disabled` under the tenant's rules. A refusal for an on-chain disable is counted there too. That is accepted: the decision log has the rule.

### D4: Unregistered is a list beside drift, not a drift kind

A drift entry fails `giano-doctor` and counts toward `giano_paymaster_drifted_tenants`. A tenant waiting for its registration is a step not yet taken (`tenant-chain-drift`), so it is a separate list, a separate gauge, and a doctor warning. Only active tenants with sponsorship switched on for the chain are listed: a tenant that does not sponsor on a chain does not need to be registered there.

### D5: No `pending-chain` status

The ticket suggested one. Registration is per chain, and a tenant can be registered on one chain and not another, so a single status on the tenant row would be wrong for some chain. The lifecycle status keeps its meaning (may this tenant act at all), and the per-chain state is read from the paymaster.

## Risks

- One extra `eth_call` per sponsorship decision. Decisions are rate limited per tenant, and the node already serves the fee read on the same path.
- A tenant disabled on chain between the decision and inclusion still reverts. The window is the authorisation's validity, as before.

## Open Questions

- **Retention or erasure after delete.** Users, credentials (public keys and wallet addresses), operation logs and decisions are kept today. Whether a deleted tenant's users must be erased on request, and after how long, is for the tech lead and legal. G34 covers database retention.
- **Should suspend require the on-chain disable?** Today suspension is a database change and the console offers the on-chain step after it. Drift reports a suspended tenant still enabled on chain. Making it a precondition would need a signer wallet-api does not hold.
