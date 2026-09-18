---
'@appliedblockchain/giano-wallet-api': minor
---

A deployable sponsorship provisioner: `src/provision-sponsorship.ts`, built as
`dist/provision-sponsorship.js`, which is the command the one-shot ECS task in
`infra/iac/ecs_tasks_oneshot.tf` has always named and the image has never contained. Everything
comes from the environment — `TENANT_SLUG`, `CHAIN_ID` (a comma-separated list, because rules are
per (tenant, chain) and never inherited), `SPONSORSHIP_CONFIG`, and the `TENANTS_SEED` secret the
tenant's admin key is looked up in — and the rules go in the way a tenant would put them in, a
`PUT /v1/admin/sponsorship` with that tenant's own key, so there is no seeding path that would
have to be disabled in production.

Rules are validated against the same schema the API applies before anything is written, read back
rather than trusted, and checked against the tenant's registration and balance on the paymaster.
`SPONSORSHIP_REQUIRE_FUNDED=false` turns an unfunded tenant from a failed task into a warning, for
the bring-up case where rules are provisioned before there is a balance to check them against.

The task definition is not changed here: it still needs `SPONSORSHIP_CONFIG`, and a `CHAIN_ID`
naming both chains rather than chain A alone.

A tenant with no rules is refused every transaction with `sponsorship-disabled`, which looks
exactly like a broken wallet rather than an unprovisioned environment — hence a task that fails
loudly and non-zero.
