## 1. wallet-api

- [x] 1.1 Remove `TENANTS_SEED` from `src/config.ts`, and remove `seedTenants`, the seed schemas and `validateTenantSeed` from `src/services/tenants.ts`. Drop `managedBy` from `OriginClaimClash`.
- [x] 1.2 Add `src/services/tenants-seed-retirement.ts` (R4) and call it from `src/index.ts` after migrations. Make the zero-tenant boot message a plain notice about active tenants.
- [x] 1.3 Remove the seed-managed guards and `adopt` from `src/services/tenant-admin.ts`, and the adopt route and `managedBy` from `src/routes/platform-tenants.ts`. Regenerate `openapi/openapi.json`.
- [x] 1.4 Add `src/services/tenant-fixtures.ts` and the `src/tenant-fixtures.ts` entry, plus the `tenant-fixtures` tsup entry (R1–R3).
- [x] 1.5 Make `src/provision-sponsorship.ts` read `ADMIN_API_KEY`.
- [x] 1.6 Tests: `test/tenant-fixtures.test.ts` and `test/tenants-seed-retirement.test.ts` (the latter is deleted in the follow-up). Move `test/setup.ts`, `tenants.test.ts`, `api.test.ts`, `platform-tenants.test.ts` and `provision-sponsorship.test.ts` off the seed.

## 2. Console

- [x] 2.1 Remove `adopt`, `ManagedBy`, `OwnerBadge`, the seed note, the Adopt dialog, the "Managed by" column and the seed error texts. History and key actors render through `actorLabel`.

## 3. Deploy

- [x] 3.1 dev, e2e, loopback and Sepolia compose: add a `tenant-fixtures` one-shot that wallet-api waits on. Move each seed into its `TENANT_FIXTURES`.
- [x] 3.2 Reference compose: replace `TENANTS_SEED` with the platform admin settings. AWS compose mirror and env example: no tenants, and `ADMIN_API_KEY` for the one-shot.
- [x] 3.3 Terraform: drop the `tenants-seed` secret from wallet-api and the one-shot (plus its IAM statements), and add `ADMIN_API_KEY` to the one-shot's overridable environment.

## 4. Docs and e2e

- [x] 4.1 e2e: drop the "seed" owner assertion and `managedBy`, and reword the provisioner, origins and README comments.
- [x] 4.2 Prose specs, READMEs and the Sepolia docs.

## 5. Archive order

- [ ] 5.0 Archive `platform-tenant-lifecycle` and `platform-console` before this change; its MODIFIED/REMOVED deltas target their capabilities.

## 6. Follow-up change (cleanup)

- [ ] 6.1 Delete `tenants-seed-retirement.ts`, its boot call and its tests.
- [ ] 6.2 Migration: drop `tenants.managed_by`. Remove its schema field and the `managedBy: 'operator'` writes.
