## 1. wallet-api

- [x] 1.1 `src/environments.ts` and `GIANO_ENVIRONMENT` in config; remove the `OPERATOR_ADDRESSES`/`SIWE` variables.
- [x] 1.2 Migration `0008_platform_admins.sql` and schema; `src/services/platform-admins.ts` (bootstrap, list, add, remove, history).
- [x] 1.3 Sign-in and session resolution read the table; routes in `src/routes/platform-admins.ts`; OpenAPI regenerated.
- [x] 1.4 `src/init.ts` (migrations → bootstrap → local fixtures) replaces `src/tenant-fixtures.ts`; tsup entry `init`.
- [x] 1.5 Tests: `platform-admins.test.ts` (bootstrap, add/remove/guards/history, init refusals), platform-auth config and removal, 0008 migration.

## 2. Console

- [x] 2.1 Admins tab: list, add, remove (not yourself, not the last), history.

## 3. Deploy

- [x] 3.1 `ecs-service` module: optional `init_container`; wallet-api uses it with `dist/init.js`, `RUN_MIGRATIONS=false`, and `GIANO_ENVIRONMENT = terraform.workspace`. The console gets `GIANO_WALLET_API_UPSTREAM`.
- [x] 3.2 Every compose file: an `init` service that wallet-api waits on, plus `GIANO_ENVIRONMENT`; the `OPERATOR_*` variables removed.
- [x] 3.3 e2e: an Admins tab spec.

## 4. Docs

- [x] 4.1 Prose specs and READMEs.
