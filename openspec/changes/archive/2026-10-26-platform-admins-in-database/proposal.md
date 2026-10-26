## Why

Platform admins were configuration: `OPERATOR_ADDRESSES` and `OPERATOR_SIWE_DOMAIN` on wallet-api. Adding or removing a platform admin meant a redeploy, and nothing recorded who changed the list. Configuration that changes at runtime belongs in the database and should be managed from the admin app. Only what a deployment *is*, such as the host its console answers on, should be decided by a release.

## What Changes

- **BREAKING** `OPERATOR_ADDRESSES`, `OPERATOR_SIWE_DOMAIN` and `OPERATOR_SIWE_URI` are removed. wallet-api requires `GIANO_ENVIRONMENT`.
- **Environment map in code** (`src/environments.ts`). Each environment (`dev`, `stg`, `prd`, `reference`, `e2e`, `local-infra`, `local-dev`, `local-sepolia`, `test`) has:
  - its platform admin sign-in domain and URI, which a release changes and the database never stores;
  - its bootstrap platform admins;
  - whether it is a local stack.
- **Admins table** with append-only history (`0008_platform_admins.sql`). Platform admins manage platform admins through `/v1/platform/admins`, and the console gains an **Admins** tab. Removing yourself or the last platform admin is refused. A removed platform admin's sessions end on their next request.
- **Init step** `dist/init.js`, run before the API everywhere:
  1. applies migrations;
  2. writes the environment's bootstrap platform admins, only into an **empty** `platform_admins` table;
  3. on local stacks only, loads `TENANT_FIXTURES`.
  
  It replaces `dist/tenant-fixtures.js`. On AWS it is an init container in the wallet-api task (`dependsOn: SUCCESS`), and wallet-api runs with `RUN_MIGRATIONS=false`.
- The AWS console gets `GIANO_WALLET_API_UPSTREAM`, so its Platform area exists on AWS.

## Capabilities

### New Capabilities
- `platform-admin-management`: platform admins as rows, the bootstrap rule, the management routes and their guards, and history.
- `deployment-init`: the environment map and the init step.

### Modified Capabilities
- `platform-admin-authentication`: platform admins are looked up in the database, and the sign-in domain comes from the environment map.

## Impact

- **Code**: `services/wallet-api` (environments, config, init, platform admins service and routes, sign-in and session lookup, migration 0008, OpenAPI), `services/paymaster-admin` (Admins tab).
- **Deploy**: every compose file has an `init` service. `infra/iac/modules/aws/ecs-service` gains an optional init container, which `ecs_services.tf` uses for wallet-api. The console gets the wallet-api upstream.
- **Security**: this reverses H-b's "configuration, never rows": whoever can write the database can now add a platform admin. Mitigations: only signed-in platform admins manage the list through the API, every change is recorded, and the guards keep at least one platform admin. The bootstrap list only applies to an empty table, so a release can't add a platform admin to a live database.
- **Rollout**: the first deploy bootstraps `giovanni` (`0xFebBB1e5b6D66E6281d0d4d4816f76B69365a09d`) on dev. stg and prd get the same platform admin when they are first provisioned.
