## Why

Operators were configuration: `OPERATOR_ADDRESSES` and `OPERATOR_SIWE_DOMAIN` on wallet-api. Adding or removing an operator meant a redeploy, and nothing recorded who changed the list. Configuration that changes at runtime belongs in the database and should be managed from the admin app. Only what a deployment *is*, such as the host its console answers on, should be decided by a release.

## What Changes

- **BREAKING** `OPERATOR_ADDRESSES`, `OPERATOR_SIWE_DOMAIN` and `OPERATOR_SIWE_URI` are removed. wallet-api requires `GIANO_ENVIRONMENT`.
- **Environment map in code** (`src/environments.ts`). Each environment (`dev`, `stg`, `prd`, `reference`, `e2e`, `local-infra`, `local-dev`, `local-sepolia`, `test`) has:
  - its operator sign-in domain and URI, which a release changes and the database never stores;
  - its bootstrap operators;
  - whether it is a local stack.
- **Operators table** with append-only history (`0008_operators.sql`). Operators manage operators through `/v1/operator/operators`, and the console gains an **Operators** tab. Removing yourself or the last operator is refused. A removed operator's sessions end on their next request.
- **Init step** `dist/init.js`, run before the API everywhere:
  1. applies migrations;
  2. writes the environment's bootstrap operators, only into an **empty** operators table;
  3. on local stacks only, loads `TENANT_FIXTURES`.
  
  It replaces `dist/tenant-fixtures.js`. On AWS it is an init container in the wallet-api task (`dependsOn: SUCCESS`), and wallet-api runs with `RUN_MIGRATIONS=false`.
- The AWS console gets `GIANO_WALLET_API_UPSTREAM`, so its Operator area exists on AWS.

## Capabilities

### New Capabilities
- `operator-management`: operators as rows, the bootstrap rule, the management routes and their guards, and history.
- `deployment-init`: the environment map and the init step.

### Modified Capabilities
- `operator-authentication`: operators are looked up in the database, and the sign-in domain comes from the environment map.

## Impact

- **Code**: `services/wallet-api` (environments, config, init, operators service and routes, sign-in and session lookup, migration 0008, OpenAPI), `services/paymaster-admin` (Operators tab).
- **Deploy**: every compose file has an `init` service. `infra/iac/modules/aws/ecs-service` gains an optional init container, which `ecs_services.tf` uses for wallet-api. The console gets the wallet-api upstream.
- **Security**: this reverses H-b's "configuration, never rows": whoever can write the database can now add an operator. Mitigations: only signed-in operators manage the list through the API, every change is recorded, and the guards keep at least one operator. The bootstrap list only applies to an empty table, so a release can't add an operator to a live database.
- **Rollout**: the first deploy bootstraps `giovanni` (`0xFebBB1e5b6D66E6281d0d4d4816f76B69365a09d`) on dev. stg and prd get the same operator when they are first provisioned.
