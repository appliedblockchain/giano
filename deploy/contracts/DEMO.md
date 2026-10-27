# Local demo against an external chain

This uses the same profile-driven deployment/provisioning tools as any other environment. The
Docker stack runs locally while transactions land on the selected external chain. There is no
Sepolia-specific deployment script. Follow [the core deployment and cutover runbook](README.md)
first; a chain is not ready merely because its contracts exist.

## Configure and deploy

```sh
cp deploy/contracts/operator.env.example deploy/contracts/base-sepolia.local.env
# Supply operator keys, the existing database tenant UUID, API admin key and desired tenant funding.
pnpm contracts:funding --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
pnpm contracts:deploy --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
pnpm contracts:provision --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
pnpm contracts:doctor --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
```

For Ethereum Sepolia choose `--chain ethereum-sepolia` and its own operator environment file.
For another EVM chain add a validated JSON profile under `deploy/chains/` or supply `--config <file>`.
The profile fixes chain identity, the released code and paymaster parameters. It references an RPC
environment variable; a keyed URL never needs to be copied into a tracked file. Operator files are
dotenv data, not shell scripts. Existing exported variables take precedence over their contents.

Provisioning requires the EOA operator to be ROLE_ADMIN. It grants that operator all development
roles, registers the sponsorship signer and the **explicit** `PAYMASTER_TENANTS` UUIDs, stakes the
paymaster and funds each balance. It asks for interactive confirmation and warns that reruns add
funding again. Production role separation/timelock execution needs its own admin transaction flow.
Neither supported testnet deploys a test ERC-20 or a permissive paymaster.

## Run the local stack

Set `RPC_URL` in your ignored local environment file for the serving backend; use the same network
as the deployment profile. `BUNDLER_NODE_RPC_URL` can override the bundler endpoint. Neither URL is
exposed to browsers. The generic Compose file requires explicit chain settings; it has no hidden
Ethereum Sepolia fallback. The generated public fragment supplies chain ID/name and the addresses:

```sh
docker compose \
  --env-file deploy/contracts/base-sepolia.local.env \
  --env-file deploy/contracts/84532.addresses.env \
  -f deploy/docker-compose.chain.yml up --build
```

Use `11155111.addresses.env` for Ethereum Sepolia. Run only one local demo stack at a time because
both use the same host ports and passkey origin. These are independent chain deployments, not
independent passkey origins.

The stack's `GIANO_ENVIRONMENT` selects the existing application admin bootstrap; the example uses
its historical name `local-sepolia`. This is an application environment identity, independent of the
chain. Changing it needs corresponding bootstrap configuration. `TENANT_ID` must match one of the
on-chain UUIDs registered during provisioning; omitting it must not generate a new UUID.

After the stack starts, install the tenant's sponsorship rules:

```sh
pnpm contracts:sponsorship --chain base-sepolia --env-file deploy/contracts/base-sepolia.local.env
```

That calls the real admin API using `ADMIN_API_KEY`. Funding makes money available; sponsorship
rules determine whether it can be spent. With no test ERC-20, the demo allowlist is empty and wallet
management/self-calls follow platform policy. Missing policies refuse sponsorship.

Wallet UI: http://wallet.localhost:8081. Bundler: http://localhost:4337. The API is available through
the wallet's `/api` proxy. Start the sample dApp using the matching `CHAIN_ID` and RPC URL rather
than its anvil defaults, create a passkey account, and send a sponsored transaction. Verify its
receipt in the selected chain's explorer. Run the readiness checks described in the main runbook.

```sh
# Use the same two --env-file arguments as startup.
docker compose --env-file deploy/contracts/base-sepolia.local.env \
  --env-file deploy/contracts/84532.addresses.env \
  -f deploy/docker-compose.chain.yml down
```
