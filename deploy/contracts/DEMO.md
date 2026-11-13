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

Provisioning requires the EOA operator to be ROLE_ADMIN. It registers the sponsorship signer (by
`SPONSORSHIP_SIGNER_ADDRESS`) and the **explicit** `PAYMASTER_TENANTS` UUIDs, stakes the paymaster,
funds each balance and gives the roles out: one holder per immediate role (`ROLE_HOLDER_*`), or, for
this demo, `PAYMASTER_GRANT_ALL_TO=<operator address>` to put every role on one address. It asks for
interactive confirmation and warns that reruns add funding again. Hand the timelocked roles to the
timelock afterwards with `contracts:timelock` and `contracts:handoff`
([runbook](../../docs/PAYMASTER-TIMELOCK-RUNBOOK.md)). To try all of this without spending testnet
ETH, run `pnpm contracts:rehearse --chain base-sepolia --platform` first ([README](README.md#rehearsal)).
Neither supported testnet deploys a test ERC-20 or a permissive paymaster.

## Run the local stack

Set `RPC_URL` in your ignored local environment file for the serving backend; use the same network
as the deployment profile. It must serve `eth_getLogs` over 9,000 blocks, or the wallet-api's
paymaster watcher never learns the tenant's balance and refuses every sponsorship. On Base Sepolia,
`https://sepolia.base.org` serves only 200; `https://base-sepolia-rpc.publicnode.com` or a keyed
endpoint works (an open decision, see TESTNET-ROLLOUT.md). `BUNDLER_NODE_RPC_URL` can override the bundler endpoint. Neither URL is
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
rules determine whether it can be spent. A public chain has no test ERC-20, so set `SPONSOR_ALLOWLIST`
to the contracts the tenant's dApp calls: the wallet-api sponsors nothing, wallet management included,
for a tenant with an empty allowlist, and `contracts:sponsorship` refuses to install one. Wallet
management and self-calls then follow platform policy. Missing policies refuse sponsorship.

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
