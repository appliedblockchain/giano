# Design

## Context

See proposal.md (Why). Facts from the code that shape the approach:

- **The gateway package.** `@appliedblockchain/silentdatarollup-custom-rpc` 1.2.0 ships one bundled file, `dist/index.js`, declared as its `bin`. It is an express server. It reads `CUSTOM_RPC_PORT` (default 54321), `CUSTOM_RPC_PROXY_URL` (default `http://localhost:8545`), `CUSTOM_RPC_LOGS_LIMIT_RANGE` (default 10,000), `CUSTOM_RPC_PER_PAGE` (default 10) and `CUSTOM_RPC_BYPASS_METHOD_PREFIXES`. It listens on all interfaces, and sends CORS headers with `Access-Control-Allow-Origin: *`. It has no health endpoint. It caches the chain id after its first successful read from the node.
- **What the gateway allows.** Reads: `eth_blockNumber`, `eth_call`, `eth_chainId`, `eth_estimateGas`, `eth_feeHistory`, `eth_gasPrice`, `eth_getBalance`, `eth_getBlockBy*`, `eth_getCode`, the filter methods, `eth_getLogs`, `eth_getProof`, `eth_getTransactionByHash`, `eth_getTransactionCount`, `eth_getTransactionReceipt`, `eth_maxPriorityFeePerGas`, `eth_syncing`, `net_*`, `web3_*`, and two `sd_*` methods. Writes: `eth_sendRawTransaction`. It refuses everything else, including `eth_getStorageAt` and every `anvil_*`, `evm_*` and `debug_*` method.
- **The root workspace installs from npmjs.** Only `services/custom-example` routes the `@appliedblockchain` scope to GitHub Packages. The root workspace has no such line, so it can install the public gateway package. `services/*` is already a workspace glob.
- **Image rules.** The `container-images` capability applies to the images `.github/workflows/docker.yml` publishes, and `scripts/check-dockerfiles.mjs` reads that list. A local-only image is outside it. `e2e.yml` verifies the DHI signatures of the Dockerfiles that the e2e stack builds (`scripts/verify-dhi-bases.mjs`, with an explicit list). `deploy/docker-compose.e2e.ci.yml` seeds builds from the layer cache that `docker.yml` writes. An image that `docker.yml` does not build has no cache scope.
- **Local chain ids are listed in several places:** `LOCAL_CHAIN_IDS` in `packages/contracts/deploy/config.ts` (the deploy CLI impersonates the canonical deployer and installs CreateX only on these), `[31337, 31338]` in `packages/contracts/scripts/deployer-entrypoint.mjs`, `LOCAL_DEVNET_CHAIN_IDS` in `services/paymaster-admin/src/lib/health.ts`, the known chain names in `packages/contracts/chains.ts` and `packages/wallet-kit/src/config.ts`, the default `SPONSOR_CHAIN_IDS` in `e2e/devnet/provision-sponsorship.mjs` and `provision-tx-mappings.mjs`, and the allowed ids in `e2e/devnet/upgrade-paymaster.mjs`.
- **The private test token on local chains.** `privateTestErc20Wanted` returns `true` for every local chain, so `local:deploy` already deploys `GianoTestPrivateErc20` there. The committed states predate that code, so they do not contain it. Its CREATE3 address depends on the deployer, so the local address differs from iron-kestrel's `0xFA7B71b9A5397b8A4faCC9127BE1C665f2F2cA9b`.
- **The BYO wallet fixture serves two chains at most.** `e2e/wallet-byo/serve.mjs` reads `CHAIN_ID`, `CHAIN_NAME`, `CHAIN_B_ID` and `CHAIN_B_NAME`, and `src/config.ts` builds the list from them. The wallet kit's `WalletConfig.chains` already takes a list. `infra/iac/ecs_services.tf` sets `CHAIN_ID` and `CHAIN_B_ID` for the dev environment.
- **The demo e2e project.** `e2e/playwright.config.ts` defines the `demo` project only when `DEMO=1`. It starts `dev:stock` (port 4410, the portless name `demo`). The name `demo-byo` (port 4411) exists in `e2e/origins.mjs`, but no web server starts `dev:byo`.

## Goals / Non-Goals

**Goals:**

- The same gateway that Silent Data runs, in front of a local chain, with no change to its code.
- Configuration for 31339 that matches the dev environment's iron-kestrel entry, so a problem shows locally first.
- Tests that fail when the gateway is missing, not only when the demo breaks.

**Non-Goals:**

- Reproducing iron-kestrel's gas price or L1 data fee.
- Running the gateway in front of 31337 or 31338.

## Decisions

### D1. The gateway runs from the published package, in a local-only image

`services/silent-data-gateway` is a private workspace package. Its only dependency is the gateway, pinned at `1.2.0`. Its `Dockerfile` installs it with `--frozen-lockfile` from the repository's lockfile, and runs `node` on the package's `dist/index.js`. The image follows ABIP-2 anyway: a `-dev` DHI Node stage to install, the DHI Node runtime to run, both pinned by digest (the digests `e2e/wallet-byo/Dockerfile` uses), no shell, and an exec-form healthcheck in `node` that sends `eth_chainId`. `docker.yml` does not build it, so it is not published.

Alternatives considered:

- `node:24-alpine` with `npx` at start, as the sponsorship provisioner runs. Rejected: it installs at start, outside the lockfile, so ABIP-6 and ABIP-7 do not apply, and it needs the network at every start.
- A copy of the gateway's source in this repository. Rejected: it drifts from what Silent Data runs, and an upgrade becomes a merge instead of a version change.
- Publishing the image. Rejected: nothing outside local stacks runs it, and a published image must meet every `container-images` requirement and get an ECR repository.

### D2. A third chain, 31339, instead of a gateway in front of Devnet B

The gateway refuses `anvil_*` methods and `eth_getStorageAt`. The demo's "fund from devnet" control and several e2e tests use them on 31337 and 31338. A third chain keeps those unchanged. It costs one more anvil node and one more state file.

The chain is named "Devnet SD (Silent Data)". The known-names maps call it "Local devnet SD", next to "Local devnet A" and "Local devnet B".

### D3. Every component reaches 31339 through the gateway

The backend chain entry (`x-giano-chains` in both compose files) uses `http://sd-gateway:8545` as `rpcUrl` and sets `bundler.stateOverride: false`. wallet-api, the bundler and paymaster-admin read it. The wallets reach the chain through wallet-api's `/v1/rpc/31339` and `/v1/bundler/31339` relays, as they do for every chain. The demo dApp reads the chain at the gateway's public name: `http://rpc-sd.giano.localhost` in the infrastructure stack and `http://rpc-sd.localhost` with portless. The gateway sends its own CORS headers, so Caddy and portless forward it unchanged.

Only two things reach the node directly: the state generator, and the e2e gateway check (D7). The node publishes host port 8547 for them, under the portless name `rpc-sd-node`. The gateway publishes host port 8548, under `rpc-sd`. Inside the compose network, the gateway listens on 8545 (`CUSTOM_RPC_PORT`), so every RPC in the stack uses the same port.

This is the dev environment's shape for iron-kestrel (`silent-data-network`, proposal, "Decided"): one configuration path for every chain, and no check by chain id.

### D4. One generator for all three states

`e2e/devnet/generate-state.mjs` already takes `CHAIN_ID` and checks addresses against `addresses.json`. 31339 joins `LOCAL_CHAIN_IDS`, so `local:deploy` runs there with impersonation, and deploys the private token as on any local chain. The generator:

- adds `privateTestErc20` to `addresses.json`, from the deployment record;
- adds the private token to the cross-chain address check;
- gets a `devnet:generate:sd` script, and `devnet:generate:all` runs all three chains.

All three states are regenerated in PR 3, so every local chain carries the private token at the same address. The alternative, generating only `state-31339.json`, would leave `addresses.json` without the token, or with a token that 31337 does not have.

### D5. The sponsorship provisioner covers 31339 and allow-lists the private token

`provision-sponsorship.mjs` gets 31339 in its default `SPONSOR_CHAIN_IDS`, and adds `privateTestErc20` from `addresses.json` to the allowlist it builds. The allowlist is the same on every chain. The token exists on every local chain, so the extra entry is harmless on 31337 and 31338. Only the infrastructure and e2e stacks run the provisioner, and after PR 4 both serve 31339. `provision-tx-mappings.mjs` gets the same default.

### D6. The BYO wallet fixture reads one `CHAINS` list

`CHAINS` is a JSON array of `{ chainId, name }`. `serve.mjs` validates it and passes it to the SPA as one `define`. `src/config.ts` maps it to wallet-kit chain entries. Without `CHAINS`, `serve.mjs` builds the list from `CHAIN_ID` / `CHAIN_B_ID` as today, so the dev environment keeps working. When both are set, it exits with a message that names both. In a devnet checkout with no chain variables, the default list is every local chain: two in PR 2, three from PR 4.

The pair stays because `infra/iac` sets it. Moving `infra/iac` to `CHAINS` belongs to the infra PR that lists iron-kestrel for `byoui` (`tasks.md`, "Workflow follow-up").

### D7. The e2e tests

`e2e/tests/demo/demo-private-token.spec.ts` runs in the opt-in `demo` project:

1. **Gateway check**, no browser. An `eth_call` of `balanceOf(holder)` on the private token, with `from` set to the holder and no signature: through `rpc-sd` it fails, and at `rpc-sd-node` it succeeds. Also `eth_getStorageAt`: refused by `rpc-sd`, answered by `rpc-sd-node`. If the gateway is missing, this test fails first, with a message that names the gateway.
2. **Stock flow**, through wallet-web: select "Devnet SD (Silent Data)", see the undeployed-wallet message, mint (the mint deploys the wallet), approve the read delegate (one `personal_sign`), read the balance, transfer, then the outsider view. Each write is confirmed in the demo's ledger. Then the test checks the sponsorship spend on 31339 through the tenant admin API (`/v1/admin/sponsorship/spend?chainId=31339`), and that the user operation settled from the receipt.
3. **BYO flow**: the same steps against `ORIGINS.demoByo` and the BYO wallet fixture, once.

`playwright.config.ts` starts `dev:byo` next to `dev:stock` when `DEMO=1`. `e2e/origins.mjs` adds the `rpc-sd` and `rpc-sd-node` routes and `CHAINS.sd`.

In CI, the "reference demo" leg already runs `pnpm test:demo`. `e2e.yml` adds `services/silent-data-gateway/Dockerfile` to the DHI signature check, and waits for the gateway with `eth_chainId` through `rpc-sd.localhost`. There is no cache entry for the gateway image in `docker-compose.e2e.ci.yml`, because `docker.yml` does not build it, so no cache scope exists. The image installs one package, so a cold build is short. (This corrects the earlier plan, which named a cache entry.)

## Risks / Trade-offs

- [A third chain in wallet-web's and wallet-byo's lists changes what existing tests see, for example a chain picker with three entries] → PR 4 runs both main e2e legs and the demo leg locally, and fixes each test that assumes exactly two chains.
- [The gateway's dependencies (express 4.21.2, body-parser 1.20.3, http-proxy-middleware 3.0.5, ethers 6.13.2) may carry advisories] → PR 3 runs `pnpm audit` on the new lockfile. A critical or high finding is handled as `dependency-security` requires, with an override or an accepted residual. The image runs only locally.
- [Someone adds a scope line for `@appliedblockchain` to a root `.npmrc`] → the install fails loudly, it does not pick another package. The manifest's comment says why the package comes from npmjs.
- [The regenerated 31337 and 31338 states change more than the private token, for example block numbers] → the generator is deterministic. PR 3 runs the full e2e suite on the regenerated states before it opens.
- [A gateway upgrade changes the allowed methods] → the version is pinned, and the gateway check in the e2e spec shows the change.
- [wallet-api's chain check reads the paymaster implementation from `Upgraded` logs on 31339 and logs an unverified warning] → this is the behaviour `silent-data-network` (task 1.7) defines for a restricted RPC. The local stack shows the same warning as dev.

## Migration Plan

None for deployed environments: 31339 exists only in local stacks. A developer runs `docker compose … down -v` and starts the stack again to load the regenerated states, as after any state change.

## Open Questions

None. The one open question is decided: the `byoui` demo on the AWS dev environment lists iron-kestrel. A separate infra PR does it after PR 2 merges (`tasks.md`, "Workflow follow-up"). It does not change this stack.
