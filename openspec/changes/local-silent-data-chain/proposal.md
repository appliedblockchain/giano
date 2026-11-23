## Why

The demo dApp has a private token section for Silent Data (`silent-data-network`, tasks 6.x), but no local stack can show it. Every local chain is plain anvil: 31337 "Devnet A" and 31338 "Devnet B". Anvil answers every read, so nothing private is enforced. The checks in `silent-data-network` (tasks 4.1, 6.2, 6.3 and 9.1) put Silent Data's gateway in front of anvil by hand. That setup is not in the repository, and no automated test covers the private token section.

The AWS dev environment will use real Silent Data chains (iron-kestrel). The local stacks and the e2e suite need their own Silent Data chain, so the same Giano build is tested against the same gateway before it reaches dev.

## What Changes

- A third local chain, 31339 "Devnet SD (Silent Data)": an anvil node with a baked state, behind Silent Data's gateway. The gateway is the published npm package `@appliedblockchain/silentdatarollup-custom-rpc`, pinned at `1.2.0` in a new workspace package `services/silent-data-gateway`, and built into a local-only image.
- The devnet state generator also runs for 31339. Every local chain gets the private test token `GianoTestPrivateErc20`, and `e2e/devnet/addresses.json` records its address.
- The local stacks (`deploy/docker-compose.infrastructure.yml` and `deploy/docker-compose.e2e.yml`) run the new chain. wallet-api, the bundler, paymaster-admin, both wallets and the demo dApp reach it only through the gateway. The backend chain entry sets `bundler.stateOverride: false`, as the dev environment does for iron-kestrel.
- The demo dApp lists 31339 with `privateToken`, for both instances: `stock` (wallet-web) and `byo` (the BYO wallet fixture). The sponsorship provisioner installs both tenants' rules on 31339 and allow-lists the private token.
- The BYO wallet fixture (`e2e/wallet-byo`) takes one `CHAINS` list instead of the fixed pair `CHAIN_ID` / `CHAIN_B_ID`. The pair stays as a fallback, because the AWS dev environment sets it.
- A new e2e spec, `e2e/tests/demo/demo-private-token.spec.ts`, in the opt-in demo project. It checks that the gateway enforces privacy, and drives the private token section for `stock` and for `byo`. CI runs it in the existing "reference demo" leg.

The work ships as a stack of five PRs, merged bottom-up. `tasks.md` lists them. This change folder is PR 1.

Decided:

- 31339 is a new chain. Devnet B stays plain anvil. The gateway refuses every `anvil_*` method and `eth_getStorageAt`, and the existing tests and the demo's "fund from devnet" control use them on 31337 and 31338.
- The gateway runs from the published package, not from a copy of its source. A version change is an ordinary pinned dependency upgrade.
- No component treats 31339 as a Silent Data chain by its id. It is configured like iron-kestrel in dev: through `GIANO_CHAINS`, with `stateOverride: false`. 31339 does join the lists of local devnet chain ids, next to 31337 and 31338.

**Non-goals:**

- The gasless variant of a Silent Data chain (base fee 0). Anvil charges gas, as iron-kestrel does.
- The L1 data fee. Anvil is not OP Stack, so the local chain does not reproduce iron-kestrel's L1 fee.
- A readable consent screen for the read-delegate approval. The wallets show the `personal_sign` message as a raw hash, as they do today.
- The `byoui` demo on the AWS dev environment. Decided: it lists iron-kestrel, in a separate infra PR after PR 2 merges (`tasks.md`, "Workflow follow-up"). That PR needs only PR 2 of this stack.
- Publishing the gateway image. It runs only in local stacks and in CI.

## Capabilities

### New Capabilities

- `local-silent-data-chain`: the local Silent Data chain. How local stacks run it (anvil behind the published gateway), how its state is baked, how every component reaches it, how both demo tenants are sponsored on it, and the e2e tests that prove the gateway enforces privacy.

### Modified Capabilities

- `demo-deployment`: "Local development parity" adds the Silent Data chain, with `privateToken`, to the chain list of both local demo instances.

`demo-dapp` needs no delta. Its "Native balance and funding" requirement already covers a node that refuses `anvil_setBalance`, which is what the gateway does. The private token section's own requirements are in `silent-data-network`, which is not archived yet, and this change does not alter them. `local-tenant-fixtures` needs no delta either: fixture tenants are rows in the database and do not depend on a chain.

## Impact

- **Code:**
  - `e2e/wallet-byo/serve.mjs` and `e2e/wallet-byo/src/config.ts` (the `CHAINS` list);
  - new `services/silent-data-gateway` (manifest and `Dockerfile`);
  - `e2e/devnet/generate-state.mjs`, `e2e/devnet/with-pinned-anvil.mjs`, `e2e/devnet/provision-sponsorship.mjs`, `e2e/devnet/provision-tx-mappings.mjs`, `e2e/package.json`;
  - `packages/contracts/deploy/config.ts` (`LOCAL_CHAIN_IDS`), `packages/contracts/chains.ts` and `packages/wallet-kit/src/config.ts` (the known chain names), `packages/contracts/scripts/deployer-entrypoint.mjs`;
  - `services/paymaster-admin/src/lib/health.ts` (`LOCAL_DEVNET_CHAIN_IDS`);
  - `services/custom-example/.env.development` (the chain list of `dev:stock` and `dev:byo`).
- **Configuration:** `deploy/docker-compose.infrastructure.yml`, `deploy/docker-compose.e2e.yml`, `deploy/infrastructure/Caddyfile`, `e2e/origins.mjs`, `e2e/playwright.config.ts`, `.github/workflows/e2e.yml`, and the SPA parity fixtures in `scripts/spa-parity/fixtures`.
- **Baked state:** `e2e/devnet/state.json` and `state-31338.json` are regenerated. `state-31339.json` is new. `addresses.json` gains `privateTestErc20`.
- **Dependencies:** `@appliedblockchain/silentdatarollup-custom-rpc` `1.2.0` (published 2026-06-16, so ABIP-6 allows it). It brings `express` 4.21.2, `body-parser` 1.20.3, `http-proxy-middleware` 3.0.5, `ethers` 6.13.2, `dotenv` 16.4.7 and `@appliedblockchain/silentdatarollup-core` 1.2.0. It needs Node 20 or later.
- **Changesets:** `giano-contracts` patch (`LOCAL_CHAIN_IDS` and the chain name) and `giano-wallet-kit` patch (the chain name), in PR 3.
- **Tests:** a new demo e2e spec. The existing e2e tests must still pass with a third chain in wallet-web's and wallet-byo's lists.
- **Integrators:** no change. 31339 exists only in local stacks.
