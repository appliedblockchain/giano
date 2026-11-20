# silent-data-gateway

Silent Data's RPC gateway in front of the local Silent Data chain, 31339 "Devnet SD (Silent Data)". It is the published package [`@appliedblockchain/silentdatarollup-custom-rpc`](https://www.npmjs.com/package/@appliedblockchain/silentdatarollup-custom-rpc), run with no change to its code. This package holds only its pin, the `Dockerfile` and this file.

The gateway sits between clients and an anvil node. It allows a fixed list of methods, checks the signer of private reads, and refuses everything else, including `eth_getStorageAt` and every `anvil_*`, `evm_*` and `debug_*` method. So the local chain enforces privacy the way iron-kestrel does on the AWS dev environment.

## Local only

Only the local infrastructure and e2e stacks build and run this image. `.github/workflows/docker.yml` does not build or publish it, and no deployed environment runs it. The image still follows ABIP-2: digest-pinned Docker Hardened Images (the digests of `e2e/wallet-byo/Dockerfile`), no shell, and an exec-form healthcheck.

## Where the package comes from

The gateway comes from npmjs, not GitHub Packages. The root workspace has no `.npmrc` that maps the `@appliedblockchain` scope to another registry. Only `services/custom-example`, a separate workspace, does that. If someone adds such a line to the root workspace, the install fails. It does not pick another package.

## Build and run

Build from the repository root:

```sh
docker build -f services/silent-data-gateway/Dockerfile -t giano-silent-data-gateway .
docker run --rm -p 8548:8545 -e CUSTOM_RPC_PROXY_URL=http://host.docker.internal:8547 giano-silent-data-gateway
```

## Environment

| Variable | Image value | What it does |
|---|---|---|
| `CUSTOM_RPC_PORT` | `8545` | The port the gateway listens on. The package's own default is 54321. |
| `CUSTOM_RPC_PROXY_URL` | none (the package default is `http://localhost:8545`) | The node behind the gateway. The stacks set it, for example `http://anvil-sd:8545`. |
| `CUSTOM_RPC_LOGS_LIMIT_RANGE` | package default, 10,000 | The widest block range `eth_getLogs` accepts. |
| `CUSTOM_RPC_PER_PAGE` | package default, 10 | The page size of `sd_getTransactionsByAddress`. |
| `CUSTOM_RPC_BYPASS_METHOD_PREFIXES` | unset | Method prefixes the gateway forwards without its checks. Leave it unset, so the local chain behaves as iron-kestrel does. |

The gateway has no health endpoint. The image's healthcheck sends `eth_chainId`, so it passes only when the gateway and the node both answer.

## Upgrade the pin

1. Check that the new version was published at least 7 days ago (ABIP-6).
2. Set the exact version in `package.json` (ABIP-7) and run `pnpm install`.
3. Run `pnpm audit`. The root `pnpm-workspace.yaml` has overrides for the gateway's express 4 dependencies (body-parser, path-to-regexp, http-proxy-middleware and qs). Remove each one that the new version no longer needs.
4. Commit `package.json`, `pnpm-workspace.yaml` (if changed) and `pnpm-lock.yaml` alone.
5. Build the image, run it in front of an anvil node, and check that it answers `eth_chainId` and still refuses `eth_getStorageAt` and `anvil_setBalance`.
