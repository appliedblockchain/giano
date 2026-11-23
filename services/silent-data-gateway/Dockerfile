# giano-silent-data-gateway — build from the REPO ROOT:
#   docker build -f services/silent-data-gateway/Dockerfile -t giano-silent-data-gateway .
#
# Silent Data's RPC gateway in front of the local Devnet SD chain (31339). It runs the published
# @appliedblockchain/silentdatarollup-custom-rpc package, at the version this package's manifest
# pins and the repository's lockfile resolves, with no change to its code. start.mjs checks the
# environment and handles the stop signals, then loads it. See README.md.
#
# Local-only: the infrastructure and e2e stacks build it. .github/workflows/docker.yml does not
# build or publish it, so the container-images checks of published images do not cover it. It
# follows ABIP-2 anyway: digest-pinned Docker Hardened Images (the digests of
# e2e/wallet-byo/Dockerfile), -dev to install and the runtime variant to run. The runtime has no
# shell; it runs as node (1000:1000).

FROM dhi.io/node:24-alpine3.23-dev@sha256:93960e52ba08d91ed90a09d26c112752fa6b1ee64e5471716923d125c61c509f AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY services/silent-data-gateway/package.json services/silent-data-gateway/package.json
# Only this package and its production dependencies, from the lockfile.
RUN pnpm install --frozen-lockfile --prod --filter @appliedblockchain/giano-silent-data-gateway

FROM dhi.io/node:24-alpine3.23@sha256:ea44fbd46a8e11a9ffb9b2bd5c6e4722fa507fb86fef0ee8d92a020ce7c850a5
# The whole tree, so pnpm's symlinks into node_modules/.pnpm stay internally consistent.
COPY --from=build --chown=1000:1000 /repo /repo
COPY --chown=1000:1000 services/silent-data-gateway/start.mjs /repo/services/silent-data-gateway/start.mjs
WORKDIR /repo/services/silent-data-gateway
# The gateway's default is 54321. 8545 is the port of every RPC in the local stacks. The stack
# sets CUSTOM_RPC_PROXY_URL to the node, for example http://anvil-sd:8545. start.mjs refuses to
# start without it.
ENV CUSTOM_RPC_PORT=8545
EXPOSE 8545
# The gateway has no health endpoint, so the check sends eth_chainId, which the gateway allows and
# forwards to the node. It passes only when the gateway and the node both answer.
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=10 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8545/',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_chainId',params:[]}),signal:AbortSignal.timeout(2500)}).then(r=>r.json()).then(j=>process.exit(j.result?0:1),()=>process.exit(1))"]
ENTRYPOINT ["node", "start.mjs"]
