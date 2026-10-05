# giano-wallet-byo — build from the REPO ROOT:
#   docker build -f e2e/wallet-byo/Dockerfile -t ghcr.io/appliedblockchain/giano-wallet-byo .
#
# Tenant `byoui`'s wallet origin: the framework-free SPA a real BYO tenant copies
# (DEVELOPER-GUIDE.md §5.5b). §16.5 of specs/INFRASTRUCTURE.md.
#
# There is NO build step, deliberately: serve.mjs bundles the SPA with esbuild at CONTAINER
# START, from environment. That is what makes this image environment-independent in the way
# §16.1 has to *make* custom-example be — one image, every deployment, with no /config.json
# machinery — and §16.5 says to keep it. The cost is that node_modules ships in the runtime
# image, which for a fixture-sized SPA is the right trade.
#
# It is also the only service in the deployment Giano would not run in a real environment: a
# real BYO tenant hosts its own UI. It exists here so the BYO serving contract is exercised
# rather than described (D17).
#
# ABIP-2: digest-pinned Docker Hardened Images, -dev to build and the runtime variant to run. The
# runtime has no shell, no tini and no curl; it runs as node (1000:1000), and serve.mjs handles
# SIGTERM itself — which is all tini was for.

FROM dhi.io/node:22-alpine3.23-dev@sha256:d3e27128c752bc57454dbb824f8ba770ecf211cc8098a471a8fbd68185dd053f AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/wallet-core/package.json packages/wallet-core/package.json
COPY packages/wallet-transport/package.json packages/wallet-transport/package.json
COPY packages/wallet-kit/package.json packages/wallet-kit/package.json
COPY packages/tx-describe/package.json packages/tx-describe/package.json
COPY packages/connector/package.json packages/connector/package.json
COPY e2e/package.json e2e/package.json
# The SPA's dependencies (esbuild, viem, wallet-core, wallet-transport, wallet-kit) are all
# devDependencies of the e2e workspace, so this install cannot be --prod.
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-e2e...
COPY packages/contracts packages/contracts
COPY packages/wallet-core packages/wallet-core
COPY packages/wallet-transport packages/wallet-transport
COPY packages/tx-describe packages/tx-describe
COPY packages/wallet-kit packages/wallet-kit
COPY packages/connector packages/connector
COPY e2e/wallet-byo e2e/wallet-byo
# Only the workspace packages need compiling — the SPA itself is bundled at container start.
# The order is a dependency order, not alphabetical: wallet-core depends on contracts, and the
# kit on both wallet-core and wallet-transport.
RUN pnpm --filter @appliedblockchain/giano-contracts build:ts \
 && pnpm --filter @appliedblockchain/giano-wallet-transport build \
 && pnpm --filter @appliedblockchain/giano-wallet-core build \
 && pnpm --filter @appliedblockchain/giano-tx-describe build \
 && pnpm --filter @appliedblockchain/giano-wallet-kit build

FROM dhi.io/node:22-alpine3.23@sha256:920a7460ab7ac19ce6a9a38fb23b244bcfed1cf78705f7fe117195c58b307f4d
# The whole tree, so pnpm's symlinks into node_modules/.pnpm stay internally consistent. The
# pnpm store itself lives outside /repo and is left behind here.
COPY --from=build --chown=1000:1000 /repo /repo
WORKDIR /repo/e2e/wallet-byo
# Matches var.container_port, and means the image runs correctly with no environment at all
# beyond the endpoints it cannot guess.
ENV BYO_WALLET_PORT=8080
EXPOSE 8080
# ⚠ NOT copied into this image, and that is the point of §16.5: e2e/devnet/addresses.json and
# e2e/origins.mjs. serve.mjs used to read both unconditionally at start-up and crashed without
# them; they are devnet artefacts with no business in a deployed image. Absent, every value
# they used to default becomes a required environment variable that fails loudly.
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/',{signal:AbortSignal.timeout(2500)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["node", "serve.mjs"]
