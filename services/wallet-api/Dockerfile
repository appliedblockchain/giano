# giano-wallet-api — build from the REPO ROOT so the workspace dep is bundled:
#   docker build -f services/wallet-api/Dockerfile -t ghcr.io/appliedblockchain/giano-wallet-api .
# No registry auth needed for Giano's own packages: @appliedblockchain/giano-contracts is built from
# source here. Pulling the bases needs `docker login dhi.io` (docs/abip-compliance.md).
#
# ABIP-2: every stage on a digest-pinned Docker Hardened Image — -dev to build, the runtime variant to
# run. The runtime has no shell, no package manager and no curl, and runs as the image's own non-root
# user (node, 1000:1000); refresh a pin with docs/abip-compliance.md § "Refreshing a pinned digest".

FROM dhi.io/node:22-alpine3.23-dev@sha256:d3e27128c752bc57454dbb824f8ba770ecf211cc8098a471a8fbd68185dd053f AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/tx-describe/package.json packages/tx-describe/package.json
COPY services/wallet-api/package.json services/wallet-api/package.json
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-wallet-api...
COPY packages/contracts packages/contracts
COPY packages/tx-describe packages/tx-describe
COPY services/wallet-api services/wallet-api
# contracts: committed generated.ts/addresses.ts -> tsup only, no solc. `deploy --prod` is the prune
# step: /out holds dist/ and production dependencies only.
RUN pnpm --filter @appliedblockchain/giano-contracts build:ts \
 && pnpm --filter @appliedblockchain/giano-tx-describe build \
 && pnpm --filter @appliedblockchain/giano-wallet-api build \
 && pnpm --filter @appliedblockchain/giano-wallet-api --legacy deploy --prod /out

FROM dhi.io/node:22-alpine3.23@sha256:920a7460ab7ac19ce6a9a38fb23b244bcfed1cf78705f7fe117195c58b307f4d
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=1000:1000 /out /app
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz',{signal:AbortSignal.timeout(2500)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
# migrations are bundled; either set RUN_MIGRATIONS=true or run the one-shot:
#   docker run ... node dist/migrate.js
CMD ["node", "dist/index.js"]
