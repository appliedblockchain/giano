# giano-bundler — Giano's own ERC-4337 submission service. Build from the REPO ROOT:
#   docker build -f services/bundler/Dockerfile -t ghcr.io/appliedblockchain/giano-bundler .
# Refuses to start with missing keys or the well-known Anvil key unless GIANO_DEV_MODE=true
# (src/config.ts). Pulling the bases needs `docker login dhi.io` (docs/abip-compliance.md).
#
# ABIP-2: every stage on a digest-pinned Docker Hardened Image — -dev to build, the runtime variant to
# run. The runtime has no shell, no package manager and no curl, and runs as the image's own non-root
# user (node, 1000:1000). src/index.ts handles SIGTERM itself, as PID 1 with no init.

FROM dhi.io/node:22-alpine3.23-dev@sha256:d3e27128c752bc57454dbb824f8ba770ecf211cc8098a471a8fbd68185dd053f AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/package.json
COPY services/bundler/package.json services/bundler/package.json
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-bundler...
COPY packages/contracts packages/contracts
COPY services/bundler services/bundler
# contracts: committed generated.ts/addresses.ts -> tsup only, no solc. `deploy --prod` is the prune
# step: /out holds dist/ and production dependencies only.
RUN pnpm --filter @appliedblockchain/giano-contracts build:ts \
 && pnpm --filter @appliedblockchain/giano-bundler build \
 && pnpm --filter @appliedblockchain/giano-bundler --legacy deploy --prod /out

FROM dhi.io/node:22-alpine3.23@sha256:920a7460ab7ac19ce6a9a38fb23b244bcfed1cf78705f7fe117195c58b307f4d
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=1000:1000 /out /app
EXPOSE 4337
# Healthy while any configured chain serves (GET /health lists each chain's own status).
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:4337/health',{signal:AbortSignal.timeout(2500)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/index.js"]
