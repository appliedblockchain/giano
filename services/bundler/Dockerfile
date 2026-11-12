# giano-bundler — Giano's own ERC-4337 submission service. Build from the REPO ROOT:
#   docker build -f services/bundler/Dockerfile -t ghcr.io/appliedblockchain/giano-bundler .
# Refuses to start with missing keys or the well-known Anvil key unless GIANO_DEV_MODE=true
# (src/config.ts). Pulling the bases needs `docker login dhi.io` (docs/abip-compliance.md).
#
# ABIP-2: every stage on a digest-pinned Docker Hardened Image — -dev to build, the runtime variant to
# run. The runtime has no shell, no package manager and no curl, and runs as the image's own non-root
# user (node, 1000:1000). src/index.ts handles SIGTERM itself, as PID 1 with no init.

FROM dhi.io/node:24-alpine3.23-dev@sha256:93960e52ba08d91ed90a09d26c112752fa6b1ee64e5471716923d125c61c509f AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/contracts/vendor/account-abstraction packages/contracts/vendor/account-abstraction
COPY services/bundler/package.json services/bundler/package.json
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-bundler...
COPY packages/contracts packages/contracts
COPY services/bundler services/bundler
# contracts: committed generated.ts/addresses.ts -> tsdown only, no solc. `deploy --prod` is the prune
# step: /out holds dist/ and production dependencies only.
# TypeScript is a type-only optional peer of viem, ox and abitype. pnpm links it to them because
# the workspace has it as a devDependency, so it would reach the runtime. Nothing loads it at
# runtime, and its native compiler (a Go binary) carries Go stdlib advisories that fail the image
# scan (G25), so it is removed once the build no longer needs it.
RUN pnpm --filter @appliedblockchain/giano-contracts build:ts \
 && pnpm --filter @appliedblockchain/giano-bundler build \
 && pnpm --filter @appliedblockchain/giano-bundler --legacy deploy --prod /out \
 && rm -rf /out/node_modules/.pnpm/typescript@* /out/node_modules/.pnpm/@typescript+*

FROM dhi.io/node:24-alpine3.23@sha256:ea44fbd46a8e11a9ffb9b2bd5c6e4722fa507fb86fef0ee8d92a020ce7c850a5
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=1000:1000 /out /app
EXPOSE 4337
# Healthy while any configured chain serves (GET /health lists each chain's own status).
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:4337/health',{signal:AbortSignal.timeout(2500)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/index.js"]
