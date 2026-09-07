# giano-wallet-api — build from the REPO ROOT so the workspace dep is bundled:
#   docker build -f services/wallet-api/Dockerfile -t ghcr.io/appliedblockchain/giano-wallet-api .
# No registry auth needed: @appliedblockchain/giano-contracts is built from source here.

FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/package.json
COPY services/wallet-api/package.json services/wallet-api/package.json
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-wallet-api...
COPY packages/contracts packages/contracts
COPY services/wallet-api services/wallet-api
# contracts: committed generated.ts/addresses.ts -> tsup only, no solc
RUN pnpm --filter @appliedblockchain/giano-contracts build:ts \
 && pnpm --filter @appliedblockchain/giano-wallet-api build \
 && pnpm --filter @appliedblockchain/giano-wallet-api --legacy deploy --prod /out

FROM node:22-alpine
ENV NODE_ENV=production
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build --chown=node:node /out /app
USER node
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
# migrations are bundled; either set RUN_MIGRATIONS=true or run the one-shot:
#   docker run ... node dist/migrate.js
CMD ["node", "dist/index.js"]
