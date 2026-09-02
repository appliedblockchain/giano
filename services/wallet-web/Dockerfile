# giano-wallet-web — build from the REPO ROOT:
#   docker build -f services/wallet-web/Dockerfile -t ghcr.io/appliedblockchain/giano-wallet-web .
# Static SPA + nginx; runtime config injected at start via /config.json (envsubst).

FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/wallet-core/package.json packages/wallet-core/package.json
COPY packages/wallet-transport/package.json packages/wallet-transport/package.json
COPY packages/wallet-kit/package.json packages/wallet-kit/package.json
COPY services/wallet-web/package.json services/wallet-web/package.json
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-wallet-web...
COPY packages/contracts packages/contracts
COPY packages/wallet-core packages/wallet-core
COPY packages/wallet-transport packages/wallet-transport
COPY packages/wallet-kit packages/wallet-kit
COPY services/wallet-web services/wallet-web
RUN pnpm --filter @appliedblockchain/giano-contracts build:ts \
 && pnpm --filter @appliedblockchain/giano-wallet-core build \
 && pnpm --filter @appliedblockchain/giano-wallet-transport build \
 && pnpm --filter @appliedblockchain/giano-wallet-kit build \
 && pnpm --filter @appliedblockchain/giano-wallet-web build

FROM nginx:1.27-alpine
RUN apk add --no-cache curl
COPY --from=build /repo/services/wallet-web/dist /usr/share/nginx/html
COPY services/wallet-web/docker/nginx.conf.template /etc/giano/nginx.conf.template
COPY services/wallet-web/docker/config.json.template /etc/giano/config.json.template
COPY services/wallet-web/docker/config.multichain.json.template /etc/giano/config.multichain.json.template
COPY services/wallet-web/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && rm /etc/nginx/conf.d/default.conf \
 && touch /etc/nginx/conf.d/default.conf \
 && chown -R nginx:nginx /etc/nginx/conf.d /usr/share/nginx/html /var/cache/nginx /var/log/nginx \
 && sed -i 's/^pid .*/pid \/tmp\/nginx.pid;/' /etc/nginx/nginx.conf
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD curl -fsS http://127.0.0.1:8080/ > /dev/null || exit 1
ENTRYPOINT ["/entrypoint.sh"]
