# giano-paymaster-admin — build from the REPO ROOT:
#   docker build -f services/paymaster-admin/Dockerfile -t ghcr.io/appliedblockchain/giano-paymaster-admin .
# Static SPA + nginx; runtime config injected at start via /config.json (envsubst).

FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/paymaster-sdk/package.json packages/paymaster-sdk/package.json
COPY services/paymaster-admin/package.json services/paymaster-admin/package.json
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-paymaster-admin...
COPY packages/contracts packages/contracts
COPY packages/paymaster-sdk packages/paymaster-sdk
COPY services/paymaster-admin services/paymaster-admin
RUN pnpm --filter @appliedblockchain/giano-contracts build:ts \
 && pnpm --filter @appliedblockchain/giano-paymaster-sdk build \
 && pnpm --filter @appliedblockchain/giano-paymaster-admin build

FROM nginx:1.27-alpine
RUN apk add --no-cache curl
COPY --from=build /repo/services/paymaster-admin/dist /usr/share/nginx/html
COPY services/paymaster-admin/docker/nginx.conf.template /etc/giano/nginx.conf.template
COPY services/paymaster-admin/docker/config.json.template /etc/giano/config.json.template
COPY services/paymaster-admin/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && rm /etc/nginx/conf.d/default.conf \
 && touch /etc/nginx/conf.d/default.conf \
 && chown -R nginx:nginx /etc/nginx/conf.d /usr/share/nginx/html /var/cache/nginx /var/log/nginx \
 && sed -i 's/^pid .*/pid \/tmp\/nginx.pid;/' /etc/nginx/nginx.conf
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD curl -fsS http://127.0.0.1:8080/ > /dev/null || exit 1
ENTRYPOINT ["/entrypoint.sh"]
