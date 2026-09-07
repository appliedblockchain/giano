# giano-example — build from the REPO ROOT:
#   docker build -f services/custom-example/Dockerfile -t ghcr.io/appliedblockchain/giano-example .
# Static SPA + nginx; runtime config injected at start via /config.js (envsubst). §16.1
#
# ONE image serves every deployment and BOTH demo tenants: `custom-example` and
# `custom-example-byoui` are the same image with a different GIANO_WALLET_URL and
# GIANO_APP_LABEL (§14.4). Nothing environment-specific may enter this build — which is why
# the `VITE_*` variables are not build args here: they survive only as `pnpm dev` fallbacks
# inside src/config.ts.

FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/wallet-transport/package.json packages/wallet-transport/package.json
COPY packages/connector/package.json packages/connector/package.json
COPY services/custom-example/package.json services/custom-example/package.json
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-example...
COPY packages/contracts packages/contracts
COPY packages/wallet-transport packages/wallet-transport
COPY packages/connector packages/connector
COPY services/custom-example services/custom-example
# Dependency order, not alphabetical: connector depends on wallet-transport, and the demo's
# `build` script runs `tsc --noEmit` first, so every workspace dependency must have emitted
# its types before it runs.
RUN pnpm --filter @appliedblockchain/giano-contracts build:ts \
 && pnpm --filter @appliedblockchain/giano-wallet-transport build \
 && pnpm --filter @appliedblockchain/giano-connector build \
 && pnpm --filter @appliedblockchain/giano-example build

FROM nginx:1.27-alpine
RUN apk add --no-cache curl
COPY --from=build /repo/services/custom-example/dist /usr/share/nginx/html
COPY services/custom-example/docker/nginx.conf.template /etc/giano/nginx.conf.template
COPY services/custom-example/docker/config.js.template /etc/giano/config.js.template
COPY services/custom-example/docker/entrypoint.sh /entrypoint.sh
# The dist carries a placeholder public/config.js so `pnpm dev` and `pnpm preview` work; the
# entrypoint overwrites it at start. Ownership has to move to `nginx` for that write to
# succeed as a non-root user.
RUN chmod +x /entrypoint.sh && rm /etc/nginx/conf.d/default.conf \
 && touch /etc/nginx/conf.d/default.conf \
 && chown -R nginx:nginx /etc/nginx/conf.d /usr/share/nginx/html /var/cache/nginx /var/log/nginx \
 && sed -i 's/^pid .*/pid \/tmp\/nginx.pid;/' /etc/nginx/nginx.conf
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD curl -fsS http://127.0.0.1:8080/ > /dev/null || exit 1
ENTRYPOINT ["/entrypoint.sh"]
