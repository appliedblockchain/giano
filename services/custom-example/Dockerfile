# giano-example — build from the REPO ROOT:
#   docker build -f services/custom-example/Dockerfile -t ghcr.io/appliedblockchain/giano-example .
# Static SPA + nginx; runtime config injected at start via /config.js (envsubst, the Baanx pattern).
#
# ONE image serves every deployment and BOTH demo tenants: `custom-example` and `custom-example-byoui`
# are the same image with a different GIANO_WALLET_URL and GIANO_APP_LABEL. Nothing
# environment-specific may enter this build — there are no `VITE_*` build args, and the post-build
# scan (scripts/scan-bundle.mjs) fails the build if one leaks into dist/.

FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
# ┌─ H2 (publish to GitHub Packages) removes this block ──────────────────────────────────────────
# │ Until the connector is installed from the registry, the demo builds its workspace dependency and
# │ that dependency's own dependency here. The demo's source imports only the connector's public
# │ entry point, so when H2 lands these lines go and `pnpm install` below fetches the same package
# │ from npm.pkg.github.com — no source change.
COPY packages/wallet-transport/package.json packages/wallet-transport/package.json
COPY packages/connector/package.json packages/connector/package.json
# └────────────────────────────────────────────────────────────────────────────────────────────────
COPY services/custom-example/package.json services/custom-example/package.json
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-example...
# ┌─ H2 removes this block too ────────────────────────────────────────────────────────────────────
COPY packages/wallet-transport packages/wallet-transport
COPY packages/connector packages/connector
RUN pnpm --filter @appliedblockchain/giano-wallet-transport build \
 && pnpm --filter @appliedblockchain/giano-connector build
# └────────────────────────────────────────────────────────────────────────────────────────────────
COPY services/custom-example services/custom-example
# lint + typecheck + vite build + bundle scan (package.json `build`)
RUN pnpm --filter @appliedblockchain/giano-example build

FROM nginx:1.27-alpine
RUN apk add --no-cache curl
COPY --from=build /repo/services/custom-example/dist /usr/share/nginx/html
COPY services/custom-example/docker/nginx.conf.template /etc/giano/nginx.conf.template
COPY services/custom-example/docker/config.js.template /etc/giano/config.js.template
COPY services/custom-example/docker/entrypoint.sh /entrypoint.sh
# The dist carries a placeholder public/config.js so `pnpm dev` and `pnpm preview` work; the
# entrypoint overwrites it at start. Ownership has to move to `nginx` for that write to succeed as a
# non-root user.
RUN chmod +x /entrypoint.sh && rm /etc/nginx/conf.d/default.conf \
 && touch /etc/nginx/conf.d/default.conf \
 && chown -R nginx:nginx /etc/nginx/conf.d /usr/share/nginx/html /var/cache/nginx /var/log/nginx \
 && sed -i 's/^pid .*/pid \/tmp\/nginx.pid;/' /etc/nginx/nginx.conf
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 CMD curl -fsS http://127.0.0.1:8080/ > /dev/null || exit 1
ENTRYPOINT ["/entrypoint.sh"]
