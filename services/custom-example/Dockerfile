# giano-example — build from the REPO ROOT:
#   docker build -f services/custom-example/Dockerfile -t ghcr.io/appliedblockchain/giano-example .
# Static SPA + nginx; runtime config injected at start via /config.js (envsubst, the Baanx pattern).
#
# ONE image serves every deployment and BOTH demo tenants: `custom-example` and `custom-example-byoui`
# are the same image with a different GIANO_WALLET_URL and GIANO_APP_LABEL. Nothing
# environment-specific may enter this build — there are no `VITE_*` build args, and the post-build
# scan (scripts/scan-bundle.mjs) fails the build if one leaks into dist/.
#
# ABIP-2: digest-pinned Docker Hardened Images. The runtime is DHI nginx, which runs as nginx
# (65532:65532) and has no shell; the start-up script renders /config.js and the server block from
# GIANO_* variables, so exactly /bin/sh, envsubst and jq are copied in from the nginx -dev image
# (docs/abip-compliance.md, SPA tool allow-list) and the script uses nothing else.

FROM dhi.io/node:22-alpine3.23-dev@sha256:d3e27128c752bc57454dbb824f8ba770ecf211cc8098a471a8fbd68185dd053f AS build
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

# The SPA tool allow-list, staged at its real paths with exactly the shared libraries it links
# beyond what the runtime already has (glibc and the loader), plus the html root owned by nginx so
# the entrypoint can render config.js into it. The final stage takes all of it in one COPY.
FROM dhi.io/nginx:1.29-debian13-dev@sha256:069b266be81839d8cfcfef9e636a3ced9c383818511b2abbd33db53efadbbbff AS tools
RUN apt-get update && apt-get install -y --no-install-recommends dash jq gettext-base \
 && rm -rf /var/lib/apt/lists/*
COPY deploy/docker/stage-spa-tools.sh /usr/local/bin/stage-spa-tools.sh
RUN sh /usr/local/bin/stage-spa-tools.sh /staging

FROM dhi.io/nginx:1.29-debian13@sha256:d457a278247531873df03b7fdaabd96de0b530624f8e72c73d41e6b81c4487dd
COPY --from=tools /staging/ /
# The dist carries a placeholder public/config.js so `pnpm dev` and `pnpm preview` work; the
# entrypoint overwrites it at start, which is why the html root is the nginx user's.
COPY --from=build --chown=65532:65532 /repo/services/custom-example/dist /usr/share/nginx/html
COPY services/custom-example/docker/nginx.conf.template /etc/giano/nginx.conf.template
COPY services/custom-example/docker/config.js.template /etc/giano/config.js.template
COPY --chmod=0755 services/custom-example/docker/entrypoint.sh /entrypoint.sh
EXPOSE 8080
# No HTTP client in the image, by design: liveness from shell built-ins (nginx is up, config is
# rendered). The HTTP check on / is the ALB's, Helm's httpGet probe, and e2e.yml's curl.
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD ["/bin/sh", "-c", "test -s /run/nginx/nginx.pid && test -s /usr/share/nginx/html/config.js"]
ENTRYPOINT ["/entrypoint.sh"]
