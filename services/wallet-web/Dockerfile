# giano-wallet-web — build from the REPO ROOT:
#   docker build -f services/wallet-web/Dockerfile -t ghcr.io/appliedblockchain/giano-wallet-web .
# Static SPA + nginx; runtime config injected at start via /config.json (envsubst).
#
# ABIP-2: digest-pinned Docker Hardened Images. The runtime is DHI nginx, which runs as nginx
# (65532:65532) and has no shell; the start-up script renders /config.json and the server block from
# GIANO_* variables, so exactly /bin/sh, envsubst and jq are copied in from the nginx -dev image
# (docs/abip-compliance.md, SPA tool allow-list) and the script uses nothing else.

FROM dhi.io/node:22-alpine3.23-dev@sha256:d3e27128c752bc57454dbb824f8ba770ecf211cc8098a471a8fbd68185dd053f AS build
RUN corepack enable
WORKDIR /repo
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json tsconfig.base.json ./
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/wallet-core/package.json packages/wallet-core/package.json
COPY packages/wallet-transport/package.json packages/wallet-transport/package.json
COPY packages/wallet-kit/package.json packages/wallet-kit/package.json
COPY packages/tx-describe/package.json packages/tx-describe/package.json
COPY services/wallet-web/package.json services/wallet-web/package.json
RUN pnpm install --frozen-lockfile --filter @appliedblockchain/giano-wallet-web...
COPY packages/contracts packages/contracts
COPY packages/wallet-core packages/wallet-core
COPY packages/wallet-transport packages/wallet-transport
COPY packages/tx-describe packages/tx-describe
COPY packages/wallet-kit packages/wallet-kit
COPY services/wallet-web services/wallet-web
RUN pnpm --filter @appliedblockchain/giano-contracts build:ts \
 && pnpm --filter @appliedblockchain/giano-wallet-core build \
 && pnpm --filter @appliedblockchain/giano-wallet-transport build \
 && pnpm --filter @appliedblockchain/giano-tx-describe build \
 && pnpm --filter @appliedblockchain/giano-wallet-kit build \
 && pnpm --filter @appliedblockchain/giano-wallet-web build

# The SPA tool allow-list, staged at its real paths with exactly the shared libraries it links
# beyond what the runtime already has (glibc and the loader), plus the html root owned by nginx so
# the entrypoint can render config.json into it. The final stage takes all of it in one COPY.
FROM dhi.io/nginx:1.29-debian13-dev@sha256:069b266be81839d8cfcfef9e636a3ced9c383818511b2abbd33db53efadbbbff AS tools
RUN apt-get update && apt-get install -y --no-install-recommends dash jq gettext-base \
 && rm -rf /var/lib/apt/lists/*
COPY deploy/docker/stage-spa-tools.sh /usr/local/bin/stage-spa-tools.sh
RUN sh /usr/local/bin/stage-spa-tools.sh /staging

FROM dhi.io/nginx:1.29-debian13@sha256:d457a278247531873df03b7fdaabd96de0b530624f8e72c73d41e6b81c4487dd
COPY --from=tools /staging/ /
COPY --from=build --chown=65532:65532 /repo/services/wallet-web/dist /usr/share/nginx/html
COPY services/wallet-web/docker/nginx.conf.template /etc/giano/nginx.conf.template
COPY services/wallet-web/docker/config.json.template /etc/giano/config.json.template
COPY services/wallet-web/docker/config.multichain.json.template /etc/giano/config.multichain.json.template
COPY --chmod=0755 services/wallet-web/docker/entrypoint.sh /entrypoint.sh
EXPOSE 8080
# No HTTP client in the image, by design: liveness from shell built-ins (nginx is up, config is
# rendered). The HTTP check on / is the ALB's, Helm's httpGet probe, and e2e.yml's curl.
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD ["/bin/sh", "-c", "test -s /run/nginx/nginx.pid && test -s /usr/share/nginx/html/config.json"]
ENTRYPOINT ["/entrypoint.sh"]
