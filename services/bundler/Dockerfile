# giano-bundler — pinned @pimlico/alto, env-driven. Refuses to start with missing keys
# or the well-known Anvil key unless GIANO_DEV_MODE=true.
#   docker build -f services/bundler/Dockerfile -t ghcr.io/appliedblockchain/giano-bundler .
FROM node:22-alpine
RUN apk add --no-cache curl tini && npm i -g @pimlico/alto@0.0.18
COPY services/bundler/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 4337
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD curl -fsS -X POST -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"eth_supportedEntryPoints","params":[]}' \
    http://127.0.0.1:4337 || exit 1
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
