# giano-bundler — pinned @pimlico/alto, env-driven. Refuses to start with missing keys
# or the well-known Anvil key unless GIANO_DEV_MODE=true (entrypoint.mjs).
#   docker build -f services/bundler/Dockerfile -t ghcr.io/appliedblockchain/giano-bundler .
#
# ABIP-2: alto is installed in the -dev stage, as root but into /app rather than globally, and the
# hardened runtime gets /app alone — no shell, no npm, no tini, no curl; it runs as node (1000:1000).
# entrypoint.mjs runs alto in-process and handles SIGTERM itself, which is what tini was for.
FROM dhi.io/node:22-alpine3.23-dev@sha256:d3e27128c752bc57454dbb824f8ba770ecf211cc8098a471a8fbd68185dd053f AS build
WORKDIR /app
RUN npm install --prefix /app --no-audit --no-fund --omit=dev @pimlico/alto@0.0.18
# Alto 0.0.18's safe-mode tracer predates RIP-7212; teach it the P-256 precompile at 0x100
# (patch-alto-precompile.cjs). Patched here, at build, so the runtime stage stays RUN-free.
COPY services/bundler/patch-alto-precompile.cjs /tmp/patch-alto-precompile.cjs
RUN node /tmp/patch-alto-precompile.cjs /app/node_modules/@pimlico/alto
COPY services/bundler/entrypoint.mjs /app/entrypoint.mjs

FROM dhi.io/node:22-alpine3.23@sha256:920a7460ab7ac19ce6a9a38fb23b244bcfed1cf78705f7fe117195c58b307f4d
WORKDIR /app
COPY --from=build --chown=1000:1000 /app /app
EXPOSE 4337
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:4337',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_supportedEntryPoints',params:[]}),signal:AbortSignal.timeout(2500)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["node", "/app/entrypoint.mjs"]
