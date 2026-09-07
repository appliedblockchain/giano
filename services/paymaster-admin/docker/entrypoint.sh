#!/bin/sh
set -eu

# Runtime config injection: one published image serves every deployment, so nothing about which
# chains or which paymasters this console administers is baked in at build time.
#
# Two ways to say it. `GIANO_DEPLOYMENTS` is a JSON array and is the general form — several
# environments in one console, which is what the deployment picker switches between. The
# `GIANO_CHAIN_ID` / `GIANO_RPC_URL` / … variables are the single-deployment shorthand, kept
# because most deployments administer one chain and because it is what a simple compose block or
# Helm values file naturally produces.

if [ -z "${GIANO_DEPLOYMENTS:-}" ]; then
  : "${GIANO_CHAIN_ID:?set GIANO_DEPLOYMENTS (a JSON array) or GIANO_CHAIN_ID + GIANO_RPC_URL}"
  : "${GIANO_RPC_URL:?set GIANO_DEPLOYMENTS (a JSON array) or GIANO_CHAIN_ID + GIANO_RPC_URL}"

  # Optional. An empty address asks the SDK to resolve it from the contracts registry — which no
  # chain currently populates, so in practice this should be set.
  GIANO_PAYMASTER_ADDRESS="${GIANO_PAYMASTER_ADDRESS:-}"
  GIANO_ENVIRONMENT_LABEL="${GIANO_ENVIRONMENT_LABEL:-chain ${GIANO_CHAIN_ID}}"
  GIANO_REFRESH_SECONDS="${GIANO_REFRESH_SECONDS:-15}"

  GIANO_DEPLOYMENTS=$(printf '[{"label":"%s","chainId":%s,"rpcUrl":"%s","paymasterAddress":"%s","refreshSeconds":%s}]' \
    "$GIANO_ENVIRONMENT_LABEL" "$GIANO_CHAIN_ID" "$GIANO_RPC_URL" "$GIANO_PAYMASTER_ADDRESS" "$GIANO_REFRESH_SECONDS")
fi
export GIANO_DEPLOYMENTS

# Where the browser may talk to. The console reads over JSON-RPC and writes through an injected
# wallet extension, so 'self' plus the RPC origins is the whole of it. With several deployments the
# operator must list them, since they cannot be derived from a single variable.
export GIANO_RPC_UPSTREAM="${GIANO_RPC_UPSTREAM:-${GIANO_RPC_URL:-http://127.0.0.1}}"
export GIANO_CSP_CONNECT_SRC="${GIANO_CSP_CONNECT_SRC:-${GIANO_RPC_URL:-}}"

envsubst '${GIANO_DEPLOYMENTS}' < /etc/giano/config.json.template > /usr/share/nginx/html/config.json
envsubst '${GIANO_RPC_UPSTREAM} ${GIANO_CSP_CONNECT_SRC}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
