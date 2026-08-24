#!/bin/sh
set -eu

# runtime config injection: one published image serves every client deployment
: "${GIANO_CHAIN_ID:?GIANO_CHAIN_ID is required}"
: "${GIANO_RPC_URL:?GIANO_RPC_URL is required}"
: "${GIANO_BUNDLER_URL:?GIANO_BUNDLER_URL is required}"
: "${GIANO_WALLET_API_UPSTREAM:?GIANO_WALLET_API_UPSTREAM is required (e.g. http://wallet-api:8080)}"
export GIANO_WALLET_API_URL="${GIANO_WALLET_API_URL:-/api}"
export GIANO_FACTORY_ADDRESS="${GIANO_FACTORY_ADDRESS:-}"
# How gas is sponsored: 'service' (the production paymaster, via the ERC-7677 sponsorship
# service), 'test-paymaster' (the permissive paymaster — development and tests only) or 'off'.
# Defaults to the dev path when a permissive paymaster address is supplied and to the service
# otherwise, so an existing devnet config keeps working unchanged.
if [ -n "${GIANO_PAYMASTER_ADDRESS:-}" ]; then
  export GIANO_SPONSORSHIP_MODE="${GIANO_SPONSORSHIP_MODE:-test-paymaster}"
else
  export GIANO_SPONSORSHIP_MODE="${GIANO_SPONSORSHIP_MODE:-service}"
fi
export GIANO_PAYMASTER_ADDRESS="${GIANO_PAYMASTER_ADDRESS:-}"
export GIANO_PAYMASTER_SERVICE_URL="${GIANO_PAYMASTER_SERVICE_URL:-${GIANO_WALLET_API_URL}/v1/paymaster}"
# JSON array of dApp origins allowed to drive the wallet; [] = none (fail closed), ["*"] = any (dev only)
export GIANO_ALLOWED_DAPP_ORIGINS="${GIANO_ALLOWED_DAPP_ORIGINS:-[]}"
export GIANO_RP_ID="${GIANO_RP_ID:-}"
export GIANO_BRAND_NAME="${GIANO_BRAND_NAME:-Giano Wallet}"
# optional same-origin proxies for the node/bundler (default to the direct URLs, which
# disables the proxy locations by pointing them at themselves)
export GIANO_RPC_UPSTREAM="${GIANO_RPC_UPSTREAM:-${GIANO_RPC_URL}}"
export GIANO_BUNDLER_UPSTREAM="${GIANO_BUNDLER_UPSTREAM:-${GIANO_BUNDLER_URL}}"
# extra connect-src entries (rpc/bundler when not same-origin), space-separated
export GIANO_CSP_CONNECT_SRC="${GIANO_CSP_CONNECT_SRC:-${GIANO_RPC_URL} ${GIANO_BUNDLER_URL}}"

envsubst < /etc/giano/config.json.template > /usr/share/nginx/html/config.json
envsubst '${GIANO_WALLET_API_UPSTREAM} ${GIANO_RPC_UPSTREAM} ${GIANO_BUNDLER_UPSTREAM} ${GIANO_CSP_CONNECT_SRC}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
