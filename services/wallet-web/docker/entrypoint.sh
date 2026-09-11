#!/bin/sh
set -eu

# Runtime config injection: one published image serves every deployment (MC-41).
#
# Two shapes, mutually exclusive (§3.4):
#   GIANO_CHAINS     JSON array of wallet chain descriptors, passed through verbatim (MC-94):
#                    [{ "chainId": 8453, "name": "Base", "factoryAddress": "0x…", "sponsorship": "service" }]
#   GIANO_CHAIN_ID   single-chain shorthand, e.g. 8453 (MC-88)
#
# No node or bundler URL is needed in either shape: the SPA reads through wallet-api's relays
# (/api/v1/rpc/<chainId>, /api/v1/bundler/<chainId>), so the chain endpoints stay in wallet-api.
# GIANO_RPC_URL / GIANO_BUNDLER_URL are accepted only as explicit overrides to dial a node or
# bundler directly (development), and then must be CORS-enabled and safe to publish.

# wallet-api base URL nginx proxies /api and /.well-known/webauthn to, e.g. http://wallet-api:8080
: "${GIANO_WALLET_API_UPSTREAM:?GIANO_WALLET_API_UPSTREAM is required (e.g. http://wallet-api:8080)}"
# base URL the SPA calls wallet-api on; /api = same-origin through nginx
export GIANO_WALLET_API_URL="${GIANO_WALLET_API_URL:-/api}"
# JSON array of dApp origins allowed to drive the wallet; [] = none (fail closed), ["*"] = any (dev only)
export GIANO_ALLOWED_DAPP_ORIGINS="${GIANO_ALLOWED_DAPP_ORIGINS:-[]}"
# WebAuthn RP ID = the wallet hostname; empty = taken from the hostname the browser used
export GIANO_RP_ID="${GIANO_RP_ID:-}"
export GIANO_BRAND_NAME="${GIANO_BRAND_NAME:-Giano Wallet}"
# extra CSP connect-src entries, space-separated; only needed when a node/bundler is dialled directly
export GIANO_CSP_CONNECT_SRC="${GIANO_CSP_CONNECT_SRC:-${GIANO_RPC_URL:-} ${GIANO_BUNDLER_URL:-}}"

if [ -n "${GIANO_CHAINS:-}" ]; then
  if [ -n "${GIANO_CHAIN_ID:-}" ] || [ -n "${GIANO_RPC_URL:-}" ] || [ -n "${GIANO_BUNDLER_URL:-}" ]; then
    echo "GIANO_CHAINS and GIANO_CHAIN_ID/GIANO_RPC_URL/GIANO_BUNDLER_URL are mutually exclusive — supply one, not both" >&2
    exit 1
  fi
  export GIANO_CHAINS
  envsubst '${GIANO_CHAINS} ${GIANO_WALLET_API_URL} ${GIANO_ALLOWED_DAPP_ORIGINS} ${GIANO_RP_ID} ${GIANO_BRAND_NAME}' \
    < /etc/giano/config.multichain.json.template > /usr/share/nginx/html/config.json
else
  : "${GIANO_CHAIN_ID:?GIANO_CHAIN_ID is required (or set GIANO_CHAINS)}"
  # empty = wallet-api's relays (see above)
  export GIANO_RPC_URL="${GIANO_RPC_URL:-}"
  export GIANO_BUNDLER_URL="${GIANO_BUNDLER_URL:-}"
  # empty = from the contracts registry for GIANO_CHAIN_ID
  export GIANO_FACTORY_ADDRESS="${GIANO_FACTORY_ADDRESS:-}"
  # service | test-paymaster | off. Defaults to test-paymaster when GIANO_PAYMASTER_ADDRESS (the
  # permissive dev paymaster) is set, otherwise to the ERC-7677 sponsorship service.
  if [ -n "${GIANO_PAYMASTER_ADDRESS:-}" ]; then
    export GIANO_SPONSORSHIP_MODE="${GIANO_SPONSORSHIP_MODE:-test-paymaster}"
  else
    export GIANO_SPONSORSHIP_MODE="${GIANO_SPONSORSHIP_MODE:-service}"
  fi
  export GIANO_PAYMASTER_ADDRESS="${GIANO_PAYMASTER_ADDRESS:-}"
  export GIANO_PAYMASTER_SERVICE_URL="${GIANO_PAYMASTER_SERVICE_URL:-${GIANO_WALLET_API_URL}/v1/paymaster}"

  envsubst < /etc/giano/config.json.template > /usr/share/nginx/html/config.json
fi

envsubst '${GIANO_WALLET_API_UPSTREAM} ${GIANO_CSP_CONNECT_SRC}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
