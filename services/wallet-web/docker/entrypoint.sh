#!/bin/sh
set -eu

# runtime config injection: one published image serves every client deployment (MC-41).
#
# Two shapes, mutually exclusive (§3.4):
#   - GIANO_CHAINS: a JSON array of chain descriptors, passed through VERBATIM — a
#     per-field template cannot express a variable-length list (MC-94).
#   - GIANO_CHAIN_ID/GIANO_RPC_URL: the single-chain shorthand, the complete configuration
#     for the on-premises profile (MC-88).
#
# There is no bundler URL to supply in either shape. The SPA reaches the bundler through
# wallet-api's relay (`${GIANO_WALLET_API_URL}/v1/bundler/<chainId>`), same-origin via /api,
# behind the session and the policy check — so the bundler never needs a route from this
# origin. GIANO_BUNDLER_URL remains accepted as an explicit override for dialling a bundler
# directly, which is a development posture and nothing else.
: "${GIANO_WALLET_API_UPSTREAM:?GIANO_WALLET_API_UPSTREAM is required (e.g. http://wallet-api:8080)}"
export GIANO_WALLET_API_URL="${GIANO_WALLET_API_URL:-/api}"
# JSON array of dApp origins allowed to drive the wallet; [] = none (fail closed), ["*"] = any (dev only)
export GIANO_ALLOWED_DAPP_ORIGINS="${GIANO_ALLOWED_DAPP_ORIGINS:-[]}"
export GIANO_RP_ID="${GIANO_RP_ID:-}"
export GIANO_BRAND_NAME="${GIANO_BRAND_NAME:-Giano Wallet}"

if [ -n "${GIANO_CHAINS:-}" ]; then
  if [ -n "${GIANO_CHAIN_ID:-}" ] || [ -n "${GIANO_RPC_URL:-}" ] || [ -n "${GIANO_BUNDLER_URL:-}" ]; then
    echo "GIANO_CHAINS and GIANO_CHAIN_ID/GIANO_RPC_URL/GIANO_BUNDLER_URL are mutually exclusive — supply one, not both" >&2
    exit 1
  fi
  export GIANO_CHAINS
  # In multichain mode the chain endpoints live inside GIANO_CHAINS; same-origin proxy
  # upstreams and extra CSP entries are declared explicitly.
  export GIANO_RPC_UPSTREAM="${GIANO_RPC_UPSTREAM:-http://127.0.0.1:8080}"
  export GIANO_CSP_CONNECT_SRC="${GIANO_CSP_CONNECT_SRC:-}"
  envsubst '${GIANO_CHAINS} ${GIANO_WALLET_API_URL} ${GIANO_ALLOWED_DAPP_ORIGINS} ${GIANO_RP_ID} ${GIANO_BRAND_NAME}' \
    < /etc/giano/config.multichain.json.template > /usr/share/nginx/html/config.json
else
  : "${GIANO_CHAIN_ID:?GIANO_CHAIN_ID is required (or set GIANO_CHAINS)}"
  : "${GIANO_RPC_URL:?GIANO_RPC_URL is required}"
  # Empty means the wallet-api relay; the SPA fills the default in (see above).
  export GIANO_BUNDLER_URL="${GIANO_BUNDLER_URL:-}"
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
  # optional same-origin proxy for the node (defaults to the direct URL, which disables the
  # proxy location by pointing it at itself)
  export GIANO_RPC_UPSTREAM="${GIANO_RPC_UPSTREAM:-${GIANO_RPC_URL}}"
  # extra connect-src entries (the RPC when not same-origin; a directly-dialled bundler if one
  # was set), space-separated
  export GIANO_CSP_CONNECT_SRC="${GIANO_CSP_CONNECT_SRC:-${GIANO_RPC_URL} ${GIANO_BUNDLER_URL}}"

  envsubst < /etc/giano/config.json.template > /usr/share/nginx/html/config.json
fi

# secondary same-origin RPC proxy (/rpc-b) for a second local chain; defaults to the primary
# upstream so the location is harmless when unused
export GIANO_RPC_B_UPSTREAM="${GIANO_RPC_B_UPSTREAM:-${GIANO_RPC_UPSTREAM}}"

envsubst '${GIANO_WALLET_API_UPSTREAM} ${GIANO_RPC_UPSTREAM} ${GIANO_RPC_B_UPSTREAM} ${GIANO_CSP_CONNECT_SRC}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
