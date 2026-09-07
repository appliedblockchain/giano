#!/bin/sh
set -eu

# Runtime config injection (§16.1). One published image serves every deployment, so this
# entrypoint — not the build — decides which chain the demo talks to and which wallet origin
# it is pinned to. A naive Dockerfile that baked `import.meta.env.VITE_*` in at build time
# would produce one image per environment, which is what the rest of the stack deliberately
# avoids.
#
# The VITE_* variables still exist, as BUILD-time fallbacks for `pnpm dev` (see src/config.ts).
# They are not read here and setting them on the container does nothing.

# --- required -----------------------------------------------------------------------------
: "${GIANO_CHAIN_ID:?set GIANO_CHAIN_ID}"
: "${GIANO_RPC_URL:?set GIANO_RPC_URL}"
# The TENANT's wallet hostname, never Giano's own serving hostname. Pointing this at the
# shared `wallet.<apex>` binds this tenant's passkeys to infrastructure, irreversibly (R1) —
# it is the one-character mistake §18 step 10 exists to catch. Each dApp is pinned to exactly
# one wallet origin, which is what makes the popup's origin check mean anything.
: "${GIANO_WALLET_URL:?set GIANO_WALLET_URL — the TENANT wallet origin, e.g. https://wallet.example.dev.giano.appliedblockchain.dev}"

# --- optional -----------------------------------------------------------------------------
GIANO_CHAIN_NAME="${GIANO_CHAIN_NAME:-chain ${GIANO_CHAIN_ID}}"
# 0 = single-chain. The cross-chain panel falls away with it.
GIANO_CHAIN_B_ID="${GIANO_CHAIN_B_ID:-0}"
GIANO_CHAIN_B_NAME="${GIANO_CHAIN_B_NAME:-chain ${GIANO_CHAIN_B_ID}}"
GIANO_RPC_B_URL="${GIANO_RPC_B_URL:-}"
# Free-text tag beside the title. Earns its keep when two instances of this image run against
# different wallet origins and are otherwise visually identical — which is exactly the
# custom-example / custom-example-byoui pair.
GIANO_APP_LABEL="${GIANO_APP_LABEL:-}"
# Prefill for the ERC-20 panel. Unset on a real chain: the devnet address means nothing there.
GIANO_TEST_ERC20="${GIANO_TEST_ERC20:-}"

# A second chain with no endpoint to reach it is a misconfiguration, not a default worth
# guessing. Failing here is loud; a fictional chain B in the picker is not.
if [ "$GIANO_CHAIN_B_ID" != "0" ] && [ -z "$GIANO_RPC_B_URL" ]; then
  echo "FATAL: GIANO_CHAIN_B_ID=$GIANO_CHAIN_B_ID but GIANO_RPC_B_URL is unset." >&2
  echo "       Set GIANO_RPC_B_URL, or set GIANO_CHAIN_B_ID=0 for a single-chain deployment." >&2
  exit 1
fi

# CSP source expressions match on scheme+host+port, so only the ORIGIN belongs in the header.
# It also matters that the path is dropped: an RPC URL that embeds an API key would otherwise
# be echoed into a response header on every single request, which spreads the key well beyond
# the /config.js that already carries it.
origin_of() {
  printf '%s' "$1" | sed -E 's#^([a-zA-Z][a-zA-Z0-9+.-]*://[^/]+).*#\1#'
}

# Where the browser may connect. Defaults to every endpoint this dApp actually dials: the
# chain RPC(s), and the WALLET origin — which the thin connector polls for user-operation
# receipts, cross-origin. Leaving the wallet origin out of connect-src makes a sponsored
# transaction hang at "waiting for receipt" with a CSP violation as the only clue.
export GIANO_RPC_UPSTREAM="${GIANO_RPC_UPSTREAM:-${GIANO_RPC_URL}}"
export GIANO_CSP_CONNECT_SRC="${GIANO_CSP_CONNECT_SRC:-$(origin_of "$GIANO_RPC_URL") ${GIANO_RPC_B_URL:+$(origin_of "$GIANO_RPC_B_URL") }$(origin_of "$GIANO_WALLET_URL")}"

# The free-text values land inside SINGLE-QUOTED JavaScript string literals in
# config.js.template, so an apostrophe in one of them — `Acme's wallet`, a chain called
# `Bob's devnet` — would terminate the literal and leave the whole bundle unparseable. The
# symptom is a blank page with a syntax error in the console and nothing pointing at the
# environment, so escape rather than trust: backslashes first, then quotes.
js_string() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g"
}
GIANO_CHAIN_NAME=$(js_string "$GIANO_CHAIN_NAME")
GIANO_CHAIN_B_NAME=$(js_string "$GIANO_CHAIN_B_NAME")
GIANO_APP_LABEL=$(js_string "$GIANO_APP_LABEL")

export GIANO_CHAIN_ID GIANO_CHAIN_NAME GIANO_RPC_URL
export GIANO_CHAIN_B_ID GIANO_CHAIN_B_NAME GIANO_RPC_B_URL
export GIANO_WALLET_URL GIANO_APP_LABEL GIANO_TEST_ERC20

# Explicit allowlists on both, so a `$var`-looking string in a template or in a brand name
# cannot be substituted by accident.
envsubst '${GIANO_CHAIN_ID} ${GIANO_CHAIN_NAME} ${GIANO_RPC_URL} ${GIANO_CHAIN_B_ID} ${GIANO_CHAIN_B_NAME} ${GIANO_RPC_B_URL} ${GIANO_WALLET_URL} ${GIANO_APP_LABEL} ${GIANO_TEST_ERC20}' \
  < /etc/giano/config.js.template > /usr/share/nginx/html/config.js
envsubst '${GIANO_RPC_UPSTREAM} ${GIANO_CSP_CONNECT_SRC}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
