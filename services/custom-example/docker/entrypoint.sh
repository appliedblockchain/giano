#!/bin/sh
set -eu

# Runtime config injection (R16, demo-deployment spec). One published image serves every deployment,
# so this entrypoint — not the build — decides which chains the demo talks to and which wallet origin
# it is pinned to. The pattern is the one Baanx uses for its static frontends: placeholders substituted
# from the environment at container start, then exec nginx. Nothing `VITE_*` exists in this image.
#
# Contract (see .env.development for the same names under `pnpm dev`):
#   GIANO_WALLET_URL          required  the TENANT wallet origin
#   GIANO_CHAINS              primary   JSON array of { chainId, name, rpcUrl, explorerUrl?, defaultToken? }
#   GIANO_OTHER_WALLET_URL    optional  a wallet origin that does not allow-list this dApp (failure lab)
#   GIANO_APP_LABEL           optional  free-text tag beside the title
#   GIANO_RPC_UPSTREAM_<id>   optional  keyed RPC for chain <id>, proxied same-origin at /rpc/<id>
#   GIANO_CSP_CONNECT_SRC     optional  override for the CSP connect-src list
#
# Deprecated for one release, converted to GIANO_CHAINS with a log line, refused alongside it:
#   GIANO_CHAIN_ID GIANO_CHAIN_NAME GIANO_RPC_URL GIANO_CHAIN_B_ID GIANO_CHAIN_B_NAME GIANO_RPC_B_URL
#   GIANO_TEST_ERC20 GIANO_RPC_UPSTREAM

# --- required -----------------------------------------------------------------------------
# The TENANT's wallet hostname, never Giano's own serving hostname. Pointing this at the shared
# `wallet.<apex>` binds this tenant's passkeys to infrastructure, irreversibly (R1) — it is the
# one-character mistake §18 step 10 exists to catch.
: "${GIANO_WALLET_URL:?set GIANO_WALLET_URL — the TENANT wallet origin, e.g. https://wallet.example.dev.giano.appliedblockchain.dev}"

# --- chains: GIANO_CHAINS, or the deprecated scalar pair ----------------------------------
if [ -n "${GIANO_CHAINS:-}" ] && [ -n "${GIANO_CHAIN_ID:-}" ]; then
  echo "FATAL: GIANO_CHAINS and GIANO_CHAIN_ID are both set — supply one, not both." >&2
  exit 1
fi

# JSON string literal for a value that lands inside the chains array.
json_string() {
  printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"
}

if [ -z "${GIANO_CHAINS:-}" ]; then
  : "${GIANO_CHAIN_ID:?set GIANO_CHAINS (a JSON array of chains) — or, deprecated, GIANO_CHAIN_ID}"
  : "${GIANO_RPC_URL:?set GIANO_RPC_URL (deprecated form; prefer GIANO_CHAINS)}"
  echo "DEPRECATED: GIANO_CHAIN_ID/GIANO_CHAIN_B_ID are converted to GIANO_CHAINS; they will be removed in the next release." >&2
  GIANO_CHAIN_NAME="${GIANO_CHAIN_NAME:-chain ${GIANO_CHAIN_ID}}"
  GIANO_CHAIN_B_ID="${GIANO_CHAIN_B_ID:-0}"
  token_field=""
  if [ -n "${GIANO_TEST_ERC20:-}" ]; then token_field=", \"defaultToken\": $(json_string "$GIANO_TEST_ERC20")"; fi
  GIANO_CHAINS="[{ \"chainId\": ${GIANO_CHAIN_ID}, \"name\": $(json_string "$GIANO_CHAIN_NAME"), \"rpcUrl\": $(json_string "$GIANO_RPC_URL")${token_field} }"
  if [ "$GIANO_CHAIN_B_ID" != "0" ]; then
    if [ -z "${GIANO_RPC_B_URL:-}" ]; then
      echo "FATAL: GIANO_CHAIN_B_ID=$GIANO_CHAIN_B_ID but GIANO_RPC_B_URL is unset." >&2
      exit 1
    fi
    GIANO_CHAIN_B_NAME="${GIANO_CHAIN_B_NAME:-chain ${GIANO_CHAIN_B_ID}}"
    GIANO_CHAINS="${GIANO_CHAINS}, { \"chainId\": ${GIANO_CHAIN_B_ID}, \"name\": $(json_string "$GIANO_CHAIN_B_NAME"), \"rpcUrl\": $(json_string "$GIANO_RPC_B_URL")${token_field} }"
  fi
  GIANO_CHAINS="[${GIANO_CHAINS#[}]"
  # The old single proxy upstream maps onto the first chain's /rpc/<id>.
  if [ -n "${GIANO_RPC_UPSTREAM:-}" ]; then export "GIANO_RPC_UPSTREAM_${GIANO_CHAIN_ID}=${GIANO_RPC_UPSTREAM}"; fi
fi

# Shape check at the edge: a JSON array. The nginx image has no JSON parser; the browser validates
# every field (src/config.ts) and renders a configuration-error screen naming what is wrong.
case "$(printf '%s' "$GIANO_CHAINS" | tr -d '[:space:]')" in
  \[*\]) ;;
  *) echo "FATAL: GIANO_CHAINS must be a JSON array, got: ${GIANO_CHAINS}" >&2; exit 1 ;;
esac
# The template drops the value inside a JS object literal; a newline-free single line keeps the
# rendered file readable and the log line greppable.
GIANO_CHAINS="$(printf '%s' "$GIANO_CHAINS" | tr -d '\n')"

# --- optional -----------------------------------------------------------------------------
GIANO_OTHER_WALLET_URL="${GIANO_OTHER_WALLET_URL:-}"
GIANO_APP_LABEL="${GIANO_APP_LABEL:-}"

# CSP source expressions match on scheme+host+port, so only the ORIGIN belongs in the header — and
# dropping the path matters: an RPC URL that embeds an API key would otherwise be echoed into a
# response header on every request.
origin_of() {
  printf '%s' "$1" | sed -E 's#^([a-zA-Z][a-zA-Z0-9+.-]*://[^/]+).*#\1#'
}

# Every rpcUrl in GIANO_CHAINS, one per line. Same-origin `/rpc/<id>` paths are skipped: 'self' covers them.
rpc_urls() {
  printf '%s' "$GIANO_CHAINS" | tr ',' '\n' | sed -n -E 's/.*"rpcUrl"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | grep -E '^https?://' || true
}
# Every chainId, one per line — for the /rpc/<id> proxy blocks.
chain_ids() {
  printf '%s' "$GIANO_CHAINS" | tr ',' '\n' | sed -n -E 's/.*"chainId"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p'
}

# Where the browser may connect: every chain RPC origin, the wallet origin (the connector polls
# `${walletUrl}/api/v1/userops/<hash>/receipt` cross-origin — leaving it out makes a sponsored
# transaction hang at "waiting for receipt"), and the other wallet origin when set.
if [ -z "${GIANO_CSP_CONNECT_SRC:-}" ]; then
  GIANO_CSP_CONNECT_SRC="$(origin_of "$GIANO_WALLET_URL")"
  if [ -n "$GIANO_OTHER_WALLET_URL" ]; then GIANO_CSP_CONNECT_SRC="$GIANO_CSP_CONNECT_SRC $(origin_of "$GIANO_OTHER_WALLET_URL")"; fi
  for url in $(rpc_urls); do GIANO_CSP_CONNECT_SRC="$GIANO_CSP_CONNECT_SRC $(origin_of "$url")"; done
fi
export GIANO_CSP_CONNECT_SRC

# Same-origin RPC proxies: one `location = /rpc/<id>` per chain that has GIANO_RPC_UPSTREAM_<id>.
# That is the posture for a keyed provider URL — the key stays server-side (R17) — and the chain's
# rpcUrl in GIANO_CHAINS is then `/rpc/<id>`.
GIANO_RPC_LOCATIONS=""
for id in $(chain_ids); do
  upstream="$(eval "printf '%s' \"\${GIANO_RPC_UPSTREAM_${id}:-}\"")"
  if [ -n "$upstream" ]; then
    GIANO_RPC_LOCATIONS="${GIANO_RPC_LOCATIONS}
    location = /rpc/${id} {
        proxy_pass ${upstream};
        proxy_set_header Host \$proxy_host;
        proxy_ssl_server_name on;
    }"
  fi
done
export GIANO_RPC_LOCATIONS

# The free-text values land inside SINGLE-QUOTED JavaScript string literals in config.js.template,
# so an apostrophe in one of them would terminate the literal and leave the whole page blank. Escape
# rather than trust: backslashes first, then quotes.
js_string() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g"
}
GIANO_WALLET_URL_JS=$(js_string "$GIANO_WALLET_URL")
GIANO_OTHER_WALLET_URL_JS=$(js_string "$GIANO_OTHER_WALLET_URL")
GIANO_APP_LABEL_JS=$(js_string "$GIANO_APP_LABEL")

export GIANO_WALLET_URL="$GIANO_WALLET_URL_JS" GIANO_OTHER_WALLET_URL="$GIANO_OTHER_WALLET_URL_JS" GIANO_APP_LABEL="$GIANO_APP_LABEL_JS" GIANO_CHAINS

# Explicit allowlists on both, so a `$var`-looking string in a template or a brand name cannot be
# substituted by accident.
envsubst '${GIANO_WALLET_URL} ${GIANO_OTHER_WALLET_URL} ${GIANO_APP_LABEL} ${GIANO_CHAINS}' \
  < /etc/giano/config.js.template > /usr/share/nginx/html/config.js
envsubst '${GIANO_CSP_CONNECT_SRC} ${GIANO_RPC_LOCATIONS}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

echo "giano-example: wallet ${GIANO_WALLET_URL} · chains ${GIANO_CHAINS} · connect-src ${GIANO_CSP_CONNECT_SRC}"
exec nginx -g 'daemon off;'
