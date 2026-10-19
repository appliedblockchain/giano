#!/bin/sh
set -eu

# Runs in the DHI nginx runtime, which carries exactly sh, envsubst and jq (docs/abip-compliance.md,
# SPA tool allow-list). Shell built-ins and those three only — no sed, tr, grep or awk exists here,
# which is why every JSON-shaped value below goes through jq.

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

if [ -z "${GIANO_CHAINS:-}" ]; then
  : "${GIANO_CHAIN_ID:?set GIANO_CHAINS (a JSON array of chains) — or, deprecated, GIANO_CHAIN_ID}"
  : "${GIANO_RPC_URL:?set GIANO_RPC_URL (deprecated form; prefer GIANO_CHAINS)}"
  echo "DEPRECATED: GIANO_CHAIN_ID/GIANO_CHAIN_B_ID are converted to GIANO_CHAINS; they will be removed in the next release." >&2
  GIANO_CHAIN_B_ID="${GIANO_CHAIN_B_ID:-0}"
  if [ "$GIANO_CHAIN_B_ID" != "0" ] && [ -z "${GIANO_RPC_B_URL:-}" ]; then
    echo "FATAL: GIANO_CHAIN_B_ID=$GIANO_CHAIN_B_ID but GIANO_RPC_B_URL is unset." >&2
    exit 1
  fi
  # jq builds the list, so a name with a quote or backslash in it is encoded rather than spliced.
  # A chain id that is not a number is passed through as a string for src/config.ts to reject.
  GIANO_CHAINS=$(jq -cn \
    --arg a_id "$GIANO_CHAIN_ID" --arg a_name "${GIANO_CHAIN_NAME:-chain ${GIANO_CHAIN_ID}}" --arg a_rpc "$GIANO_RPC_URL" \
    --arg b_id "$GIANO_CHAIN_B_ID" --arg b_name "${GIANO_CHAIN_B_NAME:-chain ${GIANO_CHAIN_B_ID}}" --arg b_rpc "${GIANO_RPC_B_URL:-}" \
    --arg token "${GIANO_TEST_ERC20:-}" '
      def chain($id; $name; $rpc):
        { chainId: ($id | tonumber? // $id), name: $name, rpcUrl: $rpc }
        + (if $token != "" then { defaultToken: $token } else {} end);
      [ chain($a_id; $a_name; $a_rpc) ]
      + (if $b_id != "0" then [ chain($b_id; $b_name; $b_rpc) ] else [] end)')
  # The old single proxy upstream maps onto the first chain's /rpc/<id>.
  if [ -n "${GIANO_RPC_UPSTREAM:-}" ]; then export "GIANO_RPC_UPSTREAM_${GIANO_CHAIN_ID}=${GIANO_RPC_UPSTREAM}"; fi
fi

# Shape check at the edge: a JSON array. The browser validates every field (src/config.ts) and
# renders a configuration-error screen naming what is wrong — but only if config.js parses, so a
# value that is not JSON at all stops the container here rather than blanking the page.
if ! printf '%s' "$GIANO_CHAINS" | jq -e 'type == "array"' > /dev/null 2>&1; then
  echo "FATAL: GIANO_CHAINS must be a JSON array, got: ${GIANO_CHAINS}" >&2
  exit 1
fi
# One line: keeps the rendered file readable and the log line greppable.
GIANO_CHAINS=$(printf '%s' "$GIANO_CHAINS" | jq -c .)
export GIANO_CHAINS

# --- optional -----------------------------------------------------------------------------
GIANO_OTHER_WALLET_URL="${GIANO_OTHER_WALLET_URL:-}"
GIANO_APP_LABEL="${GIANO_APP_LABEL:-}"
export GIANO_WALLET_URL GIANO_OTHER_WALLET_URL

# Where the browser may connect: the wallet origin (the connector polls
# `${walletUrl}/api/v1/userops/<hash>/receipt` cross-origin — leaving it out makes a sponsored
# transaction hang at "waiting for receipt"), the other wallet origin when set, and every chain RPC
# origin. Same-origin `/rpc/<id>` paths are skipped: 'self' covers them.
#
# CSP source expressions match on scheme+host+port, so only the ORIGIN belongs in the header — and
# dropping the path matters: an RPC URL that embeds an API key would otherwise be echoed into a
# response header on every request.
if [ -z "${GIANO_CSP_CONNECT_SRC:-}" ]; then
  GIANO_CSP_CONNECT_SRC=$(jq -rn '
    def origin: (capture("^(?<o>[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+)").o) // .;
    [ (env.GIANO_WALLET_URL | origin),
      (env.GIANO_OTHER_WALLET_URL | select(. != "") | origin),
      (env.GIANO_CHAINS | fromjson | .[] | .rpcUrl? | strings | select(test("^https?://")) | origin) ]
    | join(" ")')
fi
export GIANO_CSP_CONNECT_SRC

# Same-origin RPC proxies: one `location = /rpc/<id>` per chain that has GIANO_RPC_UPSTREAM_<id>.
# That is the posture for a keyed provider URL — the key stays server-side (R17) — and the chain's
# rpcUrl in GIANO_CHAINS is then `/rpc/<id>`. jq reads the per-chain variable from the environment
# by name, which is what `eval` did before.
GIANO_RPC_LOCATIONS=$(jq -rn '
  env.GIANO_CHAINS | fromjson | .[] | .chainId? | numbers | tostring as $id
  | env["GIANO_RPC_UPSTREAM_" + $id] // empty | select(. != "")
  | "\n    location = /rpc/\($id) {\n        proxy_pass \(.);\n        proxy_set_header Host $proxy_host;\n        proxy_ssl_server_name on;\n    }"')
export GIANO_RPC_LOCATIONS

# The free-text values become JSON string literals in config.js.template — valid JavaScript, and
# an apostrophe, quote, backslash or `$` in one of them round-trips unchanged.
GIANO_WALLET_URL_JS=$(jq -rn 'env.GIANO_WALLET_URL | @json')
GIANO_OTHER_WALLET_URL_JS=$(jq -rn 'env.GIANO_OTHER_WALLET_URL | @json')
GIANO_APP_LABEL_JS=$(GIANO_APP_LABEL="$GIANO_APP_LABEL" jq -rn 'env.GIANO_APP_LABEL | @json')
export GIANO_WALLET_URL_JS GIANO_OTHER_WALLET_URL_JS GIANO_APP_LABEL_JS

# Explicit allowlists on both, so a `$var`-looking string in a template or a brand name cannot be
# substituted by accident.
envsubst '${GIANO_WALLET_URL_JS} ${GIANO_OTHER_WALLET_URL_JS} ${GIANO_APP_LABEL_JS} ${GIANO_CHAINS}' \
  < /etc/giano/config.js.template > /usr/share/nginx/html/config.js
envsubst '${GIANO_CSP_CONNECT_SRC} ${GIANO_RPC_LOCATIONS}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

echo "giano-example: wallet ${GIANO_WALLET_URL} · chains ${GIANO_CHAINS} · connect-src ${GIANO_CSP_CONNECT_SRC}"
exec nginx -g 'daemon off;'
