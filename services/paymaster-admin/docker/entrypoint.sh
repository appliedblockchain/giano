#!/bin/sh
set -eu

# Runtime config injection: one published image serves every deployment, so nothing about which
# chains or which paymasters this console administers is baked in at build time.
#
# Two ways to say it. `GIANO_DEPLOYMENTS` is a JSON array and is the general form — several
# environments in one console, which is what the deployment picker switches between. Its entries
# are chain descriptors, spelled as `packages/contracts/chains.ts` spells them, so a deployment
# that also runs wallet-api passes that service's own `GIANO_CHAINS` value straight through and
# the chain list is authored once. The `GIANO_CHAIN_ID` / `GIANO_RPC_URL` / … variables are the
# single-deployment shorthand, kept because most deployments administer one chain and because it is
# what a simple compose block or Helm values file naturally produces.

if [ -z "${GIANO_DEPLOYMENTS:-}" ]; then
  : "${GIANO_CHAIN_ID:?set GIANO_DEPLOYMENTS (a JSON array) or GIANO_CHAIN_ID + GIANO_RPC_URL}"
  : "${GIANO_RPC_URL:?set GIANO_DEPLOYMENTS (a JSON array) or GIANO_CHAIN_ID + GIANO_RPC_URL}"

  # Optional. An empty address asks the SDK to resolve it from the contracts registry — which no
  # chain currently populates, so in practice this should be set.
  GIANO_PAYMASTER_ADDRESS="${GIANO_PAYMASTER_ADDRESS:-}"
  GIANO_ENVIRONMENT_LABEL="${GIANO_ENVIRONMENT_LABEL:-chain ${GIANO_CHAIN_ID}}"
  GIANO_REFRESH_SECONDS="${GIANO_REFRESH_SECONDS:-15}"

  GIANO_DEPLOYMENTS=$(printf '[{"name":"%s","chainId":%s,"rpcUrl":"%s","sponsorshipPaymaster":"%s","refreshSeconds":%s}]' \
    "$GIANO_ENVIRONMENT_LABEL" "$GIANO_CHAIN_ID" "$GIANO_RPC_URL" "$GIANO_PAYMASTER_ADDRESS" "$GIANO_REFRESH_SECONDS")
fi

# Keep the four fields the console reads and drop the rest.
#
# A deployment serving both hands this variable the same array wallet-api reads as GIANO_CHAINS,
# which is what keeps the chain list authored once. The console spells its fields as that
# descriptor spells them, so nothing is renamed here — but a descriptor also carries bundlerUrl,
# entryPoint, factory and policy, and /config.json is served to the browser. Naming what is kept
# means a field added to a descriptor later is not published to every console user by default.
#
# Malformed JSON stops the container here, with jq naming the defect in the logs. That is the
# intended failure: the alternative is nginx serving a /config.json the SPA refuses to parse, which
# presents as a blank console with nothing to read.
GIANO_DEPLOYMENTS=$(printf '%s' "$GIANO_DEPLOYMENTS" | jq -c '
  [ .[]
    | { name, chainId, rpcUrl, sponsorshipPaymaster, refreshSeconds: (.refreshSeconds // 15) }
    | with_entries(select(.value != null)) ]')
export GIANO_DEPLOYMENTS

# Keep the provider keys server-side.
#
# A deployment descriptor's rpcUrl is browser-facing: it is written into /config.json and dialled
# by the SPA, so a keyed endpoint handed over as-is is readable by everyone who can open the
# console, and usable by them for as long as it takes to rotate the key. With GIANO_RPC_PROXY on,
# each chain is proxied through this origin instead — nginx holds the keyed URL, the browser sees
# only /rpc/<chainId>, and connect-src collapses to 'self'.
#
# One generated location per chain, each with a literal upstream, so nginx resolves every host at
# config load: a name that does not resolve stops the container here rather than failing the first
# call. Off by default, because a deployment already fronting its nodes — the compose stacks point
# rpcUrl at their own /rpc — would otherwise be proxied twice, through itself.
GIANO_RPC_PROXY="${GIANO_RPC_PROXY:-false}"
GIANO_RPC_LOCATIONS=""

if [ "$GIANO_RPC_PROXY" = "true" ]; then
  GIANO_RPC_LOCATIONS=$(printf '%s' "$GIANO_DEPLOYMENTS" | jq -r '
    .[]
    | select(.rpcUrl | test("^https?://"))
    | "    location = /rpc/\(.chainId) {\n" +
      "        proxy_pass \(.rpcUrl);\n" +
      "        proxy_http_version 1.1;\n" +
      "        proxy_ssl_server_name on;\n" +
      "        proxy_set_header Host $proxy_host;\n" +
      "    }\n"')

  GIANO_DEPLOYMENTS=$(printf '%s' "$GIANO_DEPLOYMENTS" | jq -c '
    [ .[] | if (.rpcUrl | test("^https?://")) then .rpcUrl = "/rpc/\(.chainId)" else . end ]')
  export GIANO_DEPLOYMENTS
fi

# The single legacy proxy, kept for the stacks that point rpcUrl at a bare /rpc — a node with no
# CORS headers (anvil), or a keyed URL an operator moved server-side by hand. Emitted only when it
# is set, so nothing dangles at 127.0.0.1 in a deployment that does not use it.
if [ -n "${GIANO_RPC_UPSTREAM:-}" ]; then
  GIANO_RPC_LOCATIONS="${GIANO_RPC_LOCATIONS}
    location = /rpc {
        proxy_pass ${GIANO_RPC_UPSTREAM}/;
        proxy_set_header Host \$host;
    }
"
fi

# Where the browser may talk to. The console reads over JSON-RPC and writes through an injected
# wallet extension, so 'self' plus whatever RPC origins remain is the whole of it.
#
# Derived from the array rather than configured alongside it: a chain added without a matching
# connect-src entry has every call blocked by the CSP, with nothing in the UI to say why. With the
# proxy on, every rpcUrl is relative and this resolves to nothing at all — which is the point.
GIANO_CSP_CONNECT_SRC="${GIANO_CSP_CONNECT_SRC:-$(
  printf '%s' "$GIANO_DEPLOYMENTS" |
    jq -r '[ .[].rpcUrl // empty | capture("^(?<origin>[a-z]+://[^/]+)").origin ] | unique | join(" ")'
)}"
export GIANO_RPC_LOCATIONS GIANO_CSP_CONNECT_SRC

envsubst '${GIANO_DEPLOYMENTS}' < /etc/giano/config.json.template > /usr/share/nginx/html/config.json
envsubst '${GIANO_RPC_LOCATIONS} ${GIANO_CSP_CONNECT_SRC}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
