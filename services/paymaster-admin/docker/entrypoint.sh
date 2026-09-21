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

# Where the browser may talk to. The console reads over JSON-RPC and writes through an injected
# wallet extension, so 'self' plus the RPC origins is the whole of it.
#
# Derived from the array rather than configured alongside it: every deployment's rpcUrl is dialled
# directly by the browser, and a chain added to the array without a matching connect-src entry has
# every call blocked by the CSP — with nothing in the UI to say why. Still overridable, for a
# deployment that fronts its nodes with something this cannot see.
GIANO_RPC_UPSTREAM="${GIANO_RPC_UPSTREAM:-${GIANO_RPC_URL:-http://127.0.0.1}}"
GIANO_CSP_CONNECT_SRC="${GIANO_CSP_CONNECT_SRC:-$(
  printf '%s' "$GIANO_DEPLOYMENTS" |
    jq -r '[ .[].rpcUrl // empty | capture("^(?<origin>[a-z]+://[^/]+)").origin ] | unique | join(" ")'
)}"
export GIANO_RPC_UPSTREAM GIANO_CSP_CONNECT_SRC

envsubst '${GIANO_DEPLOYMENTS}' < /etc/giano/config.json.template > /usr/share/nginx/html/config.json
envsubst '${GIANO_RPC_UPSTREAM} ${GIANO_CSP_CONNECT_SRC}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
