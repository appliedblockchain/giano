#!/bin/sh
set -eu

# Runs in the DHI nginx runtime, which carries exactly sh, envsubst and jq (docs/abip-compliance.md,
# SPA tool allow-list). Shell built-ins and those three only.

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

  # Optional. The address a wallet should dial when it has to add this network itself, for the
  # common case where GIANO_RPC_URL is keyed or otherwise not for publication.
  GIANO_WALLET_RPC_URL="${GIANO_WALLET_RPC_URL:-}"

  GIANO_DEPLOYMENTS=$(printf '[{"name":"%s","chainId":%s,"rpcUrl":"%s","walletRpcUrl":"%s","sponsorshipPaymaster":"%s","refreshSeconds":%s}]' \
    "$GIANO_ENVIRONMENT_LABEL" "$GIANO_CHAIN_ID" "$GIANO_RPC_URL" "$GIANO_WALLET_RPC_URL" "$GIANO_PAYMASTER_ADDRESS" "$GIANO_REFRESH_SECONDS")
fi

# Keep the fields the console reads and drop the rest.
#
# A deployment serving both hands this variable the same backend chain document wallet-api and
# the bundler read as GIANO_CHAINS (packages/contracts/chains.ts), which is what keeps the chain
# list authored once. name, chainId, rpcUrl and sponsorshipPaymaster are its shared fields; the
# console's own settings are its `paymasterAdmin` section, and a standalone list may spell them flat
# instead. The document also carries entryPoint and the other services' sections, and /config.json
# is served to the browser: naming what is kept means a field added later is not published to every
# console user by default.
#
# Malformed JSON stops the container here, naming the variable and then letting jq name the defect.
# That is the intended failure: the alternative is nginx serving a /config.json the SPA refuses to
# parse, which presents as a blank console with nothing to read.
#
# `walletRpcUrl` is the one field here a chain descriptor does not carry — it is a property of how
# this console is published rather than of the chain — and, unlike rpcUrl, it is left exactly as
# written: it is meant to be dialled from outside this page, so proxying it would defeat it.
if ! printf '%s' "$GIANO_DEPLOYMENTS" | jq -e 'type == "array"' > /dev/null; then
  echo "FATAL: GIANO_DEPLOYMENTS must be a JSON array of deployment descriptors" >&2
  exit 1
fi
GIANO_DEPLOYMENTS=$(printf '%s' "$GIANO_DEPLOYMENTS" | jq -c '
  [ .[]
    | { name, chainId, rpcUrl, sponsorshipPaymaster,
        walletRpcUrl: (.paymasterAdmin.walletRpcUrl // .walletRpcUrl),
        refreshSeconds: (.paymasterAdmin.refreshSeconds // .refreshSeconds // 15) }
    # Only walletRpcUrl is dropped when empty. Every other field keeps an empty string on purpose:
    # the proxy step below asks whether rpcUrl looks absolute, and a missing key would make that
    # `null | test(...)`, which stops the container with a jq message instead of letting the SPA
    # report "deployment N has no rpcUrl".
    | if (.walletRpcUrl // "") == "" then del(.walletRpcUrl) else . end
    | with_entries(select(.value != null)) ]')
export GIANO_DEPLOYMENTS

# Keep the provider keys server-side.
#
# A deployment descriptor's rpcUrl is browser-facing: it is written into /config.json and dialled
# by the SPA, so a keyed endpoint handed over as-is is readable by everyone who can open the
# console, and usable by them until the key is rotated. So every absolute rpcUrl is proxied through
# this origin instead — nginx holds the keyed URL, the browser sees only /rpc/<chainId>, and
# connect-src collapses to 'self'. A relative rpcUrl is already same-origin and passes through.
#
# On by default. A console that leaks its provider credentials by default is the wrong shape for
# something an operator stands up quickly, and the cost of the proxy where it is not needed is one
# hop inside the same container. GIANO_RPC_PROXY=false opts out — for a node that must be dialled
# from the browser directly, or an upstream nginx cannot reach from where it runs.
#
# One generated location per chain, each with a literal upstream, so nginx resolves every host at
# config load: a name that does not resolve stops the container here rather than failing the first
# call an operator makes.
GIANO_RPC_PROXY="${GIANO_RPC_PROXY:-true}"
GIANO_RPC_LOCATIONS=""

if [ "$GIANO_RPC_PROXY" = "true" ]; then
  GIANO_RPC_LOCATIONS=$(printf '%s' "$GIANO_DEPLOYMENTS" | jq -r '
    .[]
    | select(.rpcUrl | test("^https?://"))
    | "    location = /rpc/\(.chainId) {\n" +
      # A proxy_pass with no URI part forwards the request URI unchanged, so the upstream would
      # be asked for /rpc/<chainId>; one with a URI replaces the matched location. Always give
      # it a URI, even when the endpoint is a bare host:port as a devnet node is.
      "        proxy_pass \(if (.rpcUrl | test("^https?://[^/]+$")) then .rpcUrl + "/" else .rpcUrl end);\n" +
      "        proxy_http_version 1.1;\n" +
      "        proxy_ssl_server_name on;\n" +
      "        proxy_set_header Host $proxy_host;\n" +
      "    }\n"')

  GIANO_DEPLOYMENTS=$(printf '%s' "$GIANO_DEPLOYMENTS" | jq -c '
    [ .[] | if (.rpcUrl | test("^https?://")) then .rpcUrl = "/rpc/\(.chainId)" else . end ]')
  export GIANO_DEPLOYMENTS
fi

# Where the browser may talk to. The console reads over JSON-RPC and writes through an injected
# wallet extension, so 'self' plus whatever RPC origins remain is the whole of it.
#
# Derived from the array rather than configured alongside it: a chain added without a matching
# connect-src entry has every call blocked by the CSP, with nothing in the UI to say why. With the
# proxy on there are no origins left to name, and this resolves to nothing at all.
#
# walletRpcUrl is deliberately not among them. The page never dials it — it is handed to a wallet
# extension, which makes that call from its own context, outside this document's CSP.
GIANO_CSP_CONNECT_SRC="${GIANO_CSP_CONNECT_SRC:-$(
  printf '%s' "$GIANO_DEPLOYMENTS" |
    jq -r '[ .[].rpcUrl // empty | capture("^(?<origin>[a-z]+://[^/]+)").origin ] | unique | join(" ")'
)}"
export GIANO_RPC_LOCATIONS GIANO_CSP_CONNECT_SRC

# The operator API (specs/OPERATOR-ADMIN-SPECS.md §11.1), only where it is asked for.
#
# With GIANO_WALLET_API_UPSTREAM set, /api/* is proxied to wallet-api on this origin, and the
# console shows its Operator area. Unset, nothing below is rendered and the console is exactly the
# read-mostly paymaster view it was — so every existing deployment keeps its nginx config byte for
# byte.
#
# The proxy drops the browser's Origin: wallet-api refuses any operator request that carries one,
# which is what keeps a page on another origin from calling those routes, and this same-origin hop
# is the one path a browser is meant to take.
#
# wallet-api is re-resolved per request, as wallet-web does it and for the same reason: under ECS
# its address changes on every rollout, and a literal proxy_pass host would be resolved once at
# config load and held. A variable in proxy_pass is what defers the lookup, and a variable needs a
# resolver — the container's own nameserver, read from /etc/resolv.conf. First IPv4 match only:
# the directive takes one address.
GIANO_API_LOCATION=""
GIANO_OPERATOR_API=false
if [ -n "${GIANO_WALLET_API_UPSTREAM:-}" ]; then
  GIANO_RESOLVER=""
  while read -r key value _ || [ -n "${key:-}" ]; do
    if [ "$key" = nameserver ]; then
      case "$value" in
        '' | *[!0-9.]*) ;;
        *) GIANO_RESOLVER=$value; break ;;
      esac
    fi
    key=""
  done < /etc/resolv.conf
  : "${GIANO_RESOLVER:?/etc/resolv.conf names no IPv4 nameserver}"

  # Regex, not prefix: a proxy_pass carrying a variable does no URI rewrite, so the /api/ prefix is
  # captured and the rest re-appended. /api/v1/x → <upstream>/v1/x.
  # Starts with a newline: the template places it straight after the RPC locations.
  GIANO_API_LOCATION=$(printf '%s\n' \
    '' \
    "    resolver ${GIANO_RESOLVER} valid=10s ipv6=off;" \
    '    resolver_timeout 5s;' \
    "    set \$giano_wallet_api ${GIANO_WALLET_API_UPSTREAM};" \
    '' \
    '    location ~ ^/api/(?<giano_api_path>.*)$ {' \
    '        proxy_pass $giano_wallet_api/$giano_api_path$is_args$args;' \
    '        proxy_http_version 1.1;' \
    '        proxy_set_header Host $proxy_host;' \
    '        proxy_set_header Origin "";' \
    '        add_header Cache-Control "no-store" always;' \
    '    }')
  GIANO_OPERATOR_API=true
fi
export GIANO_API_LOCATION GIANO_OPERATOR_API

envsubst '${GIANO_DEPLOYMENTS} ${GIANO_OPERATOR_API}' < /etc/giano/config.json.template > /usr/share/nginx/html/config.json
envsubst '${GIANO_RPC_LOCATIONS} ${GIANO_CSP_CONNECT_SRC} ${GIANO_API_LOCATION}' \
  < /etc/giano/nginx.conf.template > /etc/nginx/conf.d/default.conf

exec nginx -g 'daemon off;'
