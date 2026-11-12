#!/usr/bin/env bash
# Installs the selected demo tenant's sponsorship rules through the real admin API.
#
# Run this AFTER the stack is up — it talks to the running wallet-api, not to the chain.
#
# This step is not optional and not cosmetic: a tenant with no sponsorship configuration gets no
# sponsorship. Registering and funding the tenant on the paymaster (provision-paymaster.sh) makes
# the money available; the rules here are what decides any of it may be spent. Skip this and the
# stack comes up looking healthy and refuses every sponsored transaction.
#
# Deliberately a wrapper rather than a copy: the work is done by the same script the e2e devnet
# uses, parameterised through SPONSOR_TENANTS / SPONSOR_ERC20 / SPONSOR_ALLOWLIST / SPONSOR_CHAIN_IDS.
#
# Usage: pnpm contracts:sponsorship --chain <profile> --env-file <file>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
: "${GIANO_PROFILE_LOADED:?use pnpm contracts:funding, contracts:provision or contracts:sponsorship with --chain <profile>}"
: "${CHAIN_ID:?select a chain profile}"
: "${RPC_URL:?provide a chain RPC}"

: "${SPONSORSHIP_PAYMASTER_ADDRESS:?not set — run pnpm contracts:deploy first}"

# Same defaults as docker-compose.chain.yml's TENANT_FIXTURES — they must name the same tenant.
: "${TENANT_SLUG:?provide the tenant slug in the selected operator environment}"
export TENANT_SLUG
: "${ADMIN_API_KEY:?provide the tenant admin API key in the selected operator environment}"

# Empty on a production chain (8453 / 84532 / 11155111): the deploy script never puts the demo
# ERC-20 there (R-29).
TEST_ERC20_ADDRESS="${TEST_ERC20_ADDRESS:-}"
# The tenant's own contracts to sponsor, comma-separated addresses, every function allowed. The
# wallet-api enables no sponsorship at all, wallet management included, for a tenant whose allowlist
# is empty (services/wallet-api/src/services/sponsorship-rules.ts), so a chain without the demo
# ERC-20 needs at least one entry here. Narrow it to specific functions in the console afterwards.
SPONSOR_ALLOWLIST="${SPONSOR_ALLOWLIST:-}"
for contract in ${SPONSOR_ALLOWLIST//,/ }; do
  if ! [[ "$contract" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    echo "SPONSOR_ALLOWLIST: '$contract' is not a contract address" >&2
    exit 1
  fi
done
if [ -z "$TEST_ERC20_ADDRESS" ] && [ -z "${SPONSOR_ALLOWLIST//[, ]/}" ]; then
  echo "No contract to sponsor on chain $CHAIN_ID: there is no demo ERC-20 here, so set SPONSOR_ALLOWLIST" >&2
  echo "to the tenant's contract addresses. The wallet-api sponsors nothing, not even wallet management," >&2
  echo "for a tenant with an empty allowlist." >&2
  exit 1
fi
# The wallet-api is not published on a host port by docker-compose.chain.yml — the browser
# reaches it through wallet-web's nginx /api proxy, and so do we.
: "${WALLET_API_URL:?provide the wallet-api base URL in the selected operator environment}"

echo "==> Installing sponsorship rules"
echo "    wallet-api : $WALLET_API_URL"
echo "    tenant     : $TENANT_SLUG"
echo "    chain      : $CHAIN_ID"
if [ -n "$TEST_ERC20_ADDRESS" ]; then
  echo "    allowlisted: $TEST_ERC20_ADDRESS (the demo ERC-20, all functions)"
fi
for contract in ${SPONSOR_ALLOWLIST//,/ }; do
  echo "    allowlisted: $contract (SPONSOR_ALLOWLIST, all functions)"
done
echo

WALLET_API_URL="$WALLET_API_URL" \
SPONSOR_CHAIN_IDS="$CHAIN_ID" \
SPONSOR_ERC20="$TEST_ERC20_ADDRESS" \
SPONSOR_ALLOWLIST="$SPONSOR_ALLOWLIST" \
SPONSOR_TENANTS="$(node -e 'console.log(JSON.stringify([{slug:process.env.TENANT_SLUG,adminKey:process.env.ADMIN_API_KEY}]))')" \
  node "$REPO_ROOT/e2e/devnet/provision-sponsorship.mjs"
