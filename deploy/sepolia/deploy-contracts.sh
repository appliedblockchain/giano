#!/usr/bin/env bash
# Compatibility entry point. The guided testnet flow owns deployment and preflight checks.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$REPO_ROOT/deploy/.env"
[ -f "$ENV_FILE" ] || { echo 'Copy deploy/sepolia.env.example to deploy/.env and configure it, or run pnpm testnet:deploy directly.' >&2; exit 1; }
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a
case "${CHAIN_ID:-11155111}" in
  84532) NETWORK=base-sepolia ;;
  11155111) NETWORK=ethereum-sepolia ;;
  *) echo 'Supported targets: CHAIN_ID=84532 (Base Sepolia) or 11155111 (Ethereum Sepolia).' >&2; exit 1 ;;
esac
if [ -n "${DEPLOY_CHAIN_ID:-}" ] && [ "$DEPLOY_CHAIN_ID" != "${CHAIN_ID:-11155111}" ]; then
  echo 'CHAIN_ID and DEPLOY_CHAIN_ID differ; correct deploy/.env before continuing.' >&2
  exit 1
fi
# The operator key stays separate from the canonical deployer key. Prefer a public admin address.
if [ -z "${PAYMASTER_ROLE_ADMIN:-}" ] && [ -n "${DEPLOYER_PRIVATE_KEY:-}" ]; then
  export PAYMASTER_ROLE_ADMIN
  PAYMASTER_ROLE_ADMIN="$(cd "$REPO_ROOT/packages/contracts" && node -e 'try { console.log(new (require("ethers").Wallet)(process.env.DEPLOYER_PRIVATE_KEY).address) } catch { console.error("Cannot derive operator address. Check dependencies and DEPLOYER_PRIVATE_KEY, or provide PAYMASTER_ROLE_ADMIN directly."); process.exit(1) }')"
fi
export DEPLOY_RPC_URL="${DEPLOY_RPC_URL:-${BUNDLER_NODE_RPC_URL:-${RPC_URL:-}}}"
# Unset an empty override so the wizard chooses the selected network's default.
if [ -z "$DEPLOY_RPC_URL" ]; then unset DEPLOY_RPC_URL; fi
exec bash "$REPO_ROOT/deploy/testnet/deploy.sh" --network "$NETWORK" "$@"
