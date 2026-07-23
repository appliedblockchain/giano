#!/usr/bin/env bash
# One-time deployment of the Giano contracts to Sepolia (or any EVM chain) for the demo stack.
#
# Deploys: GianoSmartWallet (impl) + GianoSmartWalletFactory + PermissivePaymaster + PrivateERC20,
# then seeds the paymaster's EntryPoint deposit (PAYMASTER_FUND_ETH). Extracts the deployed
# addresses and writes FACTORY_ADDRESS / PAYMASTER_ADDRESS / TEST_ERC20_ADDRESS into deploy/.env.
#
# Usage:  ./deploy/sepolia/deploy-contracts.sh
#   Re-running resumes the existing deployment (safe & idempotent).
#   If a previous run was interrupted and the Ignition journal is inconsistent (resume fails
#   immediately), start clean with:   RESET=1 ./deploy/sepolia/deploy-contracts.sh
#
# Requires deploy/.env with DEPLOYER_PRIVATE_KEY set and the deployer funded (see README.md).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$REPO_ROOT/deploy/.env"
CONTRACTS="$REPO_ROOT/packages/contracts"

[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found. Run: cp deploy/sepolia.env.example deploy/.env"; exit 1; }

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

: "${DEPLOYER_PRIVATE_KEY:?set DEPLOYER_PRIVATE_KEY in deploy/.env}"
# Prefer a reliable (usually keyed) endpoint for deployment — a flaky public RPC dropping a
# receipt mid-run is what corrupts the journal. Order: DEPLOY_RPC_URL > BUNDLER_NODE_RPC_URL > RPC_URL.
export DEPLOY_RPC_URL="${DEPLOY_RPC_URL:-${BUNDLER_NODE_RPC_URL:-${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}}}"
export PAYMASTER_FUND_ETH="${PAYMASTER_FUND_ETH:-0.05}"
CHAIN_ID="${CHAIN_ID:-11155111}"
export DEPLOY_CHAIN_ID="${DEPLOY_CHAIN_ID:-$CHAIN_ID}"

# Named 'sepolia' network for the canonical case; 'custom' (env-driven chainId) otherwise.
if [ "$CHAIN_ID" = "11155111" ]; then NETWORK=sepolia; else NETWORK=custom; fi

# derive the deployer address via the contracts workspace (where ethers resolves)
DEPLOYER_ADDR="$(pnpm --filter @appliedblockchain/giano-contracts exec node -e \
  "console.log(new (require('ethers').Wallet)(process.env.DEPLOYER_PRIVATE_KEY).address)" 2>/dev/null || echo '<derive failed>')"

echo "==> Deploying Giano contracts"
echo "    chain id : $CHAIN_ID   (hardhat network: $NETWORK)"
echo "    rpc      : $DEPLOY_RPC_URL"
echo "    deployer : $DEPLOYER_ADDR"
echo "    paymaster deposit: $PAYMASTER_FUND_ETH ETH"
[ "${RESET:-0}" = "1" ] && echo "    RESET=1  -> wiping existing deployment state first"
echo

# hardhat-ignition prompts to confirm deploying to a real network, and (with --reset) a second
# time to confirm the wipe. Feed enough 'y' answers for both; extra lines are ignored.
# $2 holds optional extra flags (e.g. --reset); left unquoted so an empty value passes zero args
# (avoids bash-3.2 empty-array pitfalls under `set -u`).
run_deploy() {
  local module="$1" extra="${2:-}"
  # shellcheck disable=SC2086
  printf 'y\ny\n' | pnpm --filter @appliedblockchain/giano-contracts exec \
    hardhat ignition deploy "$module" --network "$NETWORK" $extra
}

# basic strategy (plain CREATE) — portable across chains, no deterministic-deployer dependency.
# --reset (opt-in) applies ONLY to the first module; the two modules share the chain-<id>
# deployment dir, so resetting on the second would wipe the freshly-deployed factory.
RESET_FLAG=""
[ "${RESET:-0}" = "1" ] && RESET_FLAG="--reset"

if ! run_deploy ignition/modules/GianoAccountFactory.ts "$RESET_FLAG"; then
  echo >&2
  echo "ERROR: factory deployment failed." >&2
  echo "  If a prior run was interrupted and this fails immediately on resume, the Ignition" >&2
  echo "  journal is likely inconsistent — start clean with:  RESET=1 $0" >&2
  exit 1
fi

if ! run_deploy ignition/modules/Testing.ts; then
  echo >&2
  echo "ERROR: testing-contracts deployment failed." >&2
  echo "  Re-run the script to resume, or start clean with:  RESET=1 $0" >&2
  exit 1
fi

ADDR_JSON="$CONTRACTS/ignition/deployments/chain-$CHAIN_ID/deployed_addresses.json"
[ -f "$ADDR_JSON" ] || { echo "ERROR: expected $ADDR_JSON after deploy"; exit 1; }

echo
echo "==> Writing addresses into $ENV_FILE"
node - "$ADDR_JSON" "$ENV_FILE" <<'NODE'
const fs = require('fs');
const [, , addrPath, envPath] = process.argv;
const a = JSON.parse(fs.readFileSync(addrPath, 'utf8'));
const map = {
  FACTORY_ADDRESS: a['GianoAccountFactory#GianoSmartWalletFactory'],
  PAYMASTER_ADDRESS: a['Testing#PermissivePaymaster'],
  TEST_ERC20_ADDRESS: a['Testing#PrivateERC20'],
};
let env = fs.readFileSync(envPath, 'utf8');
for (const [k, v] of Object.entries(map)) {
  if (!v) continue;
  const line = `${k}=${v}`;
  env = new RegExp(`^${k}=.*$`, 'm').test(env) ? env.replace(new RegExp(`^${k}=.*$`, 'm'), line) : `${env}\n${line}\n`;
  console.log(`    ${line}`);
}
fs.writeFileSync(envPath, env);
NODE

echo
echo "==> Done. Next:"
echo "    1. Fund the Alto executor EOA (see: ./deploy/sepolia/print-funding.sh)"
echo "    2. docker compose --env-file deploy/.env -f deploy/docker-compose.sepolia.yml up --build"
