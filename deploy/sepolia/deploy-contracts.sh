#!/usr/bin/env bash
# One-time deployment of the Giano contracts to Sepolia (or any EVM chain) for the demo stack.
#
# Deploys, through the contracts package's deploy CLI (CREATE3 via CreateX, from the latest release):
#   core    : GianoSmartWallet (impl) + GianoSmartWalletFactory + the sponsorship paymaster
#             (impl + proxy, initialised with the operator account as ROLE_ADMIN)
#   testing : PrivateERC20 + PermissivePaymaster (demo fixtures; never on a production chain)
#
# Every address is canonical by construction — a pure function of the canonical deployer and a
# label — and the CLI checks the code it finds or deploys. The script then writes the addresses
# into deploy/.env and records the deployment in packages/contracts/deployments/<chainId>.json.
#
# Two keys, kept apart on purpose:
#   CANONICAL_DEPLOYER_PRIVATE_KEY  the canonical deployer (packages/contracts/deploy/config.ts).
#                                   Owns every canonical address on every chain; used for nothing
#                                   but deploying.
#   DEPLOYER_PRIVATE_KEY            the demo's operator account: the paymaster's ROLE_ADMIN, and the
#                                   account provision-paymaster.sh provisions with.
#
# Usage:  ./deploy/sepolia/deploy-contracts.sh        Re-running is safe: deployed contracts are
#                                                     checked and recorded, never redeployed.
#
# Provisioning the paymaster (stake, signer, tenant, funding) is a SEPARATE step:
# ./deploy/sepolia/provision-paymaster.sh next.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$REPO_ROOT/deploy/.env"
CONTRACTS="$REPO_ROOT/packages/contracts"

[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found. Run: cp deploy/sepolia.env.example deploy/.env"; exit 1; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

: "${CANONICAL_DEPLOYER_PRIVATE_KEY:?set CANONICAL_DEPLOYER_PRIVATE_KEY in deploy/.env (the canonical deployer)}"
: "${DEPLOYER_PRIVATE_KEY:?set DEPLOYER_PRIVATE_KEY in deploy/.env (the operator account)}"

# Prefer a reliable (usually keyed) endpoint for deployment. Order: DEPLOY_RPC_URL > BUNDLER_NODE_RPC_URL > RPC_URL.
DEPLOY_RPC_URL="${DEPLOY_RPC_URL:-${BUNDLER_NODE_RPC_URL:-${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}}}"
CHAIN_ID="${CHAIN_ID:-11155111}"

cli() { pnpm --silent --filter @appliedblockchain/giano-contracts deploy:cli "$@"; }

OPERATOR_ADDR="$(pnpm --silent --filter @appliedblockchain/giano-contracts exec node -e \
  "console.log(new (require('ethers').Wallet)(process.env.DEPLOYER_PRIVATE_KEY).address)")"

echo "==> Deploying the canonical Giano contracts"
echo "    chain id   : $CHAIN_ID"
echo "    rpc        : $DEPLOY_RPC_URL"
echo "    role admin : $OPERATOR_ADDR (the operator account)"
echo

DEPLOYER_PRIVATE_KEY="$CANONICAL_DEPLOYER_PRIVATE_KEY" cli core --rpc "$DEPLOY_RPC_URL" --role-admin "$OPERATOR_ADDR"

# The demo fixtures. NEVER on a production chain (8453, 84532, 11155111 — R-29 layer 2): the CLI
# refuses, and gen:addresses would refuse to register a chain carrying them. This is also why the
# Sepolia demo has no test ERC-20.
case " 8453 84532 11155111 " in
  *" $CHAIN_ID "*)
    echo
    echo "==> chain $CHAIN_ID is a production chain — NOT deploying PrivateERC20 / PermissivePaymaster (R-29)" ;;
  *)
    if [ "${SKIP_TESTING:-0}" = "1" ]; then
      echo "==> SKIP_TESTING=1 — not deploying PrivateERC20 / PermissivePaymaster"
    else
      DEPLOYER_PRIVATE_KEY="$CANONICAL_DEPLOYER_PRIVATE_KEY" cli testing --rpc "$DEPLOY_RPC_URL" \
        --holder "$OPERATOR_ADDR" --owner "$OPERATOR_ADDR" --fund-eth "${PAYMASTER_FUND_ETH:-0.01}"
    fi ;;
esac

RECORD="$CONTRACTS/deployments/$CHAIN_ID.json"
[ -f "$RECORD" ] || { echo "ERROR: expected $RECORD after deploy"; exit 1; }

echo
echo "==> Writing addresses into $ENV_FILE"
node - "$RECORD" "$ENV_FILE" <<'NODE'
const fs = require('fs');
const [, , recordPath, envPath] = process.argv;
const { contracts: c } = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
const map = {
  FACTORY_ADDRESS: c.factory?.address,
  // The two paymasters are separate variables for the same reason addresses.ts keeps them in
  // separate fields: nothing should be able to pass the permissive test paymaster where the
  // production one is meant. The demo stack sponsors through SPONSORSHIP_PAYMASTER_ADDRESS.
  SPONSORSHIP_PAYMASTER_ADDRESS: c.paymasterProxy?.address,
  TEST_PAYMASTER_ADDRESS: c.testPaymaster?.address,
  TEST_ERC20_ADDRESS: c.testErc20?.address,
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
echo "    1. Provision the paymaster (stake, signer, tenant, funding):"
echo "         ./deploy/sepolia/provision-paymaster.sh"
echo "    2. Register chain $CHAIN_ID in the contracts address registry:"
echo "         pnpm --filter @appliedblockchain/giano-contracts gen:addresses"
echo "       and commit packages/contracts/deployments/$CHAIN_ID.json + addresses.ts"
echo "    3. Fund the Alto executor EOA (see: ./deploy/sepolia/print-funding.sh)"
echo "    4. docker compose --env-file deploy/.env -f deploy/docker-compose.sepolia.yml up --build"
