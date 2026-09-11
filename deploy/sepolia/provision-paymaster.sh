#!/usr/bin/env bash
# Provisions the sponsorship paymaster deployed by ./deploy/sepolia/deploy-contracts.sh:
# grants roles, registers the sponsorship signing key, stakes with the EntryPoint, registers the
# demo tenant and funds its balance. Then verifies its own work with `giano-doctor chain`.
#
# Separate from deploy-contracts.sh on purpose, and the split is the same one the Ignition module
# argues for: the deployed addresses must be identical for every operator, while everything here
# is operator-specific. specs/CHAIN-ADOPTION.md step 7.
#
# ⚠ Costs real testnet ETH: the stake, the tenant's funded balance, and gas for ~10 transactions.
#
# Usage:  ./deploy/sepolia/provision-paymaster.sh
#   Idempotent — re-running re-applies the same roles, tops the stake back up to STAKE_ETH and
#   adds TENANT_FUND_ETH to the tenant's balance again.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$REPO_ROOT/deploy/.env"

[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found. Run: cp deploy/sepolia.env.example deploy/.env"; exit 1; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

: "${DEPLOYER_PRIVATE_KEY:?set DEPLOYER_PRIVATE_KEY in deploy/.env}"
: "${SPONSORSHIP_PAYMASTER_ADDRESS:?not set — run ./deploy/sepolia/deploy-contracts.sh first}"
: "${SPONSORSHIP_SIGNER_KEY:?set SPONSORSHIP_SIGNER_KEY in deploy/.env (the key wallet-api signs sponsorships with)}"

export RPC_URL="${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}"
CHAIN_ID="${CHAIN_ID:-11155111}"

TENANT_ID="${TENANT_ID:-33333333-3333-4333-8333-333333333333}"
TENANT_SLUG="${TENANT_SLUG:-sepolia}"
# How much of the tenant's sponsorship balance to fund, and the paymaster's EntryPoint stake.
# Both are deliberately small: Sepolia faucets are rate-limited, and the e2e devnet's 1 ETH stake
# / 50 ETH balance are anvil figures. Alto runs with --safe-mode false here, so the EntryPoint's
# reputation rules — the reason a large stake matters on a public network — are not in play.
TENANT_FUND_ETH="${TENANT_FUND_ETH:-0.02}"
STAKE_ETH="${STAKE_ETH:-0.01}"
UNSTAKE_DELAY="${UNSTAKE_DELAY:-86400}"

DERIVED="$(pnpm --filter @appliedblockchain/giano-contracts exec node -e \
  "const {Wallet}=require('ethers');console.log(new Wallet(process.env.DEPLOYER_PRIVATE_KEY).address+' '+new Wallet(process.env.SPONSORSHIP_SIGNER_KEY).address)")"
DEPLOYER_ADDR="${DERIVED%% *}"
SIGNER_ADDR="${DERIVED##* }"
# Where a tenant withdraws its unspent balance to. The deployer by default — this is a demo stack
# and the deployer already holds every role; a real tenant supplies its own address.
TENANT_WITHDRAW_ADDRESS="${TENANT_WITHDRAW_ADDRESS:-$DEPLOYER_ADDR}"

echo "==> Provisioning the sponsorship paymaster"
echo "    chain id   : $CHAIN_ID"
echo "    rpc        : $RPC_URL"
echo "    paymaster  : $SPONSORSHIP_PAYMASTER_ADDRESS"
echo "    role admin : $DEPLOYER_ADDR   (every role — a development shape, see below)"
echo "    signer     : $SIGNER_ADDR"
echo "    tenant     : $TENANT_SLUG  $TENANT_ID"
echo "    withdraw to: $TENANT_WITHDRAW_ADDRESS"
echo "    stake      : $STAKE_ETH ETH (unstake delay ${UNSTAKE_DELAY}s)   tenant balance: $TENANT_FUND_ETH ETH"
echo

# Every role on the deployer EOA, and the timelock topology D13/D14 describe deliberately absent —
# the same development shape e2e/devnet/generate-state.mjs uses, for the same reason. A testnet
# demo where one account legitimately holds ROLE_ADMIN is exactly what --grant-all-to is for; a
# production deployment routes every grant through the timelock instead.
DEPLOYER_PRIVATE_KEY="$DEPLOYER_PRIVATE_KEY" RPC_URL="$RPC_URL" \
  pnpm --filter @appliedblockchain/giano-contracts provision:paymaster -- \
    --paymaster "$SPONSORSHIP_PAYMASTER_ADDRESS" \
    --grant-all-to "$DEPLOYER_ADDR" \
    --signer "$SIGNER_ADDR" \
    --stake-eth "$STAKE_ETH" \
    --unstake-delay "$UNSTAKE_DELAY" \
    --tenant "$TENANT_ID:$TENANT_WITHDRAW_ADDRESS:$TENANT_SLUG:$TENANT_FUND_ETH"

echo
echo "==> Verifying on-chain (adoption checklist step 8)"
# --tenants takes bytes16, not the dashed UUID form the provisioner takes.
TENANT_BYTES16="0x$(echo "$TENANT_ID" | tr -d '-')"
pnpm --filter @appliedblockchain/giano-contracts run doctor chain \
  --rpc "$RPC_URL" \
  --chain-id "$CHAIN_ID" \
  --factory "${FACTORY_ADDRESS:?not set — run deploy-contracts.sh first}" \
  --sponsorship-paymaster "$SPONSORSHIP_PAYMASTER_ADDRESS" \
  ${TEST_PAYMASTER_ADDRESS:+--test-paymaster "$TEST_PAYMASTER_ADDRESS"} \
  --tenants "$TENANT_BYTES16" \
  --role-admin "$DEPLOYER_ADDR" \
  --signers "$SIGNER_ADDR"

echo
echo "==> Done. Next:"
echo "    1. docker compose --env-file deploy/.env -f deploy/docker-compose.sepolia.yml up --build"
echo "    2. Install the tenant's sponsorship rules (a tenant with no rules gets no sponsorship):"
echo "         ./deploy/sepolia/provision-sponsorship.sh"
