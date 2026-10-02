#!/usr/bin/env bash
# Provisions the sponsorship paymaster deployed by ./deploy/sepolia/deploy-contracts.sh:
# grants roles, registers the sponsorship signing key, stakes with the EntryPoint, registers every
# tenant in PAYMASTER_TENANTS and funds each balance. Then verifies its own work with
# `giano-doctor chain`.
#
# Separate from deploy-contracts.sh on purpose, and the split is the same one the Ignition module
# argues for: the deployed addresses must be identical for every operator, while everything here
# is operator-specific. specs/CHAIN-ADOPTION.md step 7.
#
# ⚠ Costs real testnet ETH: the stake, the tenant's funded balance, and gas for ~10 transactions.
#
# Usage:  ./deploy/sepolia/provision-paymaster.sh
#   Idempotent for roles, signer and stake. NOT for funding: re-running adds TENANT_FUND_ETH to
#   each tenant's balance again rather than topping it up to that figure.
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

# Provisioning writes to the chain, so it uses the DEPLOYMENT rpc, not the stack's serving one.
export RPC_URL="${DEPLOY_RPC_URL:-${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}}"
CHAIN_ID="${CHAIN_ID:-11155111}"

# The tenants to register, as `slug:uuid` pairs. Defaults to the two the development environment
# serves (infra/iac/_locals.tf `tenant_hosts`). Each gets TENANT_FUND_ETH, so the deployer spends
# that amount once per tenant.
#
# The ids must equal the ones in that deployment's TENANTS_SEED: the paymaster keys a tenant's
# balance on the 16 bytes of its UUID, and a tenant whose database id differs from its on-chain id
# has every sponsorship refused as an unknown tenant.
PAYMASTER_TENANTS="${PAYMASTER_TENANTS:-example:a1000000-0000-4000-8000-000000000001,byoui:a1000000-0000-4000-8000-000000000002}"
# Per-tenant balance, and the paymaster's EntryPoint stake.
#
# STAKE_ETH must be at least 0.1: that is MIN_STAKE_WEI in scripts/doctor.ts, and the doctor
# reports anything below it as a FAILED check — "deployed but not staked" is treated as a broken
# deployment, not a warning, because bundlers reject an under-staked validating paymaster and it
# reads to a client as a bug in their own code. Running Alto with --safe-mode false does not make
# this optional; it only means the local stack happens not to exercise the rule.
TENANT_FUND_ETH="${TENANT_FUND_ETH:-0.02}"
STAKE_ETH="${STAKE_ETH:-0.1}"
UNSTAKE_DELAY="${UNSTAKE_DELAY:-86400}"

DERIVED="$(pnpm --filter @appliedblockchain/giano-contracts exec node -e \
  "const {Wallet}=require('ethers');console.log(new Wallet(process.env.DEPLOYER_PRIVATE_KEY).address+' '+new Wallet(process.env.SPONSORSHIP_SIGNER_KEY).address)")"
DEPLOYER_ADDR="${DERIVED%% *}"
SIGNER_ADDR="${DERIVED##* }"
# Where a tenant withdraws its unspent balance to. The deployer by default — this is a demo stack
# and the deployer already holds every role; a real tenant supplies its own address.
TENANT_WITHDRAW_ADDRESS="${TENANT_WITHDRAW_ADDRESS:-$DEPLOYER_ADDR}"

# Expand `slug:uuid,slug:uuid` into the provisioner's repeated --tenant flags and the doctor's
# bytes16 --tenants list. Both are built in one pass so they cannot drift apart.
TENANT_ARGS=()
TENANT_BYTES16=""
TENANT_SUMMARY=""
IFS=',' read -r -a TENANT_PAIRS <<< "$PAYMASTER_TENANTS"
for pair in "${TENANT_PAIRS[@]}"; do
  pair="$(echo "$pair" | tr -d '[:space:]')"
  [ -z "$pair" ] && continue
  slug="${pair%%:*}"
  uuid="${pair#*:}"
  if [ -z "$slug" ] || [ -z "$uuid" ] || [ "$slug" = "$uuid" ]; then
    echo "ERROR: PAYMASTER_TENANTS entry '$pair' is not in the form slug:uuid" >&2
    exit 1
  fi
  TENANT_ARGS+=(--tenant "$uuid:$TENANT_WITHDRAW_ADDRESS:$slug:$TENANT_FUND_ETH")
  # --tenants takes bytes16, not the dashed UUID form --tenant takes.
  TENANT_BYTES16="${TENANT_BYTES16:+$TENANT_BYTES16,}0x$(echo "$uuid" | tr -d '-')"
  TENANT_SUMMARY="${TENANT_SUMMARY:+$TENANT_SUMMARY, }$slug=$uuid"
done
[ ${#TENANT_ARGS[@]} -gt 0 ] || { echo "ERROR: PAYMASTER_TENANTS is empty — nothing to register" >&2; exit 1; }

echo "==> Provisioning the sponsorship paymaster"
echo "    chain id   : $CHAIN_ID"
echo "    rpc        : $RPC_URL"
echo "    paymaster  : $SPONSORSHIP_PAYMASTER_ADDRESS"
echo "    role admin : $DEPLOYER_ADDR   (every role — a development shape, see below)"
echo "    signer     : $SIGNER_ADDR"
echo "    tenants    : $TENANT_SUMMARY"
echo "    withdraw to: $TENANT_WITHDRAW_ADDRESS"
echo "    stake      : $STAKE_ETH ETH (unstake delay ${UNSTAKE_DELAY}s)   per-tenant balance: $TENANT_FUND_ETH ETH"
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
    "${TENANT_ARGS[@]}"

echo
echo "==> Verifying on-chain (adoption checklist step 8)"
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
echo "    2. Install each tenant's sponsorship rules (a tenant with no rules gets no sponsorship):"
echo "         ./deploy/sepolia/provision-sponsorship.sh"
