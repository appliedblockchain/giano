#!/usr/bin/env bash
# Provisions the sponsorship paymaster deployed by pnpm contracts:deploy:
# grants roles, registers the sponsorship signing key, stakes with the EntryPoint, registers every
# tenant in PAYMASTER_TENANTS and funds each balance. Then verifies its own work with
# `giano-doctor chain`.
#
# Roles: one holder per immediate role (ROLE_HOLDER_SIGNER_ADMIN, ROLE_HOLDER_PARAM_ADMIN,
# ROLE_HOLDER_PAUSER, ROLE_HOLDER_STAKE_ADMIN, ROLE_HOLDER_TENANT_ADMIN, ROLE_HOLDER_FEE_COLLECTOR),
# or PAYMASTER_GRANT_ALL_TO=<address> for the development shape with every role on one address,
# which a mainnet refuses. The timelocked roles go to the timelock with contracts:handoff.
#
# Separate from pnpm contracts:deploy on purpose, and the split is the same one the Ignition module
# argues for: the deployed addresses must be identical for every operator, while everything here
# is operator-specific. specs/CHAIN-ADOPTION.md step 7.
#
# ⚠ Costs real testnet ETH: the stake, the tenant's funded balance, and gas for ~10 transactions.
#
# Usage: pnpm contracts:provision --chain <profile> --env-file <file>
#   Idempotent for roles, signer and stake. NOT for funding: re-running adds TENANT_FUND_ETH to
#   each tenant's balance again rather than topping it up to that figure.
set -euo pipefail

: "${GIANO_PROFILE_LOADED:?use pnpm contracts:funding, contracts:provision or contracts:sponsorship with --chain <profile>}"
: "${CHAIN_ID:?select a chain profile}"
: "${RPC_URL:?provide a chain RPC}"

: "${DEPLOYER_PRIVATE_KEY:?set DEPLOYER_PRIVATE_KEY in the selected operator environment}"
: "${SPONSORSHIP_PAYMASTER_ADDRESS:?not set — run pnpm contracts:deploy first}"
# The sponsorship signer by its address: in production its key lives in an HSM and is never handed
# out. A testnet may still give the key (it is only used to derive the address).
if [ -z "${SPONSORSHIP_SIGNER_ADDRESS:-}" ] && [ -z "${SPONSORSHIP_SIGNER_KEY:-}" ]; then
  echo "ERROR: set SPONSORSHIP_SIGNER_ADDRESS (the address wallet-api signs sponsorships with)" >&2
  exit 1
fi
if [ "${GIANO_NETWORK:-}" = "mainnet" ] && [ -n "${SPONSORSHIP_SIGNER_KEY:-}" ]; then
  echo "ERROR: a mainnet takes the sponsorship signer as SPONSORSHIP_SIGNER_ADDRESS, never its key" >&2
  exit 1
fi

# Provisioning writes to the chain, so it uses the DEPLOYMENT rpc, not the stack's serving one.
export RPC_URL="${DEPLOY_RPC_URL:-$RPC_URL}"

# The tenants to register, as `slug:uuid` pairs. Explicitly supplied from the selected environment.
# Each gets TENANT_FUND_ETH, so the deployer spends
# that amount once per tenant.
#
# The ids must equal the ones in that deployment's database: the paymaster keys a tenant's
# balance on the 16 bytes of its UUID, and a tenant whose database id differs from its on-chain id
# has every sponsorship refused as an unknown tenant.
: "${PAYMASTER_TENANTS:?provide slug:existing-database-uuid pairs in the selected operator environment}"
# Per-tenant balance, and the paymaster's EntryPoint stake.
#
# STAKE_ETH must be at least 0.1: that is MIN_STAKE_WEI in scripts/doctor.ts, and the doctor
# reports anything below it as a FAILED check — "deployed but not staked" is treated as a broken
# deployment, not a warning, because bundlers reject an under-staked validating paymaster and it
# reads to a client as a bug in their own code. giano-bundler does not check stake, which does not
# make this optional: it only means Giano's own stack happens not to exercise the rule.
TENANT_FUND_ETH="${TENANT_FUND_ETH:-0.02}"
STAKE_ETH="${STAKE_ETH:-0.1}"
UNSTAKE_DELAY="${UNSTAKE_DELAY:-86400}"

DERIVED="$(pnpm --filter @appliedblockchain/giano-contracts exec node -e \
  "try { const {Wallet,getAddress}=require('ethers');const e=process.env;console.log(new Wallet(e.DEPLOYER_PRIVATE_KEY).address+' '+(e.SPONSORSHIP_SIGNER_ADDRESS?getAddress(e.SPONSORSHIP_SIGNER_ADDRESS):new Wallet(e.SPONSORSHIP_SIGNER_KEY).address)) } catch { console.error('Invalid operator key, sponsorship signer address/key, or missing dependencies.'); process.exit(1) }")"
DEPLOYER_ADDR="${DERIVED%% *}"
SIGNER_ADDR="${DERIVED##* }"

# One holder per immediate role, or every role on one address (development only).
ROLE_ARGS=()
for pair in signer-admin:SIGNER_ADMIN param-admin:PARAM_ADMIN pauser:PAUSER \
            stake-admin:STAKE_ADMIN tenant-admin:TENANT_ADMIN fee-collector:FEE_COLLECTOR; do
  var="ROLE_HOLDER_${pair#*:}"
  if [ -n "${!var:-}" ]; then ROLE_ARGS+=(--role-holder-"${pair%%:*}" "${!var}"); fi
done
if [ -n "${PAYMASTER_GRANT_ALL_TO:-}" ]; then
  if [ "${GIANO_NETWORK:-}" = "mainnet" ]; then
    echo "ERROR: PAYMASTER_GRANT_ALL_TO puts every role on one address; a mainnet refuses it. Name a ROLE_HOLDER_* per role." >&2
    exit 1
  fi
  [ ${#ROLE_ARGS[@]} -eq 0 ] || { echo "ERROR: set PAYMASTER_GRANT_ALL_TO or ROLE_HOLDER_*, not both" >&2; exit 1; }
  ROLE_ARGS=(--grant-all-to "$PAYMASTER_GRANT_ALL_TO")
  ROLE_SUMMARY="every role on $PAYMASTER_GRANT_ALL_TO (a development shape)"
elif [ ${#ROLE_ARGS[@]} -eq 0 ]; then
  echo "ERROR: name the role holders: ROLE_HOLDER_SIGNER_ADMIN, ROLE_HOLDER_PARAM_ADMIN, ROLE_HOLDER_PAUSER," >&2
  echo "       ROLE_HOLDER_STAKE_ADMIN, ROLE_HOLDER_TENANT_ADMIN, ROLE_HOLDER_FEE_COLLECTOR — or, on a testnet," >&2
  echo "       PAYMASTER_GRANT_ALL_TO=<address> for every role on one address." >&2
  exit 1
else
  ROLE_SUMMARY="one holder per role: ${ROLE_ARGS[*]}"
fi

# Where a tenant withdraws its unspent balance to. A real tenant supplies its own address; only a
# testnet demo may default it to the operator.
if [ -z "${TENANT_WITHDRAW_ADDRESS:-}" ] && [ "${GIANO_NETWORK:-}" = "mainnet" ]; then
  echo "ERROR: a mainnet needs each tenant's own TENANT_WITHDRAW_ADDRESS; it is never defaulted to the operator" >&2
  exit 1
fi
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
echo "    network    : $CHAIN_NAME ($CHAIN_ID)"
echo "    paymaster  : $SPONSORSHIP_PAYMASTER_ADDRESS"
echo "    role admin : $DEPLOYER_ADDR"
echo "    roles      : $ROLE_SUMMARY"
echo "    signer     : $SIGNER_ADDR"
echo "    tenants    : $TENANT_SUMMARY"
echo "    withdraw to: $TENANT_WITHDRAW_ADDRESS"
echo "    stake      : $STAKE_ETH ETH (unstake delay ${UNSTAKE_DELAY}s)   per-tenant balance: $TENANT_FUND_ETH ETH"
echo

# ROLE_ADMIN stays on the bootstrap key until contracts:handoff moves it, with the other timelocked
# roles, to the timelock (G9).
DEPLOYER_PRIVATE_KEY="$DEPLOYER_PRIVATE_KEY" RPC_URL="$RPC_URL" \
  pnpm --filter @appliedblockchain/giano-contracts provision:paymaster -- \
    --paymaster "$SPONSORSHIP_PAYMASTER_ADDRESS" \
    "${ROLE_ARGS[@]}" \
    --signer "$SIGNER_ADDR" \
    --stake-eth "$STAKE_ETH" \
    --unstake-delay "$UNSTAKE_DELAY" \
    "${TENANT_ARGS[@]}"

echo
echo "==> Verifying on-chain (adoption checklist step 8)"
pnpm --filter @appliedblockchain/giano-contracts run doctor chain \
  --rpc "$RPC_URL" \
  --chain-id "$CHAIN_ID" \
  --factory "${FACTORY_ADDRESS:?not set — run pnpm contracts:deploy first}" \
  --sponsorship-paymaster "$SPONSORSHIP_PAYMASTER_ADDRESS" \
  ${TEST_PAYMASTER_ADDRESS:+--test-paymaster "$TEST_PAYMASTER_ADDRESS"} \
  --tenants "$TENANT_BYTES16" \
  --role-admin "$DEPLOYER_ADDR" \
  --signers "$SIGNER_ADDR"

echo
echo "==> Done. Next:"
echo "    1. Start the demo using deploy/contracts/DEMO.md."
echo "    2. Install each tenant's sponsorship rules (a tenant with no rules gets no sponsorship):"
echo "         pnpm contracts:sponsorship --chain <profile> --env-file <operator-file>"
echo "    3. Before the paymaster holds real tenant money, put its timelocked roles behind the"
echo "       timelock (G9): pnpm contracts:timelock, then pnpm contracts:handoff, then contracts:doctor."
echo "       See docs/PAYMASTER-TIMELOCK-RUNBOOK.md."
