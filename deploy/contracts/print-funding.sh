#!/usr/bin/env bash
# Prints the EOAs you need to fund with testnet ETH (derived from the keys in the selected operator environment),
# their current balances, and the suggested top-up amounts. The gas part of each amount follows the
# chain's gas price (packages/contracts/deploy/funding.ts).
set -euo pipefail

: "${GIANO_PROFILE_LOADED:?use pnpm contracts:funding, contracts:provision or contracts:sponsorship with --chain <profile>}"
: "${CHAIN_ID:?select a chain profile}"
: "${RPC_URL:?provide a chain RPC}"

# The RPC URL stays in the environment: pnpm prints the command line it runs (G48 R1).
exec pnpm --filter @appliedblockchain/giano-contracts exec tsx scripts/funding.ts
