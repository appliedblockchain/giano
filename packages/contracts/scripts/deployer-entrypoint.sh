#!/bin/sh
set -eu

: "${RPC_URL:?RPC_URL is required}"
: "${CHAIN_ID:?CHAIN_ID is required}"
: "${DEPLOYER_PRIVATE_KEY:?DEPLOYER_PRIVATE_KEY is required}"
DEPLOY_TESTING="${DEPLOY_TESTING:-false}"
OUT_DIR="${OUT_DIR:-/out}"
NETWORK="${HARDHAT_NETWORK:-base}"

# hardhat.config reads these; the same key/url drive whichever network is selected
export BASE_RPC_URL="$RPC_URL"
export BASE_SEPOLIA_RPC_URL="$RPC_URL"
export SDR_TESTNET_RPC_URL="$RPC_URL"
export BASE_PRIVATE_KEY="$DEPLOYER_PRIVATE_KEY"
export SDR_PRIVATE_KEY="$DEPLOYER_PRIVATE_KEY"

# CREATE2 keeps addresses identical across chains for identical bytecode; the Ignition
# journal makes re-runs idempotent (no double-deploy).
pnpm hh:deploy --network "$NETWORK"
if [ "$DEPLOY_TESTING" = "true" ]; then
  pnpm hh:deploy:testing --network "$NETWORK"
fi

pnpm gen:addresses

# emit the registry entry for this chain in the shared schema
CHAIN_ID="$CHAIN_ID" OUT_DIR="$OUT_DIR" pnpm exec ts-node -e "
  import { gianoAddresses } from './addresses';
  import * as fs from 'fs';
  const chainId = Number(process.env.CHAIN_ID);
  const deployment = gianoAddresses[chainId];
  if (!deployment) throw new Error('no registry entry generated for chain ' + chainId);
  const path = process.env.OUT_DIR + '/giano-addresses.' + chainId + '.json';
  fs.writeFileSync(path, JSON.stringify({ chainId, ...deployment }, null, 2));
  console.log('wrote ' + path);
"
