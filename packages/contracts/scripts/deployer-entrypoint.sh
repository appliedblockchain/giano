#!/bin/sh
# Entry point of the giano-contracts-deployer image (Dockerfile.deployer).
#
#   RPC_URL, CHAIN_ID          the chain (CHAIN_ID is checked against what the endpoint reports)
#   DEPLOYER_PRIVATE_KEY       the canonical deployer's key (packages/contracts/deploy/config.ts)
#   ROLE_ADMIN                 the paymaster's sole ROLE_ADMIN; a TimelockController in production
#   RELEASE                    optional; the latest release by default
#   DEPLOY_TESTING=true        also deploy PrivateERC20 + PermissivePaymaster (never on 8453/84532/11155111)
#   PAYMASTER_FUND_ETH         the test paymaster's initial EntryPoint deposit (default 0)
#   OUT_DIR                    where the record and the registry JSON go (default /out)
set -eu

: "${RPC_URL:?RPC_URL is required}"
: "${CHAIN_ID:?CHAIN_ID is required}"
: "${DEPLOYER_PRIVATE_KEY:?DEPLOYER_PRIVATE_KEY is required (the canonical deployer)}"
: "${ROLE_ADMIN:?ROLE_ADMIN is required (the paymaster ROLE_ADMIN)}"
DEPLOY_TESTING="${DEPLOY_TESTING:-false}"
OUT_DIR="${OUT_DIR:-/out}"

cli() { node_modules/.bin/tsx deploy/cli.ts "$@"; }

# The release defaults to the latest; RELEASE pins one. The record lands in $OUT_DIR, so a re-run
# against the same volume picks up where it left off.
cli core --rpc "$RPC_URL" --role-admin "$ROLE_ADMIN" --record-dir "$OUT_DIR" ${RELEASE:+--release "$RELEASE"}

if [ "$DEPLOY_TESTING" = "true" ]; then
  cli testing --rpc "$RPC_URL" --holder "$ROLE_ADMIN" --owner "$ROLE_ADMIN" \
    --fund-eth "${PAYMASTER_FUND_ETH:-0}" --record-dir "$OUT_DIR" ${RELEASE:+--release "$RELEASE"}
fi

# The registry entry for this chain in the shared schema (GianoDeployment in addresses.ts).
CHAIN_ID="$CHAIN_ID" OUT_DIR="$OUT_DIR" node -e '
  const fs = require("fs");
  const chainId = Number(process.env.CHAIN_ID);
  const record = JSON.parse(fs.readFileSync(`${process.env.OUT_DIR}/${chainId}.json`, "utf8"));
  if (record.chainId !== chainId) throw new Error(`the endpoint is chain ${record.chainId}, not CHAIN_ID=${chainId}`);
  const c = record.contracts;
  const entry = {
    chainId,
    entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
    factory: c.factory.address,
    implementation: c.walletImplementation.address,
    sponsorshipPaymaster: c.paymasterProxy.address,
    sponsorshipPaymasterImplementation: c.paymasterImplementation.address,
    ...(c.testPaymaster ? { testPaymaster: c.testPaymaster.address } : {}),
    ...(c.testErc20 ? { testErc20: c.testErc20.address } : {}),
  };
  const path = `${process.env.OUT_DIR}/giano-addresses.${chainId}.json`;
  fs.writeFileSync(path, JSON.stringify(entry, null, 2));
  console.log(`wrote ${path}`);
'
