#!/usr/bin/env bash
# One-time deployment of the Giano contracts to Sepolia (or any EVM chain) for the demo stack.
#
# Deploys, all through Ignition's create2 strategy so the addresses are the canonical ones:
#   GianoAccountFactory : GianoSmartWallet (impl) + GianoSmartWalletFactory
#   GianoPaymaster      : the production sponsorship paymaster (impl + deployer + proxy)
#   Testing             : PrivateERC20 + PermissivePaymaster (demo fixtures only)
#
# Then asserts every produced address equals the frozen constant in packages/contracts/canonical.ts
# and writes the addresses into deploy/.env.
#
# ⚠ The create2 strategy is NOT optional. specs/CHAIN-ADOPTION.md step 5 makes a divergent address
# a hard stop: one passkey resolves to one smart-account address on every served chain only when
# the factory and implementation sit at the canonical addresses. An earlier version of this script
# deployed with plain CREATE, which is deployer-nonce dependent — it produced a working but
# non-canonical deployment, the failure mode step 5 exists to catch.
#
# Usage:  ./deploy/sepolia/deploy-contracts.sh
#   Re-running resumes the existing deployment (safe & idempotent).
#   If a previous run was interrupted and the Ignition journal is inconsistent (resume fails
#   immediately), start clean with:   RESET=1 ./deploy/sepolia/deploy-contracts.sh
#
# Requires deploy/.env with DEPLOYER_PRIVATE_KEY set and the deployer funded (see README.md).
# Provisioning the paymaster (stake, signer, tenant, funding) is a SEPARATE step — the addresses
# above must be identical for every operator, everything provisioned is operator-specific. Run
# ./deploy/sepolia/provision-paymaster.sh next.
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
# Seeds the *testing* PermissivePaymaster's EntryPoint deposit (Testing.ts forwards it via
# receive()). Small by default: the demo sponsors through the production paymaster, which is
# funded by provision-paymaster.sh instead, so this deposit only backs the legacy fixture path.
export PAYMASTER_FUND_ETH="${PAYMASTER_FUND_ETH:-0.01}"
CHAIN_ID="${CHAIN_ID:-11155111}"
export DEPLOY_CHAIN_ID="${DEPLOY_CHAIN_ID:-$CHAIN_ID}"

# Named 'sepolia' network for the canonical case; 'custom' (env-driven chainId) otherwise.
if [ "$CHAIN_ID" = "11155111" ]; then NETWORK=sepolia; else NETWORK=custom; fi

# derive the deployer address via the contracts workspace (where ethers resolves)
DEPLOYER_ADDR="$(pnpm --filter @appliedblockchain/giano-contracts exec node -e \
  "console.log(new (require('ethers').Wallet)(process.env.DEPLOYER_PRIVATE_KEY).address)" 2>/dev/null || echo '<derive failed>')"

echo "==> Deploying Giano contracts (create2 strategy — canonical addresses)"
echo "    chain id : $CHAIN_ID   (hardhat network: $NETWORK)"
echo "    rpc      : $DEPLOY_RPC_URL"
echo "    deployer : $DEPLOYER_ADDR"
echo "    test-paymaster deposit: $PAYMASTER_FUND_ETH ETH"
[ "${RESET:-0}" = "1" ] && echo "    RESET=1  -> wiping existing deployment state first"
echo

# The create2 strategy needs CreateX on the chain. Checking here turns an opaque mid-deploy
# revert into a sentence — adoption checklist step 1.
CREATEX=0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed
CREATEX_CODE="$(curl -s -m 20 -X POST -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getCode\",\"params\":[\"$CREATEX\",\"latest\"]}" \
  "$DEPLOY_RPC_URL" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')"
if [ "$CREATEX_CODE" = "0x" ] || [ -z "$CREATEX_CODE" ]; then
  echo "ERROR: CreateX is not deployed at $CREATEX on this chain." >&2
  echo "  Ignition's create2 strategy deploys through it, and without it the canonical addresses" >&2
  echo "  are unreachable. Deploy CreateX first (see specs/CHAIN-ADOPTION.md step 1)." >&2
  exit 1
fi

# hardhat-ignition prompts to confirm deploying to a real network, and (with --reset) a second
# time to confirm the wipe. Feed enough 'y' answers for both; extra lines are ignored.
# $2 holds optional extra flags (e.g. --reset); left unquoted so an empty value passes zero args
# (avoids bash-3.2 empty-array pitfalls under `set -u`).
run_deploy() {
  local module="$1" extra="${2:-}"
  # shellcheck disable=SC2086
  printf 'y\ny\n' | pnpm --filter @appliedblockchain/giano-contracts exec \
    hardhat ignition deploy "$module" --network "$NETWORK" --strategy create2 $extra
}

# --reset (opt-in) applies ONLY to the first module; all modules share the chain-<id> deployment
# dir, so resetting on a later one would wipe the freshly-deployed factory.
RESET_FLAG=""
[ "${RESET:-0}" = "1" ] && RESET_FLAG="--reset"

if ! run_deploy ignition/modules/GianoAccountFactory.ts "$RESET_FLAG"; then
  echo >&2
  echo "ERROR: factory deployment failed." >&2
  echo "  If a prior run was interrupted and this fails immediately on resume, the Ignition" >&2
  echo "  journal is likely inconsistent — start clean with:  RESET=1 $0" >&2
  exit 1
fi

if ! run_deploy ignition/modules/GianoPaymaster.ts; then
  echo >&2
  echo "ERROR: sponsorship paymaster deployment failed." >&2
  echo "  Re-run the script to resume, or start clean with:  RESET=1 $0" >&2
  exit 1
fi

# The demo fixtures (PrivateERC20 + PermissivePaymaster).
#
# NEVER deployed to a chain in PRODUCTION_CHAIN_IDS (scripts/generate-addresses.ts) — 8453, 84532
# and 11155111. That is R-29 layer 2, and gen:addresses enforces it as a build failure: a chain
# carrying testPaymaster or testErc20 cannot be registered at all. Skipping is therefore not a
# preference, it is the only way the chain can be adopted. This is also why Base Sepolia has no
# test ERC-20 — the rule, not an omission.
#
# Note the conflict, because it is real and unresolved: HANDOVER-TASKS H3 R13 asks for the test
# ERC-20 on *each testnet* with CREATE2 so its address is identical everywhere, and both 84532 and
# 11155111 are testnets. R-29 wins here only because it is the rule the code enforces.
case " 8453 84532 11155111 " in
  *" $CHAIN_ID "*) PRODUCTION_CHAIN=1 ;;
  *) PRODUCTION_CHAIN=0 ;;
esac

if [ "$PRODUCTION_CHAIN" = "1" ]; then
  echo
  echo "==> chain $CHAIN_ID is a production chain — NOT deploying PrivateERC20 / PermissivePaymaster"
  echo "    (R-29 layer 2; gen:addresses refuses to register a chain that carries them)"
elif [ "${SKIP_TESTING:-0}" = "1" ]; then
  echo
  echo "==> SKIP_TESTING=1 — not deploying PrivateERC20 / PermissivePaymaster"
elif ! run_deploy ignition/modules/Testing.ts; then
  echo >&2
  echo "ERROR: testing-contracts deployment failed." >&2
  echo "  Re-run the script to resume, or start clean with:  RESET=1 $0" >&2
  exit 1
fi

ADDR_JSON="$CONTRACTS/ignition/deployments/chain-$CHAIN_ID/deployed_addresses.json"
[ -f "$ADDR_JSON" ] || { echo "ERROR: expected $ADDR_JSON after deploy"; exit 1; }

echo
echo "==> Verifying the deployed addresses against the canonical freeze"
node - "$ADDR_JSON" "$CONTRACTS/canonical.ts" "$ENV_FILE" <<'NODE'
const fs = require('fs');
const [, , addrPath, canonicalPath, envPath] = process.argv;
const a = JSON.parse(fs.readFileSync(addrPath, 'utf8'));
const canonicalSource = fs.readFileSync(canonicalPath, 'utf8');

/*
 * canonical.ts is read as text rather than imported: it is a TypeScript source in a package whose
 * build may not have run yet, and this check must work on a clean checkout. The constants are
 * plain string literals, so a regex is sufficient and has no build-order dependency.
 */
function canonical(name) {
  const match = canonicalSource.match(new RegExp(`${name}\\s*=\\s*'(0x[0-9a-fA-F]{40})'`));
  if (!match) throw new Error(`could not read ${name} from canonical.ts`);
  return match[1];
}

const expected = [
  ['GianoAccountFactory#GianoSmartWalletFactory', 'CANONICAL_FACTORY'],
  ['GianoAccountFactory#GianoSmartWallet', 'CANONICAL_IMPLEMENTATION'],
  ['GianoPaymaster#SponsorshipPaymaster', 'CANONICAL_SPONSORSHIP_PAYMASTER'],
  ['GianoPaymaster#GianoPaymaster', 'CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION'],
  ['GianoPaymaster#GianoPaymasterDeployer', 'CANONICAL_PAYMASTER_DEPLOYER'],
];

let diverged = 0;
for (const [key, constant] of expected) {
  const got = a[key];
  const want = canonical(constant);
  if (!got) {
    console.error(`  ✗ ${constant}: ${key} missing from the deployment journal`);
    diverged += 1;
  } else if (got.toLowerCase() !== want.toLowerCase()) {
    console.error(`  ✗ ${constant}\n      expected ${want}\n      got      ${got}`);
    diverged += 1;
  } else {
    console.log(`  ✓ ${constant.padEnd(46)} ${got}`);
  }
}

if (diverged > 0) {
  console.error(
    `\nDEPLOYMENT DIVERGED FROM THE CANONICAL FREEZE (${diverged} address(es)).\n` +
      '\nDo NOT serve this chain and do NOT register these addresses. A divergent result means the\n' +
      'wrong sources or the wrong EntryPoint — specs/CHAIN-ADOPTION.md steps 1, 2 and 5. The usual\n' +
      'causes are a missing CreateX, a non-canonical EntryPoint v0.7, or a contracts build that is\n' +
      'not the frozen one (solc 0.8.28, optimizer runs 200, viaIR, evm "paris").',
  );
  process.exit(1);
}

console.log('\n==> Writing addresses into ' + envPath);
const map = {
  FACTORY_ADDRESS: a['GianoAccountFactory#GianoSmartWalletFactory'],
  // The two paymasters are separate variables for the same reason addresses.ts keeps them in
  // separate fields: nothing should be able to pass the permissive test paymaster where the
  // production one is meant. The demo stack sponsors through SPONSORSHIP_PAYMASTER_ADDRESS.
  SPONSORSHIP_PAYMASTER_ADDRESS: a['GianoPaymaster#SponsorshipPaymaster'],
  TEST_PAYMASTER_ADDRESS: a['Testing#PermissivePaymaster'],
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
echo "    1. Provision the paymaster (stake, signer, tenant, funding):"
echo "         ./deploy/sepolia/provision-paymaster.sh"
echo "    2. Register chain $CHAIN_ID in the contracts address registry:"
echo "         pnpm --filter @appliedblockchain/giano-contracts gen:addresses"
echo "       and commit ignition/deployments/chain-$CHAIN_ID + addresses.ts"
echo "    3. Fund the Alto executor EOA (see: ./deploy/sepolia/print-funding.sh)"
echo "    4. docker compose --env-file deploy/.env -f deploy/docker-compose.sepolia.yml up --build"
