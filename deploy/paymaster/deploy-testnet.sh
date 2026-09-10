#!/usr/bin/env bash
# Deploy and provision the production GianoPaymaster on a testnet, end to end.
#
# Usage:  PAYMASTER_ADMIN_PRIVATE_KEY=0x... ./deploy/paymaster/deploy-testnet.sh <base-sepolia|sepolia>
#
# Three steps, in the order the runbook in specs/DEVELOPER-GUIDE.md gives them:
#
#   1. `hh:deploy:paymaster` — implementation, deployer helper, and the CREATE2 proxy, initialised
#      in the same transaction. Parameters come from ignition/params/<network>.json, which pins
#      `roleAdmin`. Re-running resumes the existing Ignition deployment, so this is idempotent.
#   2. Seed the paymaster's EntryPoint deposit, via `EntryPoint.depositTo`. NOT attributable to
#      any tenant — it is unattributed slack, which is what the doctor reports it as. It is here
#      because `provision-paymaster.ts` fails its own completeness check on an empty deposit
#      ("nothing can be sponsored"), so without this the script could not exit clean.
#   3. `provision:paymaster` — roles, the sponsorship signing key, and the stake. A deployment is
#      not complete until it is staked (R-24), which is why this script does not stop after step 1.
#   4. `doctor chain --require-paymaster` — the acceptance test. Fails the exit code rather than
#      warning, so this script's exit status means "usable" and not merely "deployed".
#
# ⚠ NO TENANTS. This script neither registers nor funds one: a tenant's gas balance is the
# tenant's own money, and onboarding is a separate act from standing up the paymaster. It also
# cannot be half-done here — `provision-paymaster.ts` treats a registered tenant with a zero
# balance as an incomplete deployment and exits non-zero, so registering without funding is not a
# state that tool will produce. Onboard afterwards, with the tenant's own funds:
#
#   RPC_URL=<url> DEPLOYER_PRIVATE_KEY=0x... \
#   pnpm --filter @appliedblockchain/giano-contracts provision:paymaster -- \
#     --paymaster 0x<proxy> --tenant <uuid>:<withdrawAddress>:<slug>:<fundEth>
#
# Until then the doctor warns that the roster is empty, which is the accurate reading.
#
# ⚠ THE ADMIN KEY SIGNS THE PROVISIONING. `provision-paymaster.ts` refuses to run unless the
# signing wallet already holds ROLE_ADMIN, and ROLE_ADMIN is baked into the initialise call from
# the params file. So PAYMASTER_ADMIN_PRIVATE_KEY must be the key for PAYMASTER_ROLE_ADMIN, and
# that account pays for everything: the deploy gas, the stake, and the tenant's balance.
#
# ⚠ EVERY ROLE ON ONE ADDRESS. This passes `--grant-all-to`, which the provision script itself
# flags as development-only: it collapses the separation the role topology exists to create. That
# is the intent for these two testnets. A production chain wants ROLE_ADMIN on a TimelockController
# and the operational roles held separately.
#
# Env (all optional except the key):
#   PAYMASTER_ADMIN_PRIVATE_KEY  required — the key for PAYMASTER_ROLE_ADMIN
#   PAYMASTER_ROLE_ADMIN         default 0xB62217487CdcdF2C999d323EEe424Af22dddBD87
#   PAYMASTER_SIGNER             sponsorship signing key's address; defaults to the role admin
#   PAYMASTER_STAKE_ETH          default 0.1 — giano-doctor's minimum for a staked paymaster
#   PAYMASTER_UNSTAKE_DELAY      default 86400
#   PAYMASTER_DEPOSIT_ETH        default 0.05 — unattributed EntryPoint deposit; 0 skips step 2,
#                                which makes provisioning exit non-zero on an empty deposit
#   RPC_URL                      overrides the chain's default public endpoint
set -euo pipefail

NETWORK="${1:-}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$REPO_ROOT/packages/contracts"

case "$NETWORK" in
  base-sepolia) CHAIN_ID=84532;    DEFAULT_RPC="https://sepolia.base.org" ;;
  sepolia)      CHAIN_ID=11155111; DEFAULT_RPC="https://ethereum-sepolia-rpc.publicnode.com" ;;
  *) echo "usage: $0 <base-sepolia|sepolia>"; exit 2 ;;
esac

: "${PAYMASTER_ADMIN_PRIVATE_KEY:?set PAYMASTER_ADMIN_PRIVATE_KEY (the ROLE_ADMIN key — it signs provisioning and pays for the stake)}"
ROLE_ADMIN="${PAYMASTER_ROLE_ADMIN:-0xB62217487CdcdF2C999d323EEe424Af22dddBD87}"
SIGNER="${PAYMASTER_SIGNER:-$ROLE_ADMIN}"
STAKE_ETH="${PAYMASTER_STAKE_ETH:-0.1}"
UNSTAKE_DELAY="${PAYMASTER_UNSTAKE_DELAY:-86400}"
DEPOSIT_ETH="${PAYMASTER_DEPOSIT_ETH:-0.05}"
RPC="${RPC_URL:-$DEFAULT_RPC}"
PARAMS="$CONTRACTS/ignition/params/$NETWORK.json"

[ -f "$PARAMS" ] || { echo "ERROR: no parameters file at $PARAMS"; exit 1; }

# The hardhat networks read different variables for the same two things (base-sepolia takes
# BASE_PRIVATE_KEY / BASE_SEPOLIA_RPC_URL, sepolia takes DEPLOYER_PRIVATE_KEY / DEPLOY_RPC_URL),
# so one input is fanned out rather than asking for the same key under two names.
export BASE_PRIVATE_KEY="$PAYMASTER_ADMIN_PRIVATE_KEY"
export DEPLOYER_PRIVATE_KEY="$PAYMASTER_ADMIN_PRIVATE_KEY"
export BASE_SEPOLIA_RPC_URL="$RPC"
export DEPLOY_RPC_URL="$RPC"
export RPC_URL="$RPC"

cd "$CONTRACTS"

# The params file pins ROLE_ADMIN into the initialise call, and provisioning is refused unless the
# signing key holds it — so catch a mismatched key here rather than after paying for a deploy.
SIGNER_ADDR="$(node -e "console.log(new (require('ethers').Wallet)(process.env.PAYMASTER_ADMIN_PRIVATE_KEY).address)")"
PARAM_ADMIN="$(node -e "console.log(require('$PARAMS').GianoPaymaster.roleAdmin)")"
if [ "$(echo "$SIGNER_ADDR" | tr 'A-F' 'a-f')" != "$(echo "$PARAM_ADMIN" | tr 'A-F' 'a-f')" ]; then
  echo "ERROR: PAYMASTER_ADMIN_PRIVATE_KEY is for $SIGNER_ADDR, but $NETWORK.json pins roleAdmin to $PARAM_ADMIN."
  echo "       Provisioning would be refused. Use that account's key, or change the params file."
  exit 1
fi

BALANCE="$(node -e "
  const { JsonRpcProvider, formatEther } = require('ethers');
  new JsonRpcProvider('$RPC').getBalance('$SIGNER_ADDR').then((b) => console.log(formatEther(b)));
")"

echo "==> GianoPaymaster on $NETWORK (chain $CHAIN_ID)"
echo "    rpc        : $RPC"
echo "    role admin : $PARAM_ADMIN  (holds every role)"
echo "    signer     : $SIGNER"
echo "    funder     : $SIGNER_ADDR — $BALANCE ETH"
echo "    stake      : $STAKE_ETH ETH, ${UNSTAKE_DELAY}s unstake delay"
echo "    deposit    : $DEPOSIT_ETH ETH (unattributed — no tenant is registered or funded)"
echo

echo "==> 1/4 deploying"
pnpm run hh:deploy:paymaster --network "$NETWORK" --parameters "$PARAMS"

PROXY="$(node -e "
  const path = './ignition/deployments/chain-$CHAIN_ID/deployed_addresses.json';
  console.log(require(path)['GianoPaymaster#SponsorshipPaymaster'] ?? '');
")"
[ -n "$PROXY" ] || { echo "ERROR: no proxy address in the Ignition deployment for chain $CHAIN_ID"; exit 1; }
echo "    proxy: $PROXY"

echo
if [ "$DEPOSIT_ETH" != "0" ]; then
  echo "==> 2/4 seeding the EntryPoint deposit ($DEPOSIT_ETH ETH, unattributed)"
  PROXY="$PROXY" DEPOSIT_ETH="$DEPOSIT_ETH" RPC="$RPC" node -e "
    const { JsonRpcProvider, Wallet, Contract, parseEther, formatEther } = require('ethers');
    const abi = ['function depositTo(address) payable', 'function balanceOf(address) view returns (uint256)'];
    const EP = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
    (async () => {
      const wallet = new Wallet(process.env.PAYMASTER_ADMIN_PRIVATE_KEY, new JsonRpcProvider(process.env.RPC));
      const ep = new Contract(EP, abi, wallet);
      await (await ep.depositTo(process.env.PROXY, { value: parseEther(process.env.DEPOSIT_ETH) })).wait();
      console.log('    deposit now ' + formatEther(await ep.balanceOf(process.env.PROXY)) + ' ETH');
    })().catch((error) => { console.error(error.message); process.exit(1); });
  "
else
  echo "==> 2/4 skipping the deposit (PAYMASTER_DEPOSIT_ETH=0) — provisioning will report it empty"
fi

echo
echo "==> 3/4 provisioning"
pnpm run provision:paymaster -- \
  --paymaster "$PROXY" \
  --signer "$SIGNER" \
  --grant-all-to "$ROLE_ADMIN" \
  --stake-eth "$STAKE_ETH" --unstake-delay "$UNSTAKE_DELAY"

echo
echo "==> 4/4 verifying"
pnpm run doctor chain --rpc "$RPC" --chain-id "$CHAIN_ID" \
  --sponsorship-paymaster "$PROXY" --require-paymaster \
  --role-admin "$ROLE_ADMIN" --signers "$SIGNER"

cat <<NEXT

==> Done. To make this address the default for chain $CHAIN_ID, add to
    packages/contracts/address-overrides.json:

      "$CHAIN_ID": { "sponsorshipPaymaster": "$PROXY" }

    then regenerate the registry and commit both:

      pnpm --filter @appliedblockchain/giano-contracts gen:addresses

    No tenant is registered, so nothing can be sponsored yet and the doctor warns about the empty
    roster. Onboard one with its own funds:

      RPC_URL=$RPC DEPLOYER_PRIVATE_KEY=<role-admin key> \
      pnpm --filter @appliedblockchain/giano-contracts provision:paymaster -- \
        --paymaster $PROXY --tenant <uuid>:<withdrawAddress>:<slug>:<fundEth>
NEXT
