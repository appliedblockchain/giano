#!/usr/bin/env bash
# Deploy the production GianoPaymaster to a testnet. DEPLOY ONLY — it does not provision.
#
# Usage:  PAYMASTER_DEPLOY_PRIVATE_KEY=0x... ./deploy/paymaster/deploy-testnet.sh <base-sepolia|sepolia>
#
# Deploys three artifacts — the implementation, `GianoPaymasterDeployer`, and the ERC-1967 proxy,
# initialised in the same transaction — with `roleAdmin` taken from ignition/params/<network>.json.
# Re-running resumes the existing Ignition deployment, so this is idempotent.
#
# ⚠ THE DEPLOY KEY MUST NOT BE THE ROLE ADMIN. It pays gas and nothing else: `roleAdmin` is an
# initialiser argument, so the deploying account ends up holding no role at all (verified — see
# the checks at the end of this script, which assert it). Keeping them separate means the key that
# gets pasted into CI secrets and .env files cannot upgrade the paymaster or move its funds. The
# script refuses to run if the two are the same account.
#
# ⚠ IT DOES NOT PROVISION, so the paymaster it leaves behind CANNOT SPONSOR ANYTHING YET. Roles,
# the sponsorship signing key, the stake, the EntryPoint deposit and tenant onboarding all require
# ROLE_ADMIN to sign — `provision-paymaster.ts` refuses to run otherwise — and ROLE_ADMIN is held
# by an address this script has no key for. Those steps are printed as a runbook at the end, to be
# run by whoever controls that account.
#
# The proxy address does not depend on the deploying account, nor on any parameter in the params
# file: CreateX's guarded salt for this salt shape is keccak256(abi.encode(salt)) — no chainid, no
# msg.sender — and `roleAdmin` goes into the initialiser call rather than the proxy's init code.
# So the address below is the same for every operator on every chain, which is why it can be
# checked against the frozen constant in canonical.ts.
#
# Env:
#   PAYMASTER_DEPLOY_PRIVATE_KEY  required — gas only; must NOT be the role admin's key
#   RPC_URL                       overrides the chain's default public endpoint
#
# The role admin is NOT an environment variable: ignition/params/<network>.json is its single
# source of truth, because that file is what the deployment actually initialises from.
set -euo pipefail

NETWORK="${1:-}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONTRACTS="$REPO_ROOT/packages/contracts"

case "$NETWORK" in
  base-sepolia) CHAIN_ID=84532;    DEFAULT_RPC="https://sepolia.base.org" ;;
  sepolia)      CHAIN_ID=11155111; DEFAULT_RPC="https://ethereum-sepolia-rpc.publicnode.com" ;;
  *) echo "usage: $0 <base-sepolia|sepolia>"; exit 2 ;;
esac

: "${PAYMASTER_DEPLOY_PRIVATE_KEY:?set PAYMASTER_DEPLOY_PRIVATE_KEY (gas only — must not be the role admin key)}"
RPC="${RPC_URL:-$DEFAULT_RPC}"
PARAMS="$CONTRACTS/ignition/params/$NETWORK.json"

[ -f "$PARAMS" ] || { echo "ERROR: no parameters file at $PARAMS"; exit 1; }

# The two hardhat networks read different variables for the same two values (base-sepolia takes
# BASE_PRIVATE_KEY / BASE_SEPOLIA_RPC_URL, sepolia takes DEPLOYER_PRIVATE_KEY / DEPLOY_RPC_URL),
# so one input is fanned out rather than asking for the same key under two names.
export BASE_PRIVATE_KEY="$PAYMASTER_DEPLOY_PRIVATE_KEY"
export DEPLOYER_PRIVATE_KEY="$PAYMASTER_DEPLOY_PRIVATE_KEY"
export BASE_SEPOLIA_RPC_URL="$RPC"
export DEPLOY_RPC_URL="$RPC"
export RPC_URL="$RPC"

cd "$CONTRACTS"

ROLE_ADMIN="$(node -e "console.log(require('$PARAMS').GianoPaymaster.roleAdmin)")"
DEPLOYER_ADDR="$(node -e "console.log(new (require('ethers').Wallet)(process.env.PAYMASTER_DEPLOY_PRIVATE_KEY).address)")"

if [ "$(echo "$DEPLOYER_ADDR" | tr 'A-F' 'a-f')" = "$(echo "$ROLE_ADMIN" | tr 'A-F' 'a-f')" ]; then
  echo "ERROR: the deploy key IS the role admin ($DEPLOYER_ADDR)."
  echo "       Use a separate throwaway key — the deploy key is meant to hold no authority."
  exit 1
fi

BALANCE="$(node -e "
  const { JsonRpcProvider, formatEther } = require('ethers');
  new JsonRpcProvider('$RPC').getBalance('$DEPLOYER_ADDR').then((b) => console.log(formatEther(b)));
")"

echo "==> GianoPaymaster on $NETWORK (chain $CHAIN_ID)"
echo "    rpc        : $RPC"
echo "    deploy key : $DEPLOYER_ADDR — $BALANCE ETH (gas only, ends with no role)"
echo "    role admin : $ROLE_ADMIN (from $NETWORK.json — not signed for here)"
echo

pnpm run hh:deploy:paymaster --network "$NETWORK" --parameters "$PARAMS"

PROXY="$(node -e "
  const path = './ignition/deployments/chain-$CHAIN_ID/deployed_addresses.json';
  console.log(require(path)['GianoPaymaster#SponsorshipPaymaster'] ?? '');
")"
[ -n "$PROXY" ] || { echo "ERROR: no proxy address in the Ignition deployment for chain $CHAIN_ID"; exit 1; }

# Check what the deploy was actually for: the right address, the role on the right account, and
# nothing left on the deploy key. All read-only, so none of it needs the role admin's key. A wrong
# or missing params file is the failure this catches — it would silently leave ROLE_ADMIN on the
# deploy key, which is the one outcome the split exists to prevent.
echo
echo "==> verifying the deployment"
PROXY="$PROXY" ROLE_ADMIN="$ROLE_ADMIN" DEPLOYER_ADDR="$DEPLOYER_ADDR" RPC="$RPC" npx ts-node -e "
import { JsonRpcProvider, Contract, getAddress } from 'ethers';
import { CANONICAL_SPONSORSHIP_PAYMASTER } from './canonical';
import { gianoPaymasterAbi } from './generated';

const { PROXY, ROLE_ADMIN, DEPLOYER_ADDR, RPC } = process.env as Record<string, string>;
let failed = false;
const check = (ok: boolean, label: string, detail: string) => {
  if (!ok) failed = true;
  console.log(\`  \${ok ? '✓' : '✗'} \${label}: \${detail}\`);
};

(async () => {
  const paymaster = new Contract(PROXY, gianoPaymasterAbi, new JsonRpcProvider(RPC));
  const canonical = getAddress(PROXY) === getAddress(CANONICAL_SPONSORSHIP_PAYMASTER);
  check(canonical, 'proxy is at the canonical address', canonical ? PROXY : \`\${PROXY} — expected \${CANONICAL_SPONSORSHIP_PAYMASTER}; the implementation bytecode has drifted\`);

  const role = await paymaster.ROLE_ADMIN();
  const holders: string[] = [];
  const count: bigint = await paymaster.getRoleMemberCount(role);
  for (let i = 0n; i < count; i++) holders.push(getAddress(await paymaster.getRoleMember(role, i)));
  const sole = holders.length === 1 && holders[0] === getAddress(ROLE_ADMIN);
  check(sole, 'ROLE_ADMIN is the params file account, alone', sole ? holders[0] : \`\${holders.join(', ') || 'none'} — expected only \${getAddress(ROLE_ADMIN)}\`);

  const onDeployer = await paymaster.hasRole(role, DEPLOYER_ADDR);
  check(!onDeployer, 'deploy key holds no ROLE_ADMIN', onDeployer ? \`\${DEPLOYER_ADDR} HOLDS IT — do not reuse this key\` : DEPLOYER_ADDR);

  const superusers: bigint = await paymaster.getRoleMemberCount('0x' + '00'.repeat(32));
  check(superusers === 0n, 'no DEFAULT_ADMIN_ROLE holder', superusers === 0n ? 'there is no superuser' : \`\${superusers} holder(s)\`);

  const paused: boolean = await paymaster.paused();
  check(!paused, 'not paused', paused ? 'PAUSED' : 'accepting sponsorships once provisioned');

  process.exit(failed ? 1 : 0);
})().catch((error: unknown) => {
  console.error(\`  ✗ \${(error as Error).message}\`);
  process.exit(1);
});
"

cat <<NEXT

==> Deployed, NOT provisioned. Proxy: $PROXY

    It cannot sponsor anything yet. Everything below must be signed by ROLE_ADMIN
    ($ROLE_ADMIN), which this script has no key for.

    1. Provision — roles, the sponsorship signing key, and the stake. 0.1 ETH is
       giano-doctor's minimum stake; the signer is the address wallet-api signs
       authorisations with:

         RPC_URL=$RPC DEPLOYER_PRIVATE_KEY=<role admin key> \\
         pnpm --filter @appliedblockchain/giano-contracts provision:paymaster -- \\
           --paymaster $PROXY \\
           --signer <sponsorship-signer> \\
           --grant-all-to $ROLE_ADMIN \\
           --stake-eth 0.1 --unstake-delay 86400

       It exits non-zero until the EntryPoint deposit is non-empty. A tenant funding
       itself fills it; to seed it unattributed instead, send ETH to
       EntryPoint.depositTo($PROXY).

    2. Onboard a tenant, with the tenant's own funds — a paymaster with no funded
       tenant can sponsor nothing:

         … provision:paymaster -- --paymaster $PROXY \\
           --tenant <uuid>:<withdrawAddress>:<slug>:<fundEth>

    3. Register the address so the SDK and the doctor default to it. Add to
       packages/contracts/address-overrides.json:

         "$CHAIN_ID": { "sponsorshipPaymaster": "$PROXY" }

       then regenerate and commit both:

         pnpm --filter @appliedblockchain/giano-contracts gen:addresses

    4. Accept the result. Needs no key:

         pnpm run doctor chain --rpc $RPC --chain-id $CHAIN_ID \\
           --sponsorship-paymaster $PROXY --require-paymaster \\
           --role-admin $ROLE_ADMIN --signers <sponsorship-signer>
NEXT
