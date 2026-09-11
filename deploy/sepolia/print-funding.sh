#!/usr/bin/env bash
# Prints the EOAs you need to fund with testnet ETH (derived from the keys in deploy/.env),
# their current balances, and the suggested top-up amounts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$REPO_ROOT/deploy/.env"

[ -f "$ENV_FILE" ] || { echo "ERROR: $ENV_FILE not found. Run: cp deploy/sepolia.env.example deploy/.env"; exit 1; }
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

RPC="${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}" \
pnpm --filter @appliedblockchain/giano-contracts exec node - <<'NODE'
const { JsonRpcProvider, Wallet, formatEther } = require('ethers');
const provider = new JsonRpcProvider(process.env.RPC);
const stake = process.env.STAKE_ETH ?? '0.01';
const tenantFund = process.env.TENANT_FUND_ETH ?? '0.02';
const testDeposit = process.env.PAYMASTER_FUND_ETH ?? '0.01';
const rows = [
  [
    'Deployer',
    process.env.DEPLOYER_PRIVATE_KEY,
    '~0.15',
    `contracts + paymaster stake (${stake}) + tenant balance (${tenantFund}) + test deposit (${testDeposit}) + gas`,
  ],
  ['Alto executor', process.env.ALTO_EXECUTOR_PRIVATE_KEY, '~0.05', 'fronts gas for every bundle (reimbursed by paymaster)'],
  // Listed so a missing key is caught here rather than three steps later, not because it needs ETH:
  // it authorises spending against the tenant's paymaster balance and never pays gas.
  ['Sponsorship signer', process.env.SPONSORSHIP_SIGNER_KEY, 'none', 'signs ERC-7677 sponsorships — no funding needed'],
];
(async () => {
  console.log(`\nRPC: ${process.env.RPC}\n`);
  for (const [name, pk, want, note] of rows) {
    if (!pk) { console.log(`${name.padEnd(20)} <key not set in deploy/.env>`); continue; }
    const addr = new Wallet(pk).address;
    let bal = '?';
    try { bal = formatEther(await provider.getBalance(addr)); } catch {}
    console.log(`${name.padEnd(20)} ${addr}`);
    console.log(`${''.padEnd(20)} balance: ${bal} ETH   suggested: ${want} ETH   (${note})\n`);
  }
  console.log('Get Sepolia ETH from a faucet, e.g. https://sepoliafaucet.com or https://www.alchemy.com/faucets/ethereum-sepolia');
})();
NODE
