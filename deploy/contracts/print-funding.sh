#!/usr/bin/env bash
# Prints the EOAs you need to fund with testnet ETH (derived from the keys in the selected operator environment),
# their current balances, and the suggested top-up amounts.
set -euo pipefail

: "${GIANO_PROFILE_LOADED:?use pnpm contracts:funding, contracts:provision or contracts:sponsorship with --chain <profile>}"
: "${CHAIN_ID:?select a chain profile}"
: "${RPC_URL:?provide a chain RPC}"

RPC="$RPC_URL" \
pnpm --filter @appliedblockchain/giano-contracts exec node - <<'NODE'
const { JsonRpcProvider, Wallet, formatEther } = require('ethers');
const provider = new JsonRpcProvider(process.env.RPC);
const stake = process.env.STAKE_ETH ?? '0.1';
const tenantFund = process.env.TENANT_FUND_ETH ?? '0.02';
const rows = [
  // Pays for the four core contract deployments.
  ['Canonical deployer', process.env.CANONICAL_DEPLOYER_PRIVATE_KEY, process.env.DEPLOYER_MIN_ETH, 'core contract deployments'],
  [
    'Operator',
    process.env.DEPLOYER_PRIVATE_KEY,
    '~0.2',
    `paymaster stake (${stake}) + tenant balance (${tenantFund}) + provisioning gas`,
  ],
  [
    'Bundler executor',
    (process.env.BUNDLER_EXECUTOR_PRIVATE_KEYS || '').split(',')[0].trim(),
    '~0.05',
    'fronts gas for every handleOps transaction (reimbursed by the EntryPoint)',
  ],
  // Listed so a missing key is caught here rather than three steps later, not because it needs ETH:
  // it authorises spending against the tenant's paymaster balance and never pays gas.
  ['Sponsorship signer', process.env.SPONSORSHIP_SIGNER_KEY, 'none', 'signs ERC-7677 sponsorships — no funding needed'],
];
(async () => {
  console.log(`\nNetwork: ${process.env.CHAIN_NAME} (${process.env.CHAIN_ID})\n`);
  for (const [name, pk, want, note] of rows) {
    if (!pk) { console.log(`${name.padEnd(20)} <key not set in the selected operator environment>`); continue; }
    let addr;
    try { addr = new Wallet(pk).address; } catch { console.log(`${name}: invalid key; correct the operator environment.`); process.exitCode = 1; continue; }
    let bal = '?';
    try { bal = formatEther(await provider.getBalance(addr)); } catch {}
    console.log(`${name.padEnd(20)} ${addr}`);
    console.log(`${''.padEnd(20)} balance: ${bal} ETH   suggested: ${want} ETH   (${note})\n`);
  }
  console.log('Fund these addresses on the selected network; balances and fees do not carry across chains.');
})();
NODE
