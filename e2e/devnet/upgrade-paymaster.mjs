/** Upgrade the baked local paymaster through UUPS, preserving its proxy and funded tenants.
 * Run on a fresh pinned anvil via `pnpm devnet:upgrade:paymaster`.
 * This script loads and writes local fixture state only; it refuses non-Anvil nodes.
 *
 * The new implementation is the working tree's (`--release dev`), deployed by the deploy CLI under
 * a content-addressed upgrade label and installed with upgradeToAndCall from anvil account 0, which
 * holds UPGRADER_ROLE in the baked state.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';

const RPC = process.env.RPC_URL ?? 'http://127.0.0.1:18545';
/** Anvil's account 0. Never used anywhere real. */
const ANVIL_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

let id = 0;
async function rpc(method, params = []) {
  const response = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }) });
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

const version = await rpc('web3_clientVersion');
if (!version.includes('anvil') || !version.includes('1.7.1')) throw new Error('requires the pinned local Anvil 1.7.1');
if (Number(BigInt(await rpc('eth_chainId'))) !== 31337) throw new Error('requires local chain 31337');

const statePath = new URL('./state.json', import.meta.url);
const addressesPath = new URL('./addresses.json', import.meta.url);
const addresses = JSON.parse(readFileSync(addressesPath, 'utf8'));
// Anvil accepts its compressed dump format. Compress before hex encoding so the
// growing fixture stays below the JSON-RPC request-size limit.
await rpc('anvil_loadState', [`0x${gzipSync(readFileSync(statePath)).toString('hex')}`]);

const recordDir = mkdtempSync(join(tmpdir(), 'giano-devnet-upgrade-'));
try {
  execFileSync(
    'pnpm',
    ['--filter', '@appliedblockchain/giano-contracts', 'deploy:cli', 'upgrade', '--rpc', RPC, '--impersonate', '--contract', 'paymaster', '--release', 'dev', '--execute', '--record-dir', recordDir],
    { stdio: 'inherit', env: { ...process.env, UPGRADER_PRIVATE_KEY: ANVIL_KEY } },
  );
  const record = JSON.parse(readFileSync(join(recordDir, '31337.json'), 'utf8'));
  addresses.sponsorshipPaymasterImplementation = record.contracts.paymasterImplementation.address;
} finally {
  rmSync(recordDir, { recursive: true, force: true });
}

const dumped = await rpc('anvil_dumpState');
let bytes = Buffer.from(dumped.slice(2), 'hex');
if (bytes[0] === 0x1f && bytes[1] === 0x8b) bytes = gunzipSync(bytes);
writeFileSync(statePath, JSON.stringify(JSON.parse(bytes.toString('utf8'))));
writeFileSync(addressesPath, `${JSON.stringify(addresses, null, 2)}\n`);
console.log(`Upgraded local paymaster ${addresses.sponsorshipPaymaster} to ${addresses.sponsorshipPaymasterImplementation}`);
