/**
 * Deploys EntryPoint v0.7 onto a running anvil and copies its runtime code to the
 * canonical address (0x0000000071727De22E5E9d8BAf0edAc6f37da032) via anvil_setCode.
 * EntryPoint has no constructor state, so code-copy is equivalent to a real deploy.
 * Replaces the vendor/account-abstraction yarn flow for local devnets.
 */
import { createRequire } from 'node:module';

// the artifact lives in the contracts workspace's dependency tree
const require = createRequire(new URL('../../packages/contracts/package.json', import.meta.url));
const RPC = process.env.RPC_URL ?? 'http://127.0.0.1:8545';
const CANONICAL = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';
// anvil default account 0
const DEPLOYER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

const artifact = require('@account-abstraction/contracts/artifacts/EntryPoint.json');

let id = 0;
async function rpc(method, params) {
  const response = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
  });
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

const existing = await rpc('eth_getCode', [CANONICAL, 'latest']);
if (existing && existing !== '0x') {
  console.log('EntryPoint already present at canonical address');
  process.exit(0);
}

const txHash = await rpc('eth_sendTransaction', [{ from: DEPLOYER, data: artifact.bytecode, gas: '0x7a1200' }]);
let receipt = null;
for (let i = 0; i < 60 && !receipt; i++) {
  receipt = await rpc('eth_getTransactionReceipt', [txHash]);
  if (!receipt) await new Promise((resolve) => setTimeout(resolve, 250));
}
if (!receipt?.contractAddress) throw new Error('EntryPoint deploy failed');

const code = await rpc('eth_getCode', [receipt.contractAddress, 'latest']);
await rpc('anvil_setCode', [CANONICAL, code]);
console.log(`EntryPoint v0.7 code installed at ${CANONICAL} (${(code.length - 2) / 2} bytes)`);
