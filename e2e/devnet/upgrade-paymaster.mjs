/** Upgrade the baked local paymaster through UUPS, preserving its proxy and funded tenants.
 * Run on a fresh pinned anvil via `pnpm devnet:upgrade:paymaster`.
 * This script loads and writes local fixture state only; it refuses non-Anvil nodes.
 */
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { gunzipSync, gzipSync } from 'node:zlib';
const require = createRequire(new URL('../../packages/contracts/package.json', import.meta.url));
const { Contract, ContractFactory, JsonRpcProvider, Wallet } = require('ethers');
const provider = new JsonRpcProvider(process.env.RPC_URL ?? 'http://127.0.0.1:18545');
const version = await provider.send('web3_clientVersion', []);
if (!version.includes('anvil') || !version.includes('1.7.1')) throw new Error('requires the pinned local Anvil 1.7.1');
if ((await provider.getNetwork()).chainId !== 31337n) throw new Error('requires local chain 31337');
const statePath = new URL('./state.json', import.meta.url);
const addressesPath = new URL('./addresses.json', import.meta.url);
const addresses = JSON.parse(readFileSync(addressesPath, 'utf8'));
// Anvil accepts its compressed dump format. Compress before hex encoding so the
// growing fixture stays below the JSON-RPC request-size limit.
await provider.send('anvil_loadState', [`0x${gzipSync(readFileSync(statePath)).toString('hex')}`]);
const signer = new Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider);
const artifact = JSON.parse(readFileSync(new URL('../../packages/contracts/artifacts/src/paymaster/GianoPaymaster.sol/GianoPaymaster.json', import.meta.url), 'utf8'));
const implementation = await new ContractFactory(artifact.abi, artifact.bytecode, signer).deploy();
await implementation.waitForDeployment();
const paymaster = new Contract(addresses.sponsorshipPaymaster, artifact.abi, signer);
await (await paymaster.upgradeToAndCall(await implementation.getAddress(), '0x')).wait();
const dumped = await provider.send('anvil_dumpState', []);
let bytes = Buffer.from(dumped.slice(2), 'hex');
if (bytes[0] === 0x1f && bytes[1] === 0x8b) bytes = gunzipSync(bytes);
writeFileSync(statePath, JSON.stringify(JSON.parse(bytes.toString('utf8'))));
addresses.sponsorshipPaymasterImplementation = await implementation.getAddress();
writeFileSync(addressesPath, `${JSON.stringify(addresses, null, 2)}\n`);
console.log(`Upgraded local paymaster ${addresses.sponsorshipPaymaster} to ${addresses.sponsorshipPaymasterImplementation}`);
