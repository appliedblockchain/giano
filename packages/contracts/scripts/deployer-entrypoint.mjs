// giano-contracts-deployer: one-shot Ignition CREATE2 deploy from env, emitting the address registry
// JSON. Idempotent via the Ignition journal.
//
// The image runs on a Docker Hardened Image runtime (ABIP-2): no shell, no pnpm. So every step is a
// direct `node` invocation, without a shell — Hardhat through its own CLI, with hardhat.deploy.config.ts
// (which does not load hardhat-foundry: that plugin shells out to forge), and the TypeScript scripts
// through tsx (in place of ts-node, per the ABIP-2 migration guide). Each step is a child process, as each `pnpm` call was, so the Ignition journal and
// addresses.ts the next step reads are on disk before it starts.
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

function required(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`${name} is required`);
    process.exit(1);
  }
  return value;
}

const RPC_URL = required('RPC_URL');
const CHAIN_ID = required('CHAIN_ID');
const DEPLOYER_PRIVATE_KEY = required('DEPLOYER_PRIVATE_KEY');
const DEPLOY_TESTING = process.env.DEPLOY_TESTING || 'false';
const OUT_DIR = process.env.OUT_DIR || '/out';
const NETWORK = process.env.HARDHAT_NETWORK || 'base';

// hardhat.base.ts reads these; the same key/url drive whichever network is selected
const env = {
  ...process.env,
  BASE_RPC_URL: RPC_URL,
  BASE_SEPOLIA_RPC_URL: RPC_URL,
  SDR_TESTNET_RPC_URL: RPC_URL,
  BASE_PRIVATE_KEY: DEPLOYER_PRIVATE_KEY,
  SDR_PRIVATE_KEY: DEPLOYER_PRIVATE_KEY,
  CHAIN_ID,
  OUT_DIR,
};
// --network is passed explicitly; leaving HARDHAT_NETWORK set as well would be read a second time
delete env.HARDHAT_NETWORK;

function run(label, args) {
  console.log(`> ${label}`);
  const res = spawnSync(process.execPath, args, { cwd: ROOT, env, stdio: 'inherit', shell: false });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    console.error(`${label} failed (exit ${res.status ?? res.signal})`);
    process.exit(res.status ?? 1);
  }
}

const hardhat = require.resolve('hardhat/internal/cli/bootstrap.js');
const ignition = (module) => [
  hardhat, '--config', 'hardhat.deploy.config.ts', '--network', NETWORK,
  'ignition', 'deploy', module, '--strategy', 'create2',
];

// CREATE2 keeps addresses identical across chains for identical bytecode; the Ignition journal makes
// re-runs idempotent (no double-deploy).
run('hh:deploy', ignition('ignition/modules/GianoAccountFactory.ts'));
if (DEPLOY_TESTING === 'true') run('hh:deploy:testing', ignition('ignition/modules/Testing.ts'));
// tsx's CommonJS hook, not `--import tsx`: this package is "type": "commonjs" and the scripts use
// __dirname, which ts-node provided and the ESM entry point does not.
run('gen:addresses', ['--require', 'tsx/cjs', 'scripts/generate-addresses.ts']);
// emit the registry entry for this chain in the shared schema
run('registry', ['--require', 'tsx/cjs', 'scripts/emit-registry.ts']);
