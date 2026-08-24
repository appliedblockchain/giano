/**
 * Generates the baked devnet state: `e2e/devnet/state.json` + `e2e/devnet/addresses.json`.
 *
 * One command, deterministic, offline. Everything the demo and e2e stacks need in order to
 * *actually sponsor a transaction* has to exist in this state before anvil boots, because the
 * alternative — provisioning at bring-up — is how a stack comes up looking healthy and refusing
 * every sponsorship.
 *
 * What it bakes:
 *   - EntryPoint v0.7 at its canonical address
 *   - the FreshCryptoLib P-256 verifier. The pinned anvil provides the RIP-7212 precompile natively,
 *     so this is belt-and-braces — but it makes the state work on an older anvil too, and
 *     `giano-doctor` treats missing P-256 verification as a critical failure
 *   - the Giano wallet factory and implementation
 *   - the permissive test paymaster and the demo ERC-20 (fixtures whose subject is not sponsorship
 *     keep using these, so a sponsorship rule change cannot break a token-transfer test)
 *   - the **production** paymaster: implementation, proxy, initialised, staked, with the demo
 *     tenants registered and generously funded
 *
 * Determinism comes from anvil's fixed accounts and free ETH: no faucet, no external funding, no
 * credentials, and identical results on a developer machine and in CI.
 *
 * The demo tenants' *sponsorship rules* are deliberately NOT baked here. Those go in through the
 * real admin API at bring-up (`e2e/devnet/provision-sponsorship.mjs`), so there is no dev-only
 * seeding path that would then have to be disabled in production.
 *
 * **The anvil that writes this state must be the anvil that loads it.** `--load-state` parsing is
 * version-specific (the transaction-type encoding changed between 1.4 and 1.7), so a state dumped
 * by whatever anvil happens to be on a developer's PATH may be unloadable by the pinned image the
 * deployment runs — and the failure appears as anvil exiting during `docker compose up`, with every
 * other service failing after it. The version is therefore checked, not assumed.
 *
 * Usage:  pnpm --filter @appliedblockchain/giano-e2e devnet:generate
 *
 * That target starts the pinned image for you. To drive it against an anvil you started yourself,
 * run `node e2e/devnet/generate-state.mjs` with that anvil on `RPC_URL` — it will refuse if the
 * version does not match `PINNED_ANVIL_VERSION` below.
 */
import { execFileSync } from 'node:child_process';
import { gunzipSync } from 'node:zlib';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(dir, '..', '..');
const contractsDir = path.join(repoRoot, 'packages', 'contracts');
const RPC = process.env.RPC_URL ?? 'http://127.0.0.1:8545';

/**
 * The anvil version `deploy/docker-compose.e2e.yml` and `services/devnet/Dockerfile` run. Keep the
 * three in step: a state this script writes with any other version may not load there.
 */
const PINNED_ANVIL_VERSION = '1.7.1';

/** Anvil's deterministic accounts. Never used anywhere real, and the reason this needs no secret. */
const ANVIL = {
  deployer: { address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', key: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' },
  /** The sponsorship signing key. Also alto's utility key — deliberate: one fewer moving part. */
  sponsorshipSigner: { address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8', key: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' },
  stockWithdraw: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
  byoWithdraw: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
};

/**
 * Tenant ids are UUIDs in the database and `bytes16` on chain, and the paymaster has to be
 * registered against the *same* ids the wallet-api will send. Fixed here and referenced from
 * `TENANTS_SEED`, so the two cannot drift.
 */
export const DEMO_TENANTS = [
  { slug: 'stock', id: '11111111-1111-4111-8111-111111111111', withdrawAddress: ANVIL.stockWithdraw, fundEth: '50' },
  { slug: 'byo', id: '22222222-2222-4222-8222-222222222222', withdrawAddress: ANVIL.byoWithdraw, fundEth: '50' },
];

let rpcId = 0;
async function rpc(method, params = []) {
  const response = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  const body = await response.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

function run(command, args, options = {}) {
  console.log(`\n$ ${command} ${args.join(' ')}`);
  execFileSync(command, args, { stdio: 'inherit', cwd: options.cwd ?? repoRoot, env: { ...process.env, ...options.env } });
}

async function waitForRpc(attempts = 60) {
  for (let i = 0; i < attempts; i++) {
    try {
      await rpc('eth_chainId');
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
  throw new Error(`no JSON-RPC at ${RPC} — start anvil first (anvil --host 127.0.0.1)`);
}

await waitForRpc();

const clientVersion = await rpc('web3_clientVersion');
if (!String(clientVersion).includes(PINNED_ANVIL_VERSION) && !process.env.ALLOW_ANVIL_VERSION_MISMATCH) {
  throw new Error(
    `this anvil is "${clientVersion}" but the deployment pins anvil ${PINNED_ANVIL_VERSION}.\n\n` +
      '`--load-state` parsing is version-specific, so a state dumped here would very likely fail to\n' +
      'load in the pinned image — and that failure surfaces as anvil exiting during `docker compose\n' +
      'up`, taking every other service with it.\n\n' +
      'Run `pnpm --filter @appliedblockchain/giano-e2e devnet:generate`, which starts the pinned\n' +
      'image for you. Set ALLOW_ANVIL_VERSION_MISMATCH=1 only if you have verified the state loads.',
  );
}

console.log(`Generating devnet state against ${RPC} (${clientVersion})`);

// ── 1. EntryPoint ─────────────────────────────────────────────────────────────
run('node', [path.join(dir, 'setup-entrypoint.mjs')]);

// ── 2. P-256 verification ─────────────────────────────────────────────────────
// Baked rather than assumed: whether anvil offers the RIP-7212 precompile depends on its build and
// default hardfork (the pinned 1.7.1 does; older builds do not), and a devnet where passkey
// signatures cannot verify fails in a way that looks like a wallet bug. The verifier is
// deterministic (CREATE2), so baking it keeps the state reproducible either way.
run('npx', ['hardhat', 'run', 'scripts/p256_deploy.ts', '--network', 'localhost'], { cwd: contractsDir });

// ── 3. Wallet factory, implementation and the testing fixtures ────────────────
// The deployments directory is wiped first so Ignition re-executes rather than reconciling
// against a journal from a previous run's chain.
fs.rmSync(path.join(contractsDir, 'ignition', 'deployments', 'chain-31337'), { recursive: true, force: true });
run('pnpm', ['--filter', '@appliedblockchain/giano-contracts', 'hh:deploy', '--network', 'localhost']);
run('pnpm', ['--filter', '@appliedblockchain/giano-contracts', 'hh:deploy:testing', '--network', 'localhost']);

// ── 4. The production paymaster ───────────────────────────────────────────────
run('pnpm', ['--filter', '@appliedblockchain/giano-contracts', 'hh:deploy:paymaster', '--network', 'localhost']);

const deployed = JSON.parse(
  fs.readFileSync(path.join(contractsDir, 'ignition', 'deployments', 'chain-31337', 'deployed_addresses.json'), 'utf8'),
);

const sponsorshipPaymaster = deployed['GianoPaymaster#SponsorshipPaymaster'];
if (!sponsorshipPaymaster) throw new Error('the paymaster module did not report a proxy address');

/*
 * Roles: every one of them on the deployer EOA, and the timelock topology D13/D14 describe is
 * deliberately absent.
 *
 * That is a *development* shape, not a shortcut being smuggled in. A suite that had to wait out a
 * real timelock delay to test `pause()` would be untestable, and the multi-party control and
 * published exit delay are production properties asserted by `giano-doctor chain --role-admin`
 * and by the runbook — not by this file.
 */
run(
  'pnpm',
  [
    '--filter',
    '@appliedblockchain/giano-contracts',
    'provision:paymaster',
    '--',
    '--paymaster',
    sponsorshipPaymaster,
    '--grant-all-to',
    ANVIL.deployer.address,
    '--signer',
    ANVIL.sponsorshipSigner.address,
    '--stake-eth',
    '1',
    '--unstake-delay',
    '86400',
    ...DEMO_TENANTS.flatMap((tenant) => ['--tenant', `${tenant.id}:${tenant.withdrawAddress}:${tenant.slug}:${tenant.fundEth}`]),
  ],
  { env: { RPC_URL: RPC, DEPLOYER_PRIVATE_KEY: ANVIL.deployer.key } },
);

// ── 5. Verify before baking ───────────────────────────────────────────────────
// A state that bakes a half-provisioned paymaster is worse than no state at all: every stack
// built on it comes up looking fine and refuses every sponsorship.
run(
  'pnpm',
  [
    '--filter',
    '@appliedblockchain/giano-contracts',
    'run',
    'doctor',
    'chain',
    '--rpc',
    RPC,
    '--chain-id',
    '31337',
    '--factory',
    deployed['GianoAccountFactory#GianoSmartWalletFactory'],
    '--sponsorship-paymaster',
    sponsorshipPaymaster,
    '--tenants',
    DEMO_TENANTS.map((t) => `0x${t.id.replace(/-/g, '')}`).join(','),
    '--role-admin',
    ANVIL.deployer.address,
    '--signers',
    ANVIL.sponsorshipSigner.address,
  ],
);

// ── 6. Bake ───────────────────────────────────────────────────────────────────
const state = await rpc('anvil_dumpState');
fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify(JSON.parse(decodeState(state)), null, 0));

const addresses = {
  chainId: 31337,
  entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
  factory: deployed['GianoAccountFactory#GianoSmartWalletFactory'],
  implementation: deployed['GianoAccountFactory#GianoSmartWallet'],
  sponsorshipPaymaster,
  sponsorshipPaymasterImplementation: deployed['GianoPaymaster#GianoPaymaster'],
  sponsorshipSigner: ANVIL.sponsorshipSigner.address,
  sponsorshipSignerKey: ANVIL.sponsorshipSigner.key,
  paymasterRoleAdmin: ANVIL.deployer.address,
  testPaymaster: deployed['Testing#PermissivePaymaster'],
  testErc20: deployed['Testing#PrivateERC20'],
  tenants: DEMO_TENANTS,
};
fs.writeFileSync(path.join(dir, 'addresses.json'), `${JSON.stringify(addresses, null, 2)}\n`);

console.log('\nWrote e2e/devnet/state.json and e2e/devnet/addresses.json');
console.log(`  sponsorship paymaster: ${sponsorshipPaymaster}`);
console.log(`  signer:                ${ANVIL.sponsorshipSigner.address}`);
for (const tenant of DEMO_TENANTS) console.log(`  tenant ${tenant.slug}: ${tenant.id} funded ${tenant.fundEth} ETH`);

/**
 * `anvil_dumpState` returns hex-encoded gzip in some versions and raw JSON in others. Handling
 * both keeps this working across the pinned image and a developer's newer local foundry.
 */
function decodeState(dumped) {
  if (typeof dumped !== 'string') return JSON.stringify(dumped);
  if (dumped.startsWith('{')) return dumped;
  const buffer = Buffer.from(dumped.replace(/^0x/, ''), 'hex');
  // gzip magic
  if (buffer[0] === 0x1f && buffer[1] === 0x8b) {
    return gunzipSync(buffer).toString('utf8');
  }
  return buffer.toString('utf8');
}
