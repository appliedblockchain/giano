#!/usr/bin/env node
// Collect every environment the repository starts the three SPA images with, as parity fixtures:
//   fixtures/<image>/<case>/env.json
//
// Sources: each deploy/docker-compose.*.yml (resolved by `docker compose config`, with a
// placeholder for any variable the file insists on), the Helm chart's defaults (hand-written —
// there is no helm in CI — and kept next to the template they mirror), and the error cases each
// entrypoint promises to refuse. Re-run after changing a compose file; commit the result.

import { execFileSync } from 'node:child_process';
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const FIXTURES = join(HERE, 'fixtures');

export const IMAGES = {
  'wallet-web': 'services/wallet-web',
  'paymaster-admin': 'services/paymaster-admin',
  'custom-example': 'services/custom-example',
};

// A value of the right shape for a variable a compose file requires, so the fixture renders like a
// real deployment would rather than tripping over a non-numeric chain id.
function placeholder(name) {
  if (/(^|_)ID$/.test(name)) return '84532';
  if (/ADDRESS$/.test(name)) return `0x${'ab'.repeat(20)}`;
  if (/URL$/.test(name)) return `https://${name.toLowerCase().replace(/_/g, '-')}.example`;
  if (/HOST$/.test(name)) return `${name.toLowerCase().replace(/_/g, '-')}.example`;
  return `placeholder-${name.toLowerCase()}`;
}

function composeServices(file) {
  const env = { ...process.env };
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      const out = execFileSync('docker', ['compose', '-f', file, 'config', '--format', 'json'], {
        cwd: ROOT,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      return JSON.parse(out.toString()).services;
    } catch (err) {
      const m = String(err.stderr).match(/required variable (\w+) is missing/);
      if (!m) throw err;
      env[m[1]] = placeholder(m[1]);
    }
  }
  throw new Error(`${file}: too many required variables`);
}

function fromCompose() {
  const cases = [];
  const files = readdirSync(join(ROOT, 'deploy')).filter((f) => /^docker-compose\..*\.yml$/.test(f));
  for (const file of files) {
    const services = composeServices(join('deploy', file));
    for (const [svc, def] of Object.entries(services)) {
      const df = def.build?.dockerfile ?? '';
      const image = Object.keys(IMAGES).find((k) => df.startsWith(IMAGES[k]));
      if (!image) continue;
      const env = Object.fromEntries(Object.entries(def.environment ?? {}).filter(([, v]) => v !== null));
      cases.push({ image, name: `${file.replace(/^docker-compose\.|\.yml$/g, '')}--${svc}`, env });
    }
  }
  return cases;
}

// deploy/helm/giano/templates/wallet-web.yaml with values.yaml defaults, single-chain branch.
const helm = [
  {
    image: 'wallet-web',
    name: 'helm-defaults',
    env: {
      GIANO_CHAIN_ID: '8453',
      GIANO_WALLET_API_UPSTREAM: 'http://giano-wallet-api:8080',
      GIANO_RP_ID: '',
      GIANO_ALLOWED_DAPP_ORIGINS: '[]',
      GIANO_BRAND_NAME: 'Giano Wallet',
    },
  },
];

const CHAINS_A = '[{"chainId":31337,"name":"Devnet A","rpcUrl":"http://rpc.example"}]';

// What each entrypoint must refuse, plus inputs that exercise quoting and optional branches.
const edge = [
  { image: 'wallet-web', name: 'err-no-upstream', env: { GIANO_CHAIN_ID: '8453' } },
  { image: 'wallet-web', name: 'err-no-chain', env: { GIANO_WALLET_API_UPSTREAM: 'http://api:8080' } },
  {
    image: 'wallet-web',
    name: 'err-chains-and-chain-id',
    env: { GIANO_WALLET_API_UPSTREAM: 'http://api:8080', GIANO_CHAINS: '[]', GIANO_CHAIN_ID: '1' },
  },
  {
    image: 'wallet-web',
    name: 'single-chain-test-paymaster',
    env: {
      GIANO_WALLET_API_UPSTREAM: 'http://api:8080',
      GIANO_CHAIN_ID: '84532',
      GIANO_PAYMASTER_ADDRESS: '0x00000000000000000000000000000000000000aa',
      GIANO_RPC_URL: 'https://rpc.example/key',
      GIANO_BUNDLER_URL: 'https://bundler.example',
      GIANO_NATIVE_CURRENCY_SYMBOL: 'SDR',
    },
  },
  { image: 'paymaster-admin', name: 'err-nothing', env: {} },
  { image: 'paymaster-admin', name: 'err-no-rpc', env: { GIANO_CHAIN_ID: '1' } },
  { image: 'paymaster-admin', name: 'err-malformed-json', env: { GIANO_DEPLOYMENTS: '[{"name":' } },
  {
    image: 'paymaster-admin',
    name: 'single-keyed-rpc',
    env: {
      GIANO_CHAIN_ID: '8453',
      GIANO_RPC_URL: 'https://base.example/v2/SECRETKEY',
      GIANO_PAYMASTER_ADDRESS: '0x00000000000000000000000000000000000000bb',
    },
  },
  {
    image: 'paymaster-admin',
    name: 'multi-proxy-off',
    env: {
      GIANO_RPC_PROXY: 'false',
      GIANO_DEPLOYMENTS:
        '[{"name":"A","chainId":1,"rpcUrl":"https://a.example/rpc","bundlerUrl":"https://hidden","refreshSeconds":30},' +
        '{"name":"B","chainId":2,"rpcUrl":"/rpc/2","walletRpcUrl":"https://public.example"}]',
    },
  },
  {
    image: 'paymaster-admin',
    name: 'multi-proxy-bare-host',
    env: { GIANO_DEPLOYMENTS: '[{"name":"A","chainId":1,"rpcUrl":"http://anvil:8545"}]' },
  },
  { image: 'custom-example', name: 'err-no-wallet', env: { GIANO_CHAINS: CHAINS_A } },
  { image: 'custom-example', name: 'err-no-chains', env: { GIANO_WALLET_URL: 'https://w.example' } },
  {
    image: 'custom-example',
    name: 'err-chains-and-chain-id',
    env: { GIANO_WALLET_URL: 'https://w.example', GIANO_CHAINS: CHAINS_A, GIANO_CHAIN_ID: '1' },
  },
  { image: 'custom-example', name: 'err-not-array', env: { GIANO_WALLET_URL: 'https://w.example', GIANO_CHAINS: '{}' } },
  // bracketed but not JSON: the previous script let this through to a config.js that does not parse
  { image: 'custom-example', name: 'err-malformed-json', env: { GIANO_WALLET_URL: 'https://w.example', GIANO_CHAINS: '[ not json ]' } },
  {
    image: 'custom-example',
    name: 'deprecated-scalars-two-chains',
    env: {
      GIANO_WALLET_URL: 'https://w.example',
      GIANO_CHAIN_ID: '31337',
      GIANO_RPC_URL: 'http://rpc-a.example',
      GIANO_CHAIN_B_ID: '31338',
      GIANO_CHAIN_B_NAME: 'Devnet "B"',
      GIANO_RPC_B_URL: 'http://rpc-b.example',
      GIANO_TEST_ERC20: '0x00000000000000000000000000000000000000cc',
      GIANO_RPC_UPSTREAM: 'https://keyed.example/abc',
    },
  },
  {
    image: 'custom-example',
    name: 'err-deprecated-b-without-rpc',
    env: {
      GIANO_WALLET_URL: 'https://w.example',
      GIANO_CHAIN_ID: '31337',
      GIANO_RPC_URL: 'http://rpc-a.example',
      GIANO_CHAIN_B_ID: '31338',
    },
  },
  {
    image: 'custom-example',
    name: 'quoting-and-upstreams',
    env: {
      GIANO_WALLET_URL: "https://w.example/it's",
      GIANO_OTHER_WALLET_URL: 'https://other.example',
      GIANO_APP_LABEL: 'O\'Brien\'s $HOME \\ "demo"',
      GIANO_CHAINS:
        '[\n  { "chainId": 1, "name": "One", "rpcUrl": "/rpc/1" },\n  { "chainId": 2, "name": "Two", "rpcUrl": "https://two.example/path?key=1" }\n]',
      GIANO_RPC_UPSTREAM_1: 'https://keyed.example/v2/SECRET',
    },
  },
  {
    image: 'custom-example',
    name: 'csp-override',
    env: { GIANO_WALLET_URL: 'https://w.example', GIANO_CHAINS: CHAINS_A, GIANO_CSP_CONNECT_SRC: 'https://x.example' },
  },
];

function main() {
  const cases = [...fromCompose(), ...helm, ...edge];
  for (const image of Object.keys(IMAGES)) {
    rmSync(join(FIXTURES, image), { recursive: true, force: true });
  }
  for (const c of cases) {
    const dir = join(FIXTURES, c.image, c.name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'env.json'), `${JSON.stringify(c.env, null, 2)}\n`);
  }
  console.log(`wrote ${cases.length} fixtures`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
