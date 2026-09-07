// Minimal dApp fixture server: bundles the THIN SDK only (acceptance: the dApp bundle
// carries zero WebAuthn/credential/bundler code) and serves a page exercising it.
import * as esbuild from 'esbuild';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ORIGINS, portOf } from '../origins.mjs';

const dir = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.DAPP_PORT ?? portOf('app'));

const addresses = JSON.parse(fs.readFileSync(path.join(dir, '..', 'devnet', 'addresses.json'), 'utf8'));

const bundle = await esbuild.build({
  entryPoints: [path.join(dir, 'main.ts')],
  bundle: true,
  format: 'esm',
  write: false,
  define: {
    'process.env.WALLET_URL': JSON.stringify(process.env.WALLET_URL ?? ORIGINS.wallet),
    // A name, not a port: the browser reaches anvil through portless like everything else.
    'process.env.RPC_URL': JSON.stringify(process.env.RPC_URL ?? ORIGINS.rpc),
    'process.env.CHAIN_ID': JSON.stringify(process.env.CHAIN_ID ?? '31337'),
    // The second chain (MC-121): a real provider constructed for it, negotiating it with
    // the wallet origin — never a simulation (MC-122).
    'process.env.RPC_B_URL': JSON.stringify(process.env.RPC_B_URL ?? ORIGINS.rpcB),
    'process.env.CHAIN_B_ID': JSON.stringify(process.env.CHAIN_B_ID ?? '31338'),
    'process.env.TEST_ERC20_ADDRESS': JSON.stringify(process.env.TEST_ERC20_ADDRESS ?? addresses.testErc20),
  },
});
const js = bundle.outputFiles[0].text;

if (js.includes('navigator.credentials')) {
  throw new Error('E2E invariant violated: the thin-SDK dApp bundle contains navigator.credentials');
}

const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');

http
  .createServer((req, res) => {
    if (req.url === '/main.js') {
      res.setHeader('content-type', 'text/javascript');
      res.end(js);
      return;
    }
    // COOP deliberately unset: the wallet popup needs window.opener
    res.setHeader('content-type', 'text/html');
    res.end(html);
  })
  .listen(port, () => console.log(`dapp fixture on :${port} (bundle: ${(js.length / 1024).toFixed(0)} KB, no navigator.credentials)`));
