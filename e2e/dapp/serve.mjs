// Minimal dApp fixture server: bundles the THIN SDK only (acceptance: the dApp bundle
// carries zero WebAuthn/credential/bundler code) and serves a page exercising it.
import * as esbuild from 'esbuild';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.DAPP_PORT ?? 4400);

const bundle = await esbuild.build({
  entryPoints: [path.join(dir, 'main.ts')],
  bundle: true,
  format: 'esm',
  write: false,
  define: {
    'process.env.WALLET_URL': JSON.stringify(process.env.WALLET_URL ?? 'http://wallet.localtest.me:8081'),
    'process.env.RPC_URL': JSON.stringify(process.env.RPC_URL ?? 'http://localhost:8545'),
    'process.env.CHAIN_ID': JSON.stringify(process.env.CHAIN_ID ?? '31337'),
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
