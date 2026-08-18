// BYO-wallet fixture server: the SECOND tenant's wallet origin. Serves a tenant-built
// (framework-free) wallet SPA and reverse-proxies /api, /.well-known/webauthn, /rpc and
// /bundler — the same shape a real tenant would deploy with nginx/CloudFront, host-side
// so the e2e stack needs no extra image.
import * as esbuild from 'esbuild';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.BYO_WALLET_PORT ?? 8082);

const walletApiUpstream = process.env.WALLET_API_UPSTREAM ?? 'http://127.0.0.1:8080';
const rpcUpstream = process.env.RPC_UPSTREAM ?? 'http://127.0.0.1:8545';
const bundlerUpstream = process.env.BUNDLER_UPSTREAM ?? 'http://127.0.0.1:4337';

const addresses = JSON.parse(fs.readFileSync(path.join(dir, '..', 'devnet', 'addresses.json'), 'utf8'));

const bundle = await esbuild.build({
  entryPoints: [path.join(dir, 'src', 'main.ts')],
  bundle: true,
  format: 'esm',
  write: false,
  define: {
    'process.env.CHAIN_ID': JSON.stringify(process.env.CHAIN_ID ?? String(addresses.chainId)),
    'process.env.FACTORY_ADDRESS': JSON.stringify(process.env.FACTORY_ADDRESS ?? addresses.factory),
    'process.env.PAYMASTER_ADDRESS': JSON.stringify(process.env.PAYMASTER_ADDRESS ?? addresses.paymaster),
    'process.env.ALLOWED_DAPP_ORIGINS': JSON.stringify(process.env.BYO_ALLOWED_DAPP_ORIGINS ?? '["http://app-byo.localhost:4401"]'),
  },
});
const js = bundle.outputFiles[0].text;

// Inverse of the dApp fixture's invariant: the WALLET bundle must contain the ceremony
// code — proof the trust boundary (WebAuthn, signing, consent) sits on the wallet origin.
if (!js.includes('navigator.credentials')) {
  throw new Error('E2E invariant violated: the BYO wallet bundle is missing navigator.credentials');
}

const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(dir, 'styles.css'), 'utf8');

/**
 * Minimal reverse proxy. Two headers are load-bearing for tenant resolution:
 *  - `Origin` is forwarded untouched (spread) — wallet-api resolves ceremony tenants by it;
 *  - `Host` is explicitly preserved as the browser sent it (Node would otherwise rewrite
 *    it to the upstream) — /.well-known/webauthn resolves its tenant by Host.
 */
function proxy(req, res, upstreamBase, upstreamPath) {
  const upstream = new URL(upstreamBase);
  const proxyReq = http.request(
    {
      hostname: upstream.hostname,
      port: upstream.port,
      path: upstreamPath,
      method: req.method,
      headers: {
        ...req.headers,
        host: req.headers.host,
        'x-forwarded-host': req.headers.host ?? '',
        'x-forwarded-proto': 'http',
      },
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
      proxyRes.pipe(res);
    },
  );
  proxyReq.on('error', (error) => {
    res.statusCode = 502;
    res.end(`upstream error: ${error.message}`);
  });
  req.pipe(proxyReq);
}

http
  .createServer((req, res) => {
    const url = req.url ?? '/';
    if (url.startsWith('/api/') || url === '/api') {
      return proxy(req, res, walletApiUpstream, url.replace(/^\/api/, '') || '/');
    }
    if (url === '/.well-known/webauthn') {
      return proxy(req, res, walletApiUpstream, url);
    }
    if (url === '/rpc') {
      return proxy(req, res, rpcUpstream, '/');
    }
    if (url === '/bundler') {
      return proxy(req, res, bundlerUpstream, '/');
    }
    if (url === '/main.js') {
      res.setHeader('content-type', 'text/javascript');
      return res.end(js);
    }
    if (url === '/styles.css') {
      res.setHeader('content-type', 'text/css');
      return res.end(css);
    }
    // COOP deliberately unset: the popup needs window.opener
    res.setHeader('content-type', 'text/html');
    res.end(html);
  })
  .listen(port, () => console.log(`BYO wallet fixture on :${port} (api→${walletApiUpstream}, rpc→${rpcUpstream}, bundler→${bundlerUpstream})`));
