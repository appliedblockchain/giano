// BYO-wallet reference server: the SECOND tenant's wallet origin. Serves a tenant-built
// (framework-free) wallet SPA and reverse-proxies /api and /.well-known/webauthn to wallet-api —
// the whole serving contract a real tenant reproduces with nginx/CloudFront. Chain reads and
// the bundler both travel through /api (wallet-api's /v1/rpc and /v1/bundler relays), so this
// origin holds no node or bundler URL.
//
// It runs in two contexts, and everything conditional below is because of that (§16.5):
//
//   host-side, in the e2e stack   `pnpm -F @appliedblockchain/giano-e2e wallet-byo`, with
//                                 ../origins.mjs and ../devnet/addresses.json present. Every
//                                 default comes from those, so the fixture needs no env.
//   containerised, as a service   neither file exists — they are devnet artefacts with no
//                                 business in an image — so every value comes from the
//                                 environment and anything missing is a loud failure.
//
// The start-up esbuild bundle is deliberately kept: it is why this image is
// environment-independent without any of wallet-web's /config.json machinery, and it is the
// cheapest correct answer for a small SPA.
import * as esbuild from 'esbuild';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));

// --- devnet context detection -------------------------------------------------------------
// Both of these are e2e fixtures. Importing/reading them unconditionally is what made this
// file uncontainerisable: the process crashed at start-up on files that only exist in a
// checkout. Absent, every default they used to supply becomes a required variable instead.

/** ../origins.mjs — the portless name/port table. Absent in a container. */
let origins = null;
try {
  origins = await import('../origins.mjs');
} catch {
  // not a devnet checkout; env supplies the endpoints
}

/** ../devnet/addresses.json — the baked devnet contract addresses. Absent in a container. */
let devnet = null;
try {
  devnet = JSON.parse(fs.readFileSync(path.join(dir, '..', 'devnet', 'addresses.json'), 'utf8'));
} catch {
  // not a devnet checkout; env supplies the addresses
}

/** Required outside a devnet checkout, where there is no fixture default to fall back to. */
function required(value, name, why) {
  if (value === undefined || value === null || value === '') {
    console.error(`FATAL: ${name} is required — ${why}`);
    console.error('       (it defaults only in an e2e checkout, from ../origins.mjs or ../devnet/addresses.json)');
    process.exit(1);
  }
  return value;
}

// the port to listen on, e.g. 8080
const port = Number(process.env.BYO_WALLET_PORT ?? (origins ? origins.portOf('wallet-byo') : 8080));

// wallet-api base URL, e.g. http://wallet-api:8080. Loopback rather than a portless name in the
// e2e checkout: this is a server-to-server hop, and the proxy below forwards the browser's Host
// untouched (wallet-api resolves the tenant from it) — sending that Host back through portless
// would route the request straight back here.
const walletApiUpstream = required(
  process.env.WALLET_API_UPSTREAM ?? (origins ? origins.loopbackOf('api') : undefined),
  'WALLET_API_UPSTREAM',
  'the wallet-api this origin proxies /api and /.well-known/webauthn to',
);

// --- chain configuration ------------------------------------------------------------------
// Only ids and names: every endpoint is wallet-api's. The second chain falls away unless asked
// for — implicitly in a devnet checkout, which keeps the two-chain e2e suite (MC-129) passing
// with no environment at all.
const chainId = required(process.env.CHAIN_ID ?? devnet?.chainId, 'CHAIN_ID', 'the chain this wallet origin serves, e.g. 84532');
const chainBId = process.env.CHAIN_B_ID ?? (devnet ? '31338' : ''); // second chain id, or unset for single-chain
const chainName = process.env.CHAIN_NAME ?? (devnet ? 'Devnet A' : `chain ${chainId}`);
const chainBName = process.env.CHAIN_B_NAME ?? (devnet ? 'Devnet B' : `chain ${chainBId}`);

// The SPA passes this straight to createGianoProvider. §14.5 says it defaults from the
// contracts registry, but this bundle has no registry dependency — so outside a devnet
// checkout it must be supplied.
const factoryAddress = required(
  process.env.FACTORY_ADDRESS ?? devnet?.factory,
  'FACTORY_ADDRESS',
  'the account factory this wallet derives addresses from, e.g. 0x26dC…',
);

const allowedDappOrigins = required(
  process.env.BYO_ALLOWED_DAPP_ORIGINS ?? (origins ? JSON.stringify([origins.ORIGINS.dappByo]) : undefined),
  'BYO_ALLOWED_DAPP_ORIGINS',
  'a JSON array of the dApp origins allowed to connect, e.g. ["https://app.example"] — this tenant\'s own allowlist (R9)',
);

const bundle = await esbuild.build({
  entryPoints: [path.join(dir, 'src', 'main.ts')],
  bundle: true,
  format: 'esm',
  write: false,
  // Every `process.env.X` the SPA reads must appear here: esbuild substitutes only what it is
  // given, and anything left behind becomes a `process is not defined` crash in the browser.
  define: {
    'process.env.CHAIN_ID': JSON.stringify(String(chainId)),
    'process.env.CHAIN_NAME': JSON.stringify(chainName),
    'process.env.CHAIN_B_ID': JSON.stringify(String(chainBId)),
    'process.env.CHAIN_B_NAME': JSON.stringify(chainBName),
    'process.env.FACTORY_ADDRESS': JSON.stringify(factoryAddress),
    // service | test-paymaster | off. Defaults to the production paymaster path when the devnet
    // baked one, so the BYO reference demonstrates the path real tenants use.
    'process.env.SPONSORSHIP_MODE': JSON.stringify(
      process.env.SPONSORSHIP_MODE ?? (devnet?.sponsorshipPaymaster ? 'service' : devnet?.testPaymaster ? 'test-paymaster' : 'off'),
    ),
    // the permissive dev paymaster; only used in test-paymaster mode
    'process.env.PAYMASTER_ADDRESS': JSON.stringify(process.env.PAYMASTER_ADDRESS ?? devnet?.testPaymaster ?? devnet?.paymaster ?? ''),
    'process.env.ALLOWED_DAPP_ORIGINS': JSON.stringify(allowedDappOrigins),
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
 *  - `Origin` is forwarded untouched (spread) — wallet-api resolves ceremony tenants and the
 *    read relay's tenant by it;
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
  .listen(port, () => {
    const chains = chainBId ? `${chainId},${chainBId}` : String(chainId);
    console.log(`BYO wallet on :${port} (chains ${chains}, api→${walletApiUpstream}; rpc and bundler via wallet-api /api/v1/{rpc,bundler})`);
  });
