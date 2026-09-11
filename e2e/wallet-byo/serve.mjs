// BYO-wallet reference server: the SECOND tenant's wallet origin. Serves a tenant-built
// (framework-free) wallet SPA and reverse-proxies /api, /.well-known/webauthn and /rpc — the
// same shape a real tenant would deploy with nginx/CloudFront.
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

const loopbackOf = (name) => (origins ? origins.loopbackOf(name) : undefined);

/** Required outside a devnet checkout, where there is no fixture default to fall back to. */
function required(value, name, why) {
  if (value === undefined || value === null || value === '') {
    console.error(`FATAL: ${name} is required — ${why}`);
    console.error('       (it defaults only in an e2e checkout, from ../origins.mjs or ../devnet/addresses.json)');
    process.exit(1);
  }
  return value;
}

const port = Number(process.env.BYO_WALLET_PORT ?? (origins ? origins.portOf('wallet-byo') : 8080));

// Loopback, not the portless names: these are server-to-server hops, and this proxy forwards
// the browser's Host untouched (see `proxy` below) because wallet-api resolves the tenant from
// it. Sending that Host back through portless would route the request straight back here — a
// loop portless would have to reject.
const walletApiUpstream = required(
  process.env.WALLET_API_UPSTREAM ?? loopbackOf('api'),
  'WALLET_API_UPSTREAM',
  'the wallet-api this origin proxies /api and /.well-known/webauthn to',
);
const rpcUpstream = required(process.env.RPC_UPSTREAM ?? loopbackOf('rpc'), 'RPC_UPSTREAM', 'the chain RPC this origin proxies /rpc to');
const rpcBUpstream = process.env.RPC_B_UPSTREAM ?? loopbackOf('rpc-b');

// --- no bundler proxy, deliberately ------------------------------------------------------
//
// There used to be a /bundler location relaying straight to the ERC-4337 bundler, behind a
// flag (R11). On any deployment where this task could reach a bundler it was a PUBLIC
// UNAUTHENTICATED RELAY that bypassed every wallet-api policy check — and turning it off
// stopped the wallet submitting, because viem's bundler client needs a JSON-RPC bundler for
// estimation and receipts as well as submission. The SPA now points its bundler client at
// wallet-api's relay, `/api/v1/bundler/<chainId>` (see src/config.ts): the same JSON-RPC
// surface, behind the session, with submissions going through the same policy pipeline as
// `POST /v1/userops`. It travels through the /api proxy below, so this origin needs no route
// to a bundler at all. That is the whole serving contract a BYO tenant has to reproduce.

// --- chain configuration ------------------------------------------------------------------
// The second chain used to be unconditional, so a single-chain deployment advertised a
// fiction pointing at /rpc-b. It now falls away unless asked for — and it is asked for
// implicitly in a devnet checkout, which is what keeps the two-chain e2e suite (MC-129)
// passing with no environment at all.
const chainId = required(process.env.CHAIN_ID ?? devnet?.chainId, 'CHAIN_ID', 'the chain this wallet origin serves');
const chainBId = process.env.CHAIN_B_ID ?? (devnet ? '31338' : '');
const chainName = process.env.CHAIN_NAME ?? (devnet ? 'Devnet A' : `chain ${chainId}`);
const chainBName = process.env.CHAIN_B_NAME ?? (devnet ? 'Devnet B' : `chain ${chainBId}`);

if (chainBId && !rpcBUpstream) {
  console.error(`FATAL: CHAIN_B_ID=${chainBId} but RPC_B_UPSTREAM is unset.`);
  console.error('       Set RPC_B_UPSTREAM, or leave CHAIN_B_ID unset for a single-chain deployment.');
  process.exit(1);
}

// The SPA passes this straight to createGianoProvider. §14.5 says it defaults from the
// contracts registry, but this bundle has no registry dependency — so outside a devnet
// checkout it must be supplied.
const factoryAddress = required(
  process.env.FACTORY_ADDRESS ?? devnet?.factory,
  'FACTORY_ADDRESS',
  'the account factory this wallet derives addresses from',
);

const allowedDappOrigins = required(
  process.env.BYO_ALLOWED_DAPP_ORIGINS ?? (origins ? JSON.stringify([origins.ORIGINS.dappByo]) : undefined),
  'BYO_ALLOWED_DAPP_ORIGINS',
  'a JSON array of the dApp origins allowed to connect — this tenant\'s own allowlist, which is why R9 does not reach it',
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
    // Defaults to the production paymaster path when the devnet baked one, so what the BYO
    // reference demonstrates is the path real tenants use — rules enforced, balance debited, fee
    // charged — rather than a permissive fixture that cannot fail.
    'process.env.SPONSORSHIP_MODE': JSON.stringify(
      process.env.SPONSORSHIP_MODE ?? (devnet?.sponsorshipPaymaster ? 'service' : devnet?.testPaymaster ? 'test-paymaster' : 'off'),
    ),
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
    if (url === '/rpc-b') {
      if (!rpcBUpstream) {
        res.statusCode = 404;
        return res.end('second chain not configured on this wallet origin');
      }
      return proxy(req, res, rpcBUpstream, '/');
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
    console.log(`BYO wallet on :${port} (chains ${chains}, api→${walletApiUpstream}, rpc→${rpcUpstream}, bundler→via wallet-api /api/v1/bundler)`);
  });
