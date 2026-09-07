// BYO-wallet reference server: the SECOND tenant's wallet origin. Serves a tenant-built
// (framework-free) wallet SPA and reverse-proxies /api, /.well-known/webauthn, /rpc and
// /bundler — the same shape a real tenant would deploy with nginx/CloudFront.
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

// --- the /bundler proxy, and why it is a flag (R11) ---------------------------------------
//
// This location relays straight to the ERC-4337 bundler. On a deployment where the wallet
// task can reach a private bundler, leaving it on makes the wallet origin a PUBLIC
// UNAUTHENTICATED BUNDLER RELAY: it bypasses every wallet-api policy check and lets anyone
// drain the funded Alto executor. So it is now switchable, and a deployment turns it off.
//
// ⚠ BUT TURNING IT OFF ALSO STOPS THE WALLET SUBMITTING. §16.5 assumed `service` sponsorship
// needs no bundler; the code says otherwise. src/runtime.ts builds a viem
// `createBundlerClient({ transport: http(`${origin}${bundlerPath}`) })` and submits through it
// on EVERY path — sponsorship mode only swaps the paymaster hooks. wallet-api's
// `POST /v1/userops` is a REST endpoint (`{userOperation, chainId}` + a session), not a
// JSON-RPC bundler, so it cannot be dropped in as that transport. The stock wallet
// (services/wallet-web/src/wallet.ts) does exactly the same thing, which is why R3 is the same
// defect seen from the other end.
//
// Until wallet-api exposes a JSON-RPC relay, a deployment therefore has to choose:
//   * proxy off  — safe, and the wallet cannot send transactions (this is what dev is set to)
//   * proxy on   — the wallet works and the relay is exposed; only acceptable if the bundler
//                  is not reachable from this task at all
// The route below answers 501 with an explanatory JSON-RPC error rather than 404, so the
// choice shows up in the browser console as a decision instead of a mystery.
const bundlerProxyEnabled = (process.env.BYO_BUNDLER_PROXY_ENABLED ?? 'true') !== 'false';
const bundlerUpstream = bundlerProxyEnabled ? (process.env.BUNDLER_UPSTREAM ?? loopbackOf('bundler')) : undefined;
const bundlerBUpstream = bundlerProxyEnabled ? (process.env.BUNDLER_B_UPSTREAM ?? loopbackOf('bundler-b')) : undefined;

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

/** A disabled bundler location, answered so the reason reaches the browser console. */
function bundlerDisabled(res) {
  res.writeHead(501, { 'content-type': 'application/json' });
  res.end(
    JSON.stringify({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32601,
        message:
          'bundler proxy disabled on this wallet origin (BYO_BUNDLER_PROXY_ENABLED=false). ' +
          'A wallet origin that relays to the bundler bypasses wallet-api policy checks and can drain the executor (R11). ' +
          'Submission needs a JSON-RPC relay on wallet-api; POST /v1/userops is REST and cannot serve as a bundler transport.',
      },
    }),
  );
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
      return bundlerUpstream ? proxy(req, res, bundlerUpstream, '/') : bundlerDisabled(res);
    }
    if (url === '/rpc-b') {
      if (!rpcBUpstream) {
        res.statusCode = 404;
        return res.end('second chain not configured on this wallet origin');
      }
      return proxy(req, res, rpcBUpstream, '/');
    }
    if (url === '/bundler-b') {
      return bundlerBUpstream ? proxy(req, res, bundlerBUpstream, '/') : bundlerDisabled(res);
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
    console.log(`BYO wallet on :${port} (chains ${chains}, api→${walletApiUpstream}, rpc→${rpcUpstream}, bundler→${bundlerUpstream ?? 'DISABLED'})`);
    if (!bundlerProxyEnabled) {
      console.warn('WARNING: /bundler and /bundler-b are disabled, so this wallet CANNOT SUBMIT transactions.');
      console.warn('         See the R11 note in serve.mjs: closing the relay and keeping submission needs a');
      console.warn('         JSON-RPC relay endpoint on wallet-api, which does not exist yet.');
    }
  });
