/**
 * The e2e demo's addresses, in one place.
 *
 * Every address the demo *speaks* is a name — `http://wallet.localhost`, not
 * `http://wallet.localhost:8081`. The names are served by portless
 * (https://github.com/vercel-labs/portless), a local reverse proxy on port 80 that maps
 * `<name>.localhost` to a loopback port. The ports below are plumbing; nothing in the
 * fixtures, the tenant seed, the tests or the docs refers to them.
 *
 * Why HTTP on port 80 rather than portless's default HTTPS on 443: `http://*.localhost`
 * is already a secure context in Chromium, so passkeys keep working exactly as they did
 * on `http://wallet.localhost:8081` — and no local CA has to be minted and trusted on
 * developer machines or in CI. The only thing that changed is that the port is gone.
 *
 * Route `kind` records who listens on the loopback port, because it decides who has to be
 * up before a name answers:
 *  - 'fixture' — a host-side Node server this repo starts (Playwright's `webServer`);
 *  - 'compose' — a port published by deploy/docker-compose.e2e.yml.
 * Both kinds are registered with portless as static routes (`portless alias`); see
 * portless-setup.mjs.
 *
 * The route names live in portless's machine-global namespace, so a developer running
 * another portless project that has claimed `app` or `api` will get a route conflict
 * reported by `portless alias`. Renaming here is the fix — but note that `wallet` and
 * `wallet-byo` are also WebAuthn RP IDs (a tenant's RP ID must equal its wallet origin's
 * host), so renaming those two means updating TENANTS_SEED and GIANO_RP_ID in
 * deploy/docker-compose.e2e.yml to match.
 */

/** The suffix portless serves. Also the eTLD that makes these names a secure context. */
export const TLD = 'localhost';

/**
 * The port portless listens on. 80 is privileged, which is the whole point — it is what
 * lets the URLs omit a port. Starting the proxy therefore needs sudo once per boot; see
 * portless-setup.mjs for the message a developer gets when it is not running.
 */
export const PROXY_PORT = 80;

/** @typedef {{ name: string, port: number, kind: 'fixture' | 'compose', what: string }} Route */

/** @type {Route[]} */
export const ROUTES = [
  { name: 'app', port: 4400, kind: 'fixture', what: "tenant stock's demo dApp (thin SDK only)" },
  { name: 'app-byo', port: 4401, kind: 'fixture', what: "tenant byo's demo dApp (same fixture, other wallet)" },
  { name: 'wallet-byo', port: 8082, kind: 'fixture', what: "tenant byo's wallet origin (BYO UI + /api proxy)" },
  { name: 'wallet', port: 8081, kind: 'compose', what: "tenant stock's wallet-web" },
  { name: 'api', port: 8080, kind: 'compose', what: 'wallet-api (public + admin)' },
  { name: 'rpc', port: 8545, kind: 'compose', what: 'anvil devnet JSON-RPC' },
  { name: 'bundler', port: 4337, kind: 'compose', what: 'alto ERC-4337 bundler' },
];

const byName = new Map(ROUTES.map((route) => [route.name, route]));

/** @param {string} name */
function route(name) {
  const found = byName.get(name);
  if (!found) throw new Error(`unknown e2e route "${name}" — known routes: ${[...byName.keys()].join(', ')}`);
  return found;
}

/** The public origin for a route: a name, never a port. @param {string} name */
export const originOf = (name) => `http://${route(name).name}.${TLD}`;

/** The loopback port a route proxies to. @param {string} name */
export const portOf = (name) => route(name).port;

/**
 * The loopback address a route proxies to. Server-to-server hops use these rather than the
 * public names on purpose: a backend that called back through the proxy without rewriting
 * Host would route straight back to itself, and portless would (correctly) report a loop.
 * @param {string} name
 */
export const loopbackOf = (name) => `http://127.0.0.1:${portOf(name)}`;

/**
 * The demo's browser-visible origins — what the dApps, the wallets, the tenant seed and
 * the tests all agree on.
 */
export const ORIGINS = {
  dapp: originOf('app'),
  dappByo: originOf('app-byo'),
  wallet: originOf('wallet'),
  walletByo: originOf('wallet-byo'),
  api: originOf('api'),
  rpc: originOf('rpc'),
  bundler: originOf('bundler'),
};
