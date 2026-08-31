/**
 * The e2e demo's addresses, in one place.
 *
 * Every address the demo *speaks* is a name — `http://wallet.localhost`, not
 * `http://wallet.localhost:8081`. The names are served by portless
 * (https://github.com/vercel-labs/portless), a local reverse proxy that maps
 * `<name>.localhost` to a loopback port. The ports below are plumbing; nothing in the
 * fixtures, the tenant seed, the tests or the docs refers to them.
 *
 * Why HTTP rather than portless's default HTTPS: `http://*.localhost` is already a secure
 * context in Chromium, so passkeys keep working exactly as they did on
 * `http://wallet.localhost:8081` — and no local CA has to be minted and trusted on developer
 * machines or in CI. The only thing that changed is that the port is gone.
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
 * The port the names are served on. A URL with no port *is* port 80, so this is not a choice
 * so much as the definition of the goal.
 */
export const PROXY_PORT = 80;

/**
 * The port portless itself listens on — deliberately above 1024, so nothing here needs root.
 *
 * macOS and Linux reserve ports below 1024 for root, so a port-free URL normally costs a
 * `sudo portless proxy start`. It does not have to: Docker already binds host ports for this
 * stack through its own privileged helper, so the `portless-port80` service in
 * deploy/docker-compose.e2e.yml holds port 80 and pipes every connection, bytes untouched, to
 * portless here. The Host header — which is what portless routes on, and what wallet-api
 * resolves tenants by — survives that hop because a TCP relay has no opinion about it.
 *
 * The upshot: the browser talks to port 80, portless does all the routing, and no part of the
 * local demo runs as root or edits /etc/hosts. CI takes the sudo route instead, because on a
 * throwaway runner sudo is free and one less moving part is worth more than symmetry.
 */
export const PORTLESS_LISTEN_PORT = 1355;

/** @typedef {{ name: string, port: number, kind: 'fixture' | 'compose', what: string }} Route */

/** @type {Route[]} */
export const ROUTES = [
  { name: 'app', port: 4400, kind: 'fixture', what: "tenant stock's demo dApp (thin SDK only)" },
  { name: 'app-byo', port: 4401, kind: 'fixture', what: "tenant byo's demo dApp (same fixture, other wallet)" },
  { name: 'wallet-byo', port: 8082, kind: 'fixture', what: "tenant byo's wallet origin (BYO UI + /api proxy)" },
  { name: 'wallet', port: 8081, kind: 'compose', what: "tenant stock's wallet-web" },
  { name: 'paymaster', port: 8083, kind: 'compose', what: 'paymaster admin console (read-only without a wallet)' },
  { name: 'api', port: 8080, kind: 'compose', what: 'wallet-api (public + admin)' },
  { name: 'rpc', port: 8545, kind: 'compose', what: 'anvil devnet JSON-RPC (chain A, 31337)' },
  { name: 'bundler', port: 4337, kind: 'compose', what: 'alto ERC-4337 bundler (chain A)' },
  { name: 'rpc-b', port: 8546, kind: 'compose', what: 'anvil devnet JSON-RPC (chain B, 31338)' },
  { name: 'bundler-b', port: 4338, kind: 'compose', what: 'alto ERC-4337 bundler (chain B)' },
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
  rpcB: originOf('rpc-b'),
  bundlerB: originOf('bundler-b'),
  paymasterAdmin: originOf('paymaster'),
};

/** The two chains the e2e stack runs (S10): distinct ids that cannot be confused. */
export const CHAINS = {
  a: { chainId: 31337, name: 'Devnet A', rpc: originOf('rpc') },
  b: { chainId: 31338, name: 'Devnet B', rpc: originOf('rpc-b') },
};
