/**
 * Registers the e2e demo's names with portless and refuses to run the suite until they
 * answer. Used two ways:
 *   - as Playwright's `globalSetup` (see playwright.config.ts), so `pnpm test` is enough;
 *   - directly (`pnpm portless:up`), to bring the names up for a manual demo session.
 *
 * Registering a static route is unprivileged and does not need the proxy to be running —
 * portless writes routes.json and the proxy, which watches that file, picks the route up
 * (and re-syncs /etc/hosts) on its own. So this module is safe to run before or after the
 * fixtures and the compose stack come up, and the order Playwright chooses for `webServer`
 * versus `globalSetup` does not matter.
 *
 * It will start the proxy if it is not running, because on PORTLESS_LISTEN_PORT that costs no
 * privilege. What it will not do is acquire port 80 — that needs either the `portless-port80`
 * container (see deploy/docker-compose.e2e.yml) or sudo, and both are the developer's call.
 */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { PORTLESS_LISTEN_PORT, PROXY_PORT, ROUTES, originOf } from './origins.mjs';

/**
 * The workspace's own portless, so the suite does not depend on a global install. Resolved with
 * the ESM resolver: portless's `exports` map declares only an `import` condition, so a CJS
 * `require.resolve` — of the package or of its package.json — cannot see it.
 */
const CLI = path.join(path.dirname(fileURLToPath(import.meta.resolve('portless'))), 'cli.js');
if (!fs.existsSync(CLI)) throw new Error(`portless is installed but its CLI is not at ${CLI}`);

/** Both ways to put something on port 80, in the order a developer should prefer them. */
const PORT_80_OPTIONS = [
  ['Let Docker hold the port — no root, and it goes away with the stack:',
   '  pnpm -F @appliedblockchain/giano-e2e portless:port80'],
  ['Or run the proxy on port 80 itself, which does need root:',
   '  sudo pnpm -F @appliedblockchain/giano-e2e portless:proxy',
   `  sudo ${process.execPath} ${CLI} proxy start --no-tls`],
];

/** @param {string[]} args */
function portless(args) {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  if (result.error) throw result.error;
  return { status: result.status, out: `${result.stdout ?? ''}${result.stderr ?? ''}`.trim() };
}

/**
 * Is the portless proxy — and not merely *something* — answering on port 80? Every response
 * the proxy emits carries `X-Portless`, including its own 404 for an unregistered name and
 * its 502 for a registered name with nothing behind it. Insisting on that header turns
 * "some other web server owns port 80" into a clear failure rather than a confusing one.
 */
async function servedByPortless(url) {
  try {
    const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(2_000) });
    return response.headers.has('x-portless');
  } catch {
    return false;
  }
}

/** Is anything serving the demo's names on port 80 — the container, or a root-run proxy? */
const namesAreServed = () => servedByPortless(originOf('app'));

/** Is portless itself listening where it does not need root? */
const proxyIsListening = () => servedByPortless(`http://127.0.0.1:${PORTLESS_LISTEN_PORT}`);

/** Waits for a name to be served by whoever owns the port behind it (fixture or compose). */
async function waitFor(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no attempt made';
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5_000) });
      // portless answers 502 when the route is registered but its port is dead, and 404 when
      // the name is not registered at all. Neither is the backend talking; everything else is
      // (none of the probed endpoints legitimately 404s).
      if (response.status !== 502 && response.status !== 404) return;
      last = `${response.status} from portless (${response.status === 404 ? 'name not registered' : 'nothing listening behind the route'})`;
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`${url} did not answer within ${timeoutMs}ms — last attempt: ${last}`);
}

/**
 * Points every name at its loopback port. Separate from the readiness wait below because CI
 * needs the names to resolve *before* it health-checks the stack, which happens long before
 * Playwright — and unlike the wait, this neither needs the proxy nor anything listening.
 */
export function registerRoutes() {
  for (const { name, port } of ROUTES) {
    // `alias` is idempotent for a name already pointing at the same port, and simply
    // re-points one that is not — so re-running the suite is never a conflict.
    const { status, out } = portless(['alias', name, String(port)]);
    if (status !== 0) {
      throw new Error(`portless could not register ${name}.localhost -> 127.0.0.1:${port}:\n${out}`);
    }
  }
  printRoutes();
}

function printRoutes() {
  const width = Math.max(...ROUTES.map((r) => originOf(r.name).length));
  console.log('\nportless routes for the e2e demo:');
  for (const { name, port, what } of ROUTES) {
    console.log(`  ${originOf(name).padEnd(width)}  ->  127.0.0.1:${String(port).padEnd(5)}  ${what}`);
  }
  console.log();
}

export default async function globalSetup() {
  registerRoutes();

  if (!(await namesAreServed())) {
    // Starting portless on an unprivileged port needs no permission, so just do it rather than
    // making someone read an error to learn that. Port 80 is the part nobody can take silently.
    if (!(await proxyIsListening())) {
      const { status, out } = portless(['proxy', 'start', '--no-tls', '-p', String(PORTLESS_LISTEN_PORT)]);
      if (status !== 0) throw new Error(`could not start the portless proxy on port ${PORTLESS_LISTEN_PORT}:\n${out}`);
      console.log(`started the portless proxy on port ${PORTLESS_LISTEN_PORT}`);
    }
    // The relay may need a moment to accept, and the proxy a moment to bind.
    const deadline = Date.now() + 15_000;
    while (!(await namesAreServed())) {
      if (Date.now() > deadline) {
        throw new Error(
          [
            `Nothing is serving the demo's names on port ${PROXY_PORT}, so URLs without a port do not resolve.`,
            `portless is listening on ${PORTLESS_LISTEN_PORT}; something has to hand it port ${PROXY_PORT}.`,
            '',
            ...PORT_80_OPTIONS.flatMap((option) => [...option, '']),
            'Undo either with `pnpm -F @appliedblockchain/giano-e2e portless:down`.',
          ].join('\n'),
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }

  // Only the compose-backed HTTP services are waited on, and deliberately so: the fixtures are
  // Playwright's to start (and it gates them on `webServer.url` already), so waiting for them
  // here would make `pnpm portless:up` — which a developer runs right after `docker compose up`,
  // before any fixture exists — hang and fail. anvil and alto are skipped because neither
  // answers a plain GET meaningfully; the suite's own traffic is what exercises those routes.
  await Promise.all([
    waitFor(originOf('wallet'), 120_000),
    // /readyz rather than /: "answering" is not the same as "migrated, and able to sponsor".
    waitFor(`${originOf('api')}/readyz`, 120_000),
  ]);
}

// Also runnable on its own: `node portless-setup.mjs` brings the names up and waits for them;
// `--routes-only` just registers them (what CI does, before its own health checks).
if (import.meta.filename === process.argv[1]) {
  if (process.argv.includes('--routes-only')) registerRoutes();
  else await globalSetup();
}
