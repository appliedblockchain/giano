/**
 * Undoes portless-setup.mjs: drops the demo's routes and stops the proxy.
 *
 * The port-80 relay is a compose service, so it is not this script's to stop — it goes away
 * with `docker compose --profile portless -f deploy/docker-compose.e2e.yml down`, along with
 * the rest of the stack.
 *
 * Nothing here needs root, and nothing it undoes touched /etc/hosts: portless only syncs the
 * hosts file when it can write it, which an unprivileged proxy cannot. (If you took the sudo
 * route instead, a root proxy *will* have written a block there — `portless hosts clean`
 * removes it, and `portless clean` removes all portless state.)
 */
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ROUTES } from './origins.mjs';

/**
 * The workspace's own portless, so the suite does not depend on a global install. Resolved with
 * the ESM resolver: portless's `exports` map declares only an `import` condition, so a CJS
 * `require.resolve` — of the package or of its package.json — cannot see it.
 */
const CLI = path.join(path.dirname(fileURLToPath(import.meta.resolve('portless'))), 'cli.js');
if (!fs.existsSync(CLI)) throw new Error(`portless is installed but its CLI is not at ${CLI}`);

/** @param {string[]} args */
function portless(args) {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  return { status: result.status, out: `${result.stdout ?? ''}${result.stderr ?? ''}`.trim() };
}

for (const { name } of ROUTES) {
  const { status, out } = portless(['alias', '--remove', name]);
  console.log(`${status === 0 ? 'removed' : 'could not remove'} ${name}.localhost${status === 0 ? '' : `: ${out}`}`);
}

// portless prints what to run when it cannot stop the proxy itself (only the case for a proxy
// someone started with sudo), so pass its output straight through.
const stopped = portless(['proxy', 'stop']);
if (stopped.out) console.log(stopped.out);
process.exit(stopped.status ?? 0);
