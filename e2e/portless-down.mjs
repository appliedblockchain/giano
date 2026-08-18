/**
 * Undoes portless-setup.mjs: drops the demo's routes and stops the proxy.
 *
 * Worth knowing what this cleans up, because the proxy touches the machine and not just this
 * repo: while it runs it keeps a block of the registered names in /etc/hosts. Removing the
 * routes shrinks that block; stopping the proxy is what empties it. `portless hosts clean`
 * removes the block outright, and `portless clean` removes all portless state.
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

// The proxy runs as root (port 80), so stopping it needs the same privilege. portless prints
// what to run when it cannot do it itself, so pass its output straight through.
const stopped = portless(['proxy', 'stop']);
if (stopped.out) console.log(stopped.out);
process.exit(stopped.status ?? 0);
