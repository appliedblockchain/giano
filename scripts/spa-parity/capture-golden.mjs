#!/usr/bin/env node
// Record what the pre-ABIP-2 SPA entrypoints render for every fixture — the golden output the
// rewritten entrypoints are held to (parity.test.mjs). Runs the entrypoint from a given git
// revision, so the goldens stay reproducible after the scripts themselves have changed:
//
//   node scripts/spa-parity/capture-golden.mjs [<rev>]     default: main
//
// Writes fixtures/<image>/<case>/expected.json.

import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { IMAGES } from './collect-envs.mjs';
import { ROOT, render } from './render.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const rev = process.argv[2] ?? 'main';

function checkoutDockerDir(image) {
  const dir = mkdtempSync(join(tmpdir(), `spa-golden-${image}-`));
  const prefix = `${IMAGES[image]}/docker/`;
  const files = execFileSync('git', ['ls-tree', '--name-only', `${rev}:${prefix}`], { cwd: ROOT }).toString().split('\n').filter(Boolean);
  for (const f of files) {
    writeFileSync(join(dir, f), execFileSync('git', ['show', `${rev}:${prefix}${f}`], { cwd: ROOT }));
  }
  execFileSync('chmod', ['0755', join(dir, 'entrypoint.sh')]);
  return dir;
}

let n = 0;
for (const image of Object.keys(IMAGES)) {
  const dockerDir = checkoutDockerDir(image);
  const base = join(HERE, 'fixtures', image);
  for (const name of readdirSync(base).sort()) {
    const env = JSON.parse(readFileSync(join(base, name, 'env.json'), 'utf8'));
    const r = render({ layout: 'legacy', image, env, dockerDir });
    mkdirSync(join(base, name), { recursive: true });
    writeFileSync(join(base, name, 'expected.json'), `${JSON.stringify({ rev, ...r }, null, 2)}\n`);
    console.log(`${image}/${name}: exit ${r.exit}`);
    n++;
  }
  rmSync(dockerDir, { recursive: true, force: true });
}
console.log(`captured ${n} goldens from ${rev}`);
