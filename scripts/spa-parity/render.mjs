// Run an SPA image's start-up script in a container, with `exec nginx` stubbed out, and return
// what it rendered. Two layouts:
//
//   legacy    the nginx:1.27-alpine images this change replaces: templates in /etc/giano,
//             server block to /etc/nginx/conf.d/default.conf, full busybox on PATH.
//   hardened  the DHI nginx runtime (design D2): same paths — DHI nginx already lets its user
//             (65532) write /etc/nginx/conf.d — but run as UID 65532 with PATH holding ONLY
//             sh, envsubst, jq and the nginx stub, so a script that reaches for sed, awk, tr,
//             grep or cat fails here exactly as it would in the hardened runtime.
//
// The runner images are local test tooling, never published (Dockerfile.legacy/.hardened).

import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { runInNewContext } from 'node:vm';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = resolve(HERE, '../..');
const RESOLV = 'nameserver 10.0.0.2\nnameserver fd00::1\n';

const LAYOUTS = {
  legacy: {
    runner: 'giano-spa-parity:legacy',
    dockerfile: 'Dockerfile.legacy',
    templates: '/etc/giano',
    conf: '/etc/nginx/conf.d',
    stub: '/usr/local/sbin/nginx',
    args: [],
  },
  hardened: {
    runner: 'giano-spa-parity:hardened',
    dockerfile: 'Dockerfile.hardened',
    templates: '/etc/giano',
    conf: '/etc/nginx/conf.d',
    stub: '/tools/nginx',
    args: ['--user', '65532:65532', '-e', 'PATH=/tools'],
  },
};

const built = new Set();
export function ensureRunner(layout) {
  const l = LAYOUTS[layout];
  if (built.has(layout)) return;
  execFileSync('docker', ['build', '-q', '-t', l.runner, '-f', join(HERE, l.dockerfile), HERE], { stdio: 'pipe' });
  built.add(layout);
}

export function dockerAvailable() {
  return spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0;
}

/** Browser config file each image renders, relative to the html root. */
export const CONFIG_FILE = { 'wallet-web': 'config.json', 'paymaster-admin': 'config.json', 'custom-example': 'config.js' };

/**
 * @param {object} o
 * @param {'legacy'|'hardened'} o.layout
 * @param {string} o.image wallet-web | paymaster-admin | custom-example
 * @param {Record<string,string>} o.env
 * @param {string} [o.dockerDir] directory holding entrypoint.sh and the templates
 */
export function render({ layout, image, env, dockerDir = join(ROOT, 'services', image, 'docker') }) {
  const l = LAYOUTS[layout];
  ensureRunner(layout);
  const tmp = mkdtempSync(join(tmpdir(), 'spa-parity-'));
  const html = join(tmp, 'html');
  const conf = join(tmp, 'conf');
  for (const d of [html, conf]) {
    mkdirSync(d);
    chmodSync(d, 0o777);
  }
  // the bundle ships a placeholder config file; the entrypoint overwrites it
  writeFileSync(join(html, CONFIG_FILE[image]), '');
  chmodSync(join(html, CONFIG_FILE[image]), 0o666);
  // a private, world-readable copy with the entrypoint executable, as the image's COPY --chmod
  // makes it: the hardened layout runs as UID 65532, which cannot read a 0600 working-tree file
  const docker = join(tmp, 'docker');
  cpSync(dockerDir, docker, { recursive: true });
  chmodSync(docker, 0o755);
  for (const f of readdirSync(docker)) chmodSync(join(docker, f), f === 'entrypoint.sh' ? 0o755 : 0o644);
  writeFileSync(join(tmp, 'resolv.conf'), RESOLV);
  writeFileSync(join(tmp, 'nginx'), '#!/bin/sh\nexit 0\n');
  chmodSync(join(tmp, 'nginx'), 0o755);

  const envArgs = Object.keys(env).flatMap((k) => ['-e', k]);
  const res = spawnSync(
    'docker',
    [
      'run', '--rm', '--network', 'none',
      ...l.args,
      ...envArgs,
      '-v', `${join(docker, 'entrypoint.sh')}:/entrypoint.sh:ro`,
      '-v', `${docker}:${l.templates}:ro`,
      '-v', `${html}:/usr/share/nginx/html`,
      '-v', `${conf}:${l.conf}`,
      '-v', `${join(tmp, 'resolv.conf')}:/etc/resolv.conf:ro`,
      '-v', `${join(tmp, 'nginx')}:${l.stub}:ro`,
      '--entrypoint', '/entrypoint.sh',
      l.runner,
    ],
    // only the fixture's variables reach the container: -e NAME takes the value from here
    { env: { PATH: process.env.PATH, HOME: process.env.HOME, DOCKER_HOST: process.env.DOCKER_HOST ?? '', ...env }, encoding: 'utf8' },
  );

  const read = (p) => (existsSync(p) ? readFileSync(p, 'utf8') : null);
  const out = {
    exit: res.status,
    stderr: res.stderr,
    config: normaliseConfig(image, read(join(html, CONFIG_FILE[image]))),
    conf: normaliseConf(read(join(conf, 'default.conf'))),
  };
  rmSync(tmp, { recursive: true, force: true });
  return out;
}

function normaliseConfig(image, text) {
  if (!text) return null;
  if (image === 'custom-example') {
    const sandbox = { window: {} };
    try {
      runInNewContext(text, sandbox);
      // through JSON: objects from the vm context have another realm's prototypes, which a strict
      // deep-equal against the parsed golden would reject
      const cfg = sandbox.window.__GIANO_CONFIG__;
      return cfg === undefined ? { unparsed: text } : JSON.parse(JSON.stringify(cfg));
    } catch {
      return { unparsed: text };
    }
  }
  try {
    return JSON.parse(text);
  } catch {
    return { unparsed: text };
  }
}

/** nginx config, whitespace-insensitive: one directive per line, blank lines and comments dropped. */
export function normaliseConf(text) {
  if (text === null) return null;
  return text
    .split('\n')
    .map((l) => l.replace(/#.*$/, '').trim().replace(/\s+/g, ' '))
    .filter(Boolean)
    .join('\n');
}

/** Variable names an error message mentions — what a parity check can compare across shells. */
export function namedVariables(stderr) {
  return [...new Set(stderr.match(/GIANO_[A-Z0-9_]+/g) ?? [])].sort();
}
