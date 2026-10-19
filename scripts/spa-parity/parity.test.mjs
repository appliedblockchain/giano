// The SPA start-up scripts, run in the hardened layout (sh + envsubst + jq only, UID 65532), must
// render what the pre-ABIP-2 scripts rendered for every fixture (openspec: spa-container-runtime,
// "Parity with the previous entrypoint"). Goldens: capture-golden.mjs. Needs Docker; skips without.
//
//   node --test scripts/spa-parity/parity.test.mjs

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { IMAGES } from './collect-envs.mjs';
import { dockerAvailable, namedVariables, render } from './render.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const skip = dockerAvailable() ? false : 'docker is not available';

// Malformed JSON must stop the container with a message naming the variable (spa-container-runtime,
// "Malformed JSON input"). The previous scripts either left that to a bare jq parse error
// (paymaster-admin) or let bracketed non-JSON through to a config.js that does not parse
// (custom-example), so these cases are held to the spec rather than to their golden.
const MUST_NAME = {
  'paymaster-admin/err-malformed-json': ['GIANO_DEPLOYMENTS'],
  'custom-example/err-not-array': ['GIANO_CHAINS'],
  'custom-example/err-malformed-json': ['GIANO_CHAINS'],
};

for (const image of Object.keys(IMAGES)) {
  describe(`${image} start-up parity`, { skip }, () => {
    const base = join(HERE, 'fixtures', image);
    for (const name of readdirSync(base).sort()) {
      it(name, () => {
        const env = JSON.parse(readFileSync(join(base, name, 'env.json'), 'utf8'));
        const expected = JSON.parse(readFileSync(join(base, name, 'expected.json'), 'utf8'));
        const actual = render({ layout: 'hardened', image, env });

        if (expected.exit !== 0 || MUST_NAME[`${image}/${name}`]) {
          assert.notEqual(actual.exit, 0, `expected a refusal, got exit 0\n${actual.stderr}`);
          // shells word their errors differently; what must survive is WHICH variable is named
          for (const v of [...namedVariables(expected.stderr), ...(MUST_NAME[`${image}/${name}`] ?? [])]) {
            assert.ok(actual.stderr.includes(v), `stderr should name ${v}:\n${actual.stderr}`);
          }
          return;
        }
        assert.equal(actual.exit, 0, `start-up failed:\n${actual.stderr}`);
        assert.deepEqual(actual.config, expected.config, 'rendered browser configuration');
        assert.equal(actual.conf, expected.conf, 'rendered nginx server block');
      });
    }
  });
}

// demo-deployment "Keyed RPC via proxy" / spa-container-runtime "Keyed RPC stays server-side": the
// keyed upstream is in the proxy block and nowhere the browser can read it.
describe('keyed upstreams stay server-side', { skip }, () => {
  const cases = [
    ['custom-example', 'quoting-and-upstreams', 'SECRET'],
    ['paymaster-admin', 'single-keyed-rpc', 'SECRETKEY'],
  ];
  for (const [image, name, key] of cases) {
    it(`${image}/${name}`, () => {
      const env = JSON.parse(readFileSync(join(HERE, 'fixtures', image, name, 'env.json'), 'utf8'));
      const r = render({ layout: 'hardened', image, env });
      assert.equal(r.exit, 0, r.stderr);
      assert.ok(!JSON.stringify(r.config).includes(key), 'key leaked into the browser configuration');
      const headers = r.conf.split('\n').filter((l) => l.startsWith('add_header'));
      assert.ok(headers.length > 0 && headers.every((l) => !l.includes(key)), 'key leaked into a response header');
      assert.ok(r.conf.split('\n').some((l) => l.startsWith('proxy_pass') && l.includes(key)), 'key missing from the proxy');
    });
  }
});
