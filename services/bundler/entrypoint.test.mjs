// node --test services/bundler/entrypoint.test.mjs
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ANVIL_KEY, ConfigError, DEFAULT_ENTRYPOINT, altoArgs } from './entrypoint.mjs';

const KEY = `0x${'11'.repeat(32)}`;
const base = { ALTO_RPC_URL: 'http://anvil:8545', ALTO_EXECUTOR_PRIVATE_KEYS: KEY };

describe('bundler entrypoint', () => {
  it('requires ALTO_RPC_URL', () => {
    assert.throws(() => altoArgs({ ALTO_EXECUTOR_PRIVATE_KEYS: KEY }), (e) => e instanceof ConfigError && /ALTO_RPC_URL/.test(e.message));
  });

  it('requires executor keys', () => {
    assert.throws(() => altoArgs({ ALTO_RPC_URL: 'http://x' }), /ALTO_EXECUTOR_PRIVATE_KEYS is required/);
  });

  it('refuses the Anvil key outside dev mode, as an executor or utility key', () => {
    assert.throws(() => altoArgs({ ...base, ALTO_EXECUTOR_PRIVATE_KEYS: ANVIL_KEY }), /refusing to start with the well-known Anvil key/);
    assert.throws(() => altoArgs({ ...base, ALTO_UTILITY_PRIVATE_KEY: ANVIL_KEY }), /well-known Anvil key/);
    assert.throws(() => altoArgs({ ...base, ALTO_EXECUTOR_PRIVATE_KEYS: `${KEY},${ANVIL_KEY}`, GIANO_DEV_MODE: 'yes' }), /well-known Anvil key/);
  });

  it('allows the Anvil key in dev mode, with a warning', () => {
    const { args, warning } = altoArgs({ ...base, ALTO_EXECUTOR_PRIVATE_KEYS: ANVIL_KEY, GIANO_DEV_MODE: 'true' });
    assert.match(warning, /GIANO_DEV_MODE=true/);
    assert.ok(args.includes(ANVIL_KEY));
  });

  it('applies the same defaults as entrypoint.sh', () => {
    const { args, warning } = altoArgs(base);
    assert.equal(warning, undefined);
    assert.deepEqual(args, [
      'run',
      '--rpc-url', 'http://anvil:8545',
      '--entrypoints', DEFAULT_ENTRYPOINT,
      '--executor-private-keys', KEY,
      '--safe-mode', 'true',
      '--port', '4337',
    ]);
  });

  it('passes overrides and the optional utility key through', () => {
    const util = `0x${'22'.repeat(32)}`;
    const { args } = altoArgs({ ...base, ALTO_UTILITY_PRIVATE_KEY: util, ALTO_SAFE_MODE: 'false', ALTO_PORT: '3000', ALTO_ENTRYPOINTS: '0xabc' });
    assert.deepEqual(args.slice(5), ['--executor-private-keys', KEY, '--utility-private-key', util, '--safe-mode', 'false', '--port', '3000']);
    assert.equal(args[4], '0xabc');
  });
});
