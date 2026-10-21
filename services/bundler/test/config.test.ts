import { describe, expect, it } from 'vitest';
import { ANVIL_KEY, ConfigError, DEFAULT_ENTRYPOINT, loadConfig } from '../src/config.js';

const KEY = `0x${'11'.repeat(32)}`;
const base = { BUNDLER_RPC_URL: 'http://anvil:8545', BUNDLER_EXECUTOR_PRIVATE_KEYS: KEY };

describe('loadConfig', () => {
  it('requires an RPC URL and executor keys', () => {
    expect(() => loadConfig({ BUNDLER_EXECUTOR_PRIVATE_KEYS: KEY })).toThrow(/BUNDLER_RPC_URL is required/);
    expect(() => loadConfig({ BUNDLER_RPC_URL: 'http://x' })).toThrow(/BUNDLER_EXECUTOR_PRIVATE_KEYS is required/);
    expect(() => loadConfig({ ...base, BUNDLER_EXECUTOR_PRIVATE_KEYS: '0x1234' })).toThrow(ConfigError);
    expect(() => loadConfig({ ...base, BUNDLER_EXECUTOR_PRIVATE_KEYS: `${KEY},${KEY}` })).toThrow(/same key twice/);
  });

  it('refuses the Anvil key outside dev mode', () => {
    expect(() => loadConfig({ ...base, BUNDLER_EXECUTOR_PRIVATE_KEYS: ANVIL_KEY })).toThrow(/well-known Anvil key/);
    expect(() => loadConfig({ ...base, BUNDLER_EXECUTOR_PRIVATE_KEYS: `${KEY},${ANVIL_KEY}`, GIANO_DEV_MODE: 'yes' })).toThrow(/well-known Anvil key/);
  });

  it('allows the Anvil key in dev mode, with a warning', () => {
    const config = loadConfig({ ...base, BUNDLER_EXECUTOR_PRIVATE_KEYS: ANVIL_KEY, GIANO_DEV_MODE: 'true' });
    expect(config.warnings.join('\n')).toMatch(/GIANO_DEV_MODE=true/);
    expect(config.executors[0].address).toBe('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266');
  });

  it('applies defaults', () => {
    const config = loadConfig(base);
    expect(config).toMatchObject({
      rpcUrl: 'http://anvil:8545',
      entryPoint: DEFAULT_ENTRYPOINT,
      port: 4337,
      maxBlockRange: 2000n,
      chainType: 'auto',
      resubmitTimeoutMs: 30_000,
      maxReplacements: 3,
      warnings: [],
    });
    expect(config.executors).toHaveLength(1);
  });

  it('takes several executor keys, one lane each', () => {
    const second = `0x${'22'.repeat(32)}`;
    expect(loadConfig({ ...base, BUNDLER_EXECUTOR_PRIVATE_KEYS: `${KEY}, ${second}` }).executors).toHaveLength(2);
  });

  it("reads Alto's variables, so an existing deployment boots unchanged", () => {
    const config = loadConfig({
      ALTO_RPC_URL: 'http://alto-era:8545',
      ALTO_EXECUTOR_PRIVATE_KEYS: KEY,
      ALTO_ENTRYPOINTS: '0x0000000071727de22e5e9d8baf0edac6f37da032',
      ALTO_PORT: '3000',
      ALTO_SAFE_MODE: 'true',
      ALTO_UTILITY_PRIVATE_KEY: `0x${'22'.repeat(32)}`,
    });
    expect(config).toMatchObject({ rpcUrl: 'http://alto-era:8545', port: 3000, entryPoint: DEFAULT_ENTRYPOINT });
    expect(config.warnings).toEqual([
      'ALTO_RPC_URL is deprecated, read as BUNDLER_RPC_URL',
      'ALTO_EXECUTOR_PRIVATE_KEYS is deprecated, read as BUNDLER_EXECUTOR_PRIVATE_KEYS',
      'ALTO_ENTRYPOINTS is deprecated, read as BUNDLER_ENTRYPOINT',
      'ALTO_PORT is deprecated, read as BUNDLER_PORT',
      expect.stringMatching(/^ALTO_SAFE_MODE is ignored/),
      expect.stringMatching(/^ALTO_UTILITY_PRIVATE_KEY is ignored/),
    ]);
  });

  it('prefers BUNDLER_* over the Alto names', () => {
    expect(loadConfig({ ...base, ALTO_RPC_URL: 'http://old:1' }).rpcUrl).toBe('http://anvil:8545');
  });

  it('serves exactly one EntryPoint', () => {
    expect(() => loadConfig({ ...base, BUNDLER_ENTRYPOINT: `${DEFAULT_ENTRYPOINT},0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` })).toThrow(/exactly one/);
    expect(() => loadConfig({ ...base, BUNDLER_ENTRYPOINT: 'nope' })).toThrow(/not an address/);
  });

  it('treats empty values as unset', () => {
    expect(loadConfig({ ...base, BUNDLER_PORT: '', BUNDLER_ENTRYPOINT: '' })).toMatchObject({ port: 4337, entryPoint: DEFAULT_ENTRYPOINT });
  });
});
