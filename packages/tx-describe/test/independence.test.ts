import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * R1: the library depends on nothing in Giano. Checked on the manifest, not the lockfile,
 * because the manifest is what a consumer installs.
 */
describe('independence (R1)', () => {
  const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as Record<string, Record<string, string>>;

  it('declares no Giano package in any dependency field', () => {
    for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies', 'devDependencies']) {
      const names = Object.keys(pkg[field] ?? {});
      expect(names.filter((n) => n.startsWith('@appliedblockchain/')), field).toEqual([]);
    }
  });

  it('imports no Giano package and no network API from src', () => {
    const src = ['index', 'describe', 'engine', 'builtins', 'validate', 'signature', 'types']
      .map((f) => readFileSync(join(__dirname, '..', 'src', `${f}.ts`), 'utf8'))
      .join('\n');
    expect(src).not.toMatch(/@appliedblockchain\//);
    expect(src).not.toMatch(/\bfetch\s*\(/);
    expect(src).not.toMatch(/XMLHttpRequest|WebSocket|createPublicClient/);
  });
});
