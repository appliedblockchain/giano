import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm', 'cjs'],
  platform: 'node',
  target: 'es2022',
  sourcemap: true,
  clean: true,
  tsconfig: './tsconfig.json',
  // The file names package.json `exports` names: .mjs/.d.mts for ESM, .js/.d.ts for CJS.
  outExtensions: ({ format }) => ({ js: format === 'es' ? '.mjs' : '.js', dts: format === 'es' ? '.d.mts' : '.d.ts' }),
  // Declarations from each source file alone (isolatedDeclarations): no TypeScript compiler involved,
  // so the build does not depend on its API. An export without explicit types fails the build.
  dts: { generator: 'oxc' },
});
