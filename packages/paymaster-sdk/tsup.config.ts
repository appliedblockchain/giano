import { defineConfig } from 'tsup';

export default defineConfig({
  // `cli` is a second entry rather than a separate package: it is a thin shell over the same
  // client, and splitting it would mean versioning the two in step forever.
  entry: { index: 'src/index.ts', cli: 'cli/index.ts' },
  format: ['esm', 'cjs'],
  // Types are for the library; the CLI is an executable and nothing imports it.
  dts: { entry: { index: 'src/index.ts' } },
  sourcemap: true,
  clean: true,
  tsconfig: './tsconfig.json',
});
