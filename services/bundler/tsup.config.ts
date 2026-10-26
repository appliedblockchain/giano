import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm'],
  target: 'node22',
  sourcemap: true,
  clean: true,
  tsconfig: './tsconfig.json',
});
