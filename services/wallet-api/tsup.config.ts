import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', migrate: 'src/migrate.ts' },
  format: ['esm'],
  target: 'node22',
  sourcemap: true,
  clean: true,
  // workspace dep is bundled at image build via `pnpm deploy`; keep runtime deps external
  tsconfig: './tsconfig.json',
});
