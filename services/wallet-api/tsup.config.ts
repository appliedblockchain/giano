import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    migrate: 'src/migrate.ts',
    // the one-shot task in infra/iac/ecs_tasks_oneshot.tf runs this by path, so it has to be
    // its own entry rather than a chunk
    'provision-sponsorship': 'src/provision-sponsorship.ts',
  },
  format: ['esm'],
  target: 'node22',
  sourcemap: true,
  clean: true,
  // workspace dep is bundled at image build via `pnpm deploy`; keep runtime deps external
  tsconfig: './tsconfig.json',
});
