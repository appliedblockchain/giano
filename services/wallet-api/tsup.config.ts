import { readFileSync } from 'node:fs';
import { defineConfig } from 'tsup';

// The shared release version /v1/version reports (src/release-version.ts). The image build copies
// the connector's package.json outside the workspace, where pnpm would take it for a package with
// missing dependencies, and points at it with GIANO_RELEASE_PACKAGE_JSON.
const releasePackage = process.env.GIANO_RELEASE_PACKAGE_JSON ?? new URL('../../packages/connector/package.json', import.meta.url);
const releaseVersion = (JSON.parse(readFileSync(releasePackage, 'utf8')) as { version: string }).version;

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
  define: { __GIANO_RELEASE_VERSION__: JSON.stringify(releaseVersion) },
});
