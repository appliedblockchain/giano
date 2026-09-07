/**
 * Generates the committed OpenAPI document (openapi/openapi.json) from the live route
 * definitions. `--check` exits non-zero on drift (CI gate). The app is built with a
 * dummy config and never connects to anything.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createDb } from '../src/db/index.js';

const outPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'openapi.json');

// No TENANTS_SEED: buildApp never reads the tenants table at registration time
// (tenant resolution is strictly per-request), so no tenant data is needed here.
// Sponsorship is enabled here even though it is off by default at runtime: the ERC-7677 methods
// are part of the published contract a tenant integrates against, and a spec that omitted them
// would send tenants to the source to find out what the service speaks.
const config = loadConfig({
  NODE_ENV: 'production',
  GIANO_DEPLOYMENT_CLASS: 'production',
  LOG_LEVEL: 'error',
  DATABASE_URL: 'postgres://user:pass@localhost:5432/openapi-codegen',
  CHAIN_ID: '84532',
  RPC_URL: 'http://localhost:8545',
  BUNDLER_URL: 'http://localhost:4337',
  SPONSORSHIP_ENABLED: 'true',
  SPONSORSHIP_PAYMASTER_ADDRESS: '0x0000000000000000000000000000000000000001',
  // `local` is refused for a production deployment class, which is the point — so the document is
  // generated against the production signer shape.
  SPONSORSHIP_SIGNER_KIND: 'hsm',
  SPONSORSHIP_SIGNER_KEY_REF: 'arn:aws:kms:eu-west-1:000000000000:key/giano-sponsorship',
} as NodeJS.ProcessEnv);

const { db, pool } = createDb(config.DATABASE_URL);
const app = await buildApp({
  config,
  db,
  // Never called: generating the document touches no route handler.
  hsmSignerAdapter: {
    keyId: 'openapi-codegen',
    getAddress: async () => '0x0000000000000000000000000000000000000002',
    signDigest: async () => `0x${'00'.repeat(65)}`,
  },
});
await app.ready();
const spec = JSON.stringify(app.swagger(), null, 2) + '\n';
await app.close();
await pool.end();

if (process.argv.includes('--check')) {
  const committed = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf8') : '';
  if (committed !== spec) {
    console.error('openapi/openapi.json is out of date — run `pnpm openapi` and commit the result');
    process.exit(1);
  }
  console.log('openapi/openapi.json is up to date');
} else {
  fs.writeFileSync(outPath, spec);
  console.log(`Wrote ${outPath}`);
}
