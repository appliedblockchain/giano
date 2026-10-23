/**
 * Creates a local stack's test tenants (services/tenant-fixtures.ts). Run once per bring-up by the
 * dev, e2e and loopback compose files, before wallet-api starts; never by a live deployment, which
 * boots with no tenants and gets them from its operators.
 *
 *   DATABASE_URL=… TENANT_FIXTURES='[{ "slug": …, "adminKeys": [ … ] }]' node dist/tenant-fixtures.js
 *
 * Applies pending migrations first (idempotent, and safe alongside a wallet-api doing the same), so
 * it can run against an empty database. Exits non-zero on any refused fixture: a stack whose
 * tenants did not load must fail to come up rather than come up empty.
 */
import { createDb } from './db/index.js';
import { runMigrations } from './migrate.js';
import { loadTenantFixtures, parseTenantFixtures } from './services/tenant-fixtures.js';

const fail = (message: string): never => {
  console.error(message);
  process.exit(1);
};

const databaseUrl = process.env.DATABASE_URL ?? fail('DATABASE_URL is required');
const raw = process.env.TENANT_FIXTURES ?? fail('TENANT_FIXTURES is required: a JSON array of tenants');

let fixtures;
try {
  fixtures = parseTenantFixtures(raw);
} catch (error) {
  fail((error as Error).message);
}

const applied = await runMigrations(databaseUrl);
if (applied.length > 0) console.log(`Applied migrations: ${applied.join(', ')}`);

const { db, pool } = createDb(databaseUrl);
try {
  const { created, existing } = await loadTenantFixtures(db, fixtures!);
  if (created.length > 0) console.log(`Created fixture tenants: ${created.join(', ')}`);
  if (existing.length > 0) console.log(`Already present, left as they are: ${existing.join(', ')}`);
} catch (error) {
  fail((error as Error).message);
} finally {
  await pool.end();
}
