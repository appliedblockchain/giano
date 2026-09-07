import { sql } from 'drizzle-orm';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { createDb } from './db/index.js';
import { runMigrations } from './migrate.js';
import { seedTenants } from './services/tenants.js';

const config = loadConfig();

if (config.RUN_MIGRATIONS) {
  const applied = await runMigrations(config.DATABASE_URL);
  if (applied.length > 0) {
    console.log(`Applied migrations: ${applied.join(', ')}`);
  }
}

const { db, pool } = createDb(config.DATABASE_URL);

// Declarative tenant provisioning (after migrations, before listen). A malformed seed
// already failed loadConfig; violations of the RP/origin invariants throw here.
if (config.TENANTS_SEED.length > 0) {
  await seedTenants(db, config.TENANTS_SEED);
  console.log(`Seeded tenants: ${config.TENANTS_SEED.map((t) => t.slug).join(', ')}`);
}
const [{ count: tenantCount }] = (await db.execute(sql`SELECT count(*)::int AS count FROM tenants`)).rows as [{ count: number }];
if (tenantCount === 0) {
  console.warn('WARNING: no tenants configured — every tenant-scoped route will refuse requests (set TENANTS_SEED)');
}

const app = await buildApp({ config, db });

const shutdown = async (signal: string) => {
  app.log.info({ signal }, 'shutting down');
  await app.close();
  await pool.end();
  process.exit(0);
};
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

await app.listen({ host: config.HOST, port: config.PORT });
