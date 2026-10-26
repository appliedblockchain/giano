import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDb, type Db } from '../src/db/index.js';
import { tenantAdminKeys, tenantHistory, tenants } from '../src/db/schema.js';
import { runMigrations } from '../src/migrate.js';
import { retireTenantsSeed, SEED_RETIREMENT_ACTOR } from '../src/services/tenants-seed-retirement.js';
import { sha256hex } from '../src/services/tenants.js';
import { stopPostgres } from './postgres.js';

/** ONE-TIME MIGRATION — deleted together with services/tenants-seed-retirement.ts. */
describe('retireTenantsSeed', () => {
  let container: StartedPostgreSqlContainer;
  let db: Db;
  let pool: { end: () => Promise<void> };
  const log = { info: () => {}, warn: () => {} };
  const seeded = (slug: string, status: 'active' | 'suspended' | 'deleted' = 'active') =>
    db.insert(tenants).values({ slug, walletOrigin: `https://wallet.${slug}.app`, rpId: `wallet.${slug}.app`, rpName: slug, expectedOrigins: [`https://wallet.${slug}.app`], managedBy: 'seed', status });

  beforeAll(async () => {
    container = await new PostgreSqlContainer('postgres:17-alpine').start();
    await runMigrations(container.getConnectionUri());
    ({ db, pool } = createDb(container.getConnectionUri()));
  });

  afterAll(async () => {
    await pool?.end();
    await stopPostgres(container);
  });

  beforeEach(async () => {
    await db.execute(sql`TRUNCATE tenant_history, tenant_admin_keys, tenants CASCADE`);
  });

  it('hands every seed-managed tenant, in any state, to the operators, keeping fields, keys and state', async () => {
    await seeded('acme');
    await seeded('paused', 'suspended');
    const [acme] = await db.select().from(tenants).where(eq(tenants.slug, 'acme'));
    await db.insert(tenantAdminKeys).values({ tenantId: acme.id, keyHash: sha256hex('acme-admin-key-0001') });
    expect((await retireTenantsSeed(db, log)).sort()).toEqual(['acme', 'paused']);
    const rows = await db.select().from(tenants).orderBy(tenants.slug);
    expect(rows.map((r) => [r.slug, r.managedBy, r.status, r.version])).toEqual([
      ['acme', 'operator', 'active', 2],
      ['paused', 'operator', 'suspended', 2],
    ]);
    expect((await db.select().from(tenantAdminKeys)).map((k) => k.keyHash)).toEqual([sha256hex('acme-admin-key-0001')]);
    const entries = await db.select().from(tenantHistory).where(eq(tenantHistory.tenantId, acme.id));
    expect(entries).toEqual([expect.objectContaining({ action: 'adopt', actor: SEED_RETIREMENT_ACTOR, before: expect.objectContaining({ managedBy: 'seed' }), after: expect.objectContaining({ managedBy: 'operator' }) })]);
  });

  it('does nothing on a database with no seed-managed tenant', async () => {
    expect(await retireTenantsSeed(db, log)).toEqual([]);
    expect(await db.select().from(tenantHistory)).toEqual([]);
  });

  it('two replicas booting at once adopt each tenant once', async () => {
    await seeded('acme');
    const { db: replica, pool: replicaPool } = createDb(container.getConnectionUri());
    try {
      const results = await Promise.all([retireTenantsSeed(db, log), retireTenantsSeed(replica, log)]);
      expect(results.flat()).toEqual(['acme']);
    } finally {
      await replicaPool.end();
    }
    expect(await db.select().from(tenantHistory)).toHaveLength(1);
  });

  it('warns when TENANTS_SEED is still set, and ignores it', async () => {
    const warn = vi.fn();
    vi.stubEnv('TENANTS_SEED', JSON.stringify([{ slug: 'ignored', walletOrigin: 'https://wallet.ignored.app', rpName: 'Ignored', openRegistration: true }]));
    try {
      await retireTenantsSeed(db, { info: () => {}, warn });
    } finally {
      vi.unstubAllEnvs();
    }
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('TENANTS_SEED is set but no longer read'));
    expect(await db.select().from(tenants)).toEqual([]);
  });
});
