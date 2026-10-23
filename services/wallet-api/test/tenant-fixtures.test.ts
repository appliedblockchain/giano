import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createDb, type Db } from '../src/db/index.js';
import { tenantAdminKeys, tenantHistory, tenants } from '../src/db/schema.js';
import { runMigrations } from '../src/migrate.js';
import { FIXTURE_ACTOR, loadTenantFixtures, parseTenantFixtures, type TenantFixture } from '../src/services/tenant-fixtures.js';
import { checkOriginClaims, sha256hex, tenantUniqueViolation } from '../src/services/tenants.js';
import { stopPostgres } from './postgres.js';

/**
 * The local stacks' test tenants (services/tenant-fixtures.ts): a fixture is a create and nothing
 * else, passes the same cross-tenant origin check as every tenant write, and never rewrites a
 * tenant that already exists.
 */
describe('loadTenantFixtures', () => {
  let container: StartedPostgreSqlContainer;
  let db: Db;
  let pool: { end: () => Promise<void> };

  const acme = (overrides: Record<string, unknown> = {}): TenantFixture =>
    parseTenantFixtures(
      JSON.stringify([{ slug: 'acme', walletOrigin: 'https://wallet.acme.app', rpName: 'Acme', adminKeys: ['acme-admin-key-0001'], ...overrides }]),
    )[0];

  const row = async (slug: string) => (await db.select().from(tenants).where(eq(tenants.slug, slug)))[0];
  const history = async (slug: string) => {
    const tenant = await row(slug);
    return db.select().from(tenantHistory).where(eq(tenantHistory.tenantId, tenant.id)).orderBy(tenantHistory.createdAt);
  };
  const keyHashes = async (slug: string) => {
    const tenant = await row(slug);
    return (await db.select({ keyHash: tenantAdminKeys.keyHash }).from(tenantAdminKeys).where(eq(tenantAdminKeys.tenantId, tenant.id))).map((r) => r.keyHash);
  };
  const platformTenant = (slug: string, walletOrigin: string, status: 'active' | 'suspended' | 'deleted' = 'active') =>
    db
      .insert(tenants)
      .values({ slug, walletOrigin, rpId: new URL(walletOrigin).hostname, rpName: slug, expectedOrigins: [walletOrigin], status })
      .returning();

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

  it('creates an unknown slug as an active tenant, with hashed keys and a create entry by fixture', async () => {
    expect(await loadTenantFixtures(db, [acme({ id: '11111111-1111-4111-8111-111111111111' })])).toEqual({ created: ['acme'], existing: [] });
    const tenant = await row('acme');
    expect(tenant).toMatchObject({ id: '11111111-1111-4111-8111-111111111111', status: 'active', version: 1, rpId: 'wallet.acme.app' });
    expect(await keyHashes('acme')).toEqual([sha256hex('acme-admin-key-0001')]);
    expect((await history('acme')).map((h) => [h.action, h.actor])).toEqual([['create', FIXTURE_ACTOR]]);
    expect(JSON.stringify(await history('acme'))).not.toContain('acme-admin-key');
  });

  it('leaves an existing slug exactly as it is: a restart never reverts an admin edit', async () => {
    await loadTenantFixtures(db, [acme()]);
    await db.update(tenants).set({ rpName: 'Edited in the console', status: 'suspended' }).where(eq(tenants.slug, 'acme'));
    expect(await loadTenantFixtures(db, [acme({ adminKeys: ['acme-admin-key-0002'] })])).toEqual({ created: [], existing: ['acme'] });
    expect(await row('acme')).toMatchObject({ rpName: 'Edited in the console', status: 'suspended', version: 1 });
    expect(await keyHashes('acme')).toEqual([sha256hex('acme-admin-key-0001')]);
    expect(await history('acme')).toHaveLength(1);
  });

  it('never re-creates a deleted slug', async () => {
    await platformTenant('acme', 'https://wallet.acme.app', 'deleted');
    expect(await loadTenantFixtures(db, [acme()])).toEqual({ created: [], existing: ['acme'] });
    expect((await row('acme')).status).toBe('deleted');
  });

  it('refuses a fixture that claims an origin another tenant holds, naming it and its state', async () => {
    await platformTenant('runtime', 'https://pay.wallet.acme.app', 'suspended');
    await expect(loadTenantFixtures(db, [acme({ expectedOrigins: ['https://pay.wallet.acme.app'] })])).rejects.toThrow(
      /origin https:\/\/pay\.wallet\.acme\.app is already claimed by tenant "runtime" \(suspended\)/,
    );
  });

  it("keeps a deleted tenant's origins claimed", async () => {
    await platformTenant('gone', 'https://pay.wallet.acme.app', 'deleted');
    await expect(loadTenantFixtures(db, [acme({ expectedOrigins: ['https://pay.wallet.acme.app'] })])).rejects.toThrow(/claimed by tenant "gone"/);
  });

  it('two loaders at once create the tenant once', async () => {
    const { db: other, pool: otherPool } = createDb(container.getConnectionUri());
    try {
      await Promise.all([loadTenantFixtures(db, [acme()]), loadTenantFixtures(other, [acme()])]);
    } finally {
      await otherPool.end();
    }
    expect(await history('acme')).toHaveLength(1);
  });

  it('rejects malformed fixtures before writing anything', () => {
    expect(() => parseTenantFixtures('not json')).toThrow(/not valid JSON/);
    expect(() => parseTenantFixtures(JSON.stringify([{ slug: 'acme', walletOrigin: 'https://wallet.acme.app', rpName: 'Acme', adminKeys: ['short'] }]))).toThrow(/at least 16 characters/);
    const twice = { slug: 'acme', walletOrigin: 'https://wallet.acme.app', rpName: 'Acme', openRegistration: true };
    expect(() => parseTenantFixtures(JSON.stringify([twice, { ...twice, walletOrigin: 'https://wallet.other.app' }]))).toThrow(/duplicate slug/);
  });

  it('serialises concurrent claims of one origin: exactly one writer wins', async () => {
    const claim = (slug: string) =>
      db.transaction(async (tx) => {
        const walletOrigin = `https://${slug}.wallet.acme.app`;
        const claims = [walletOrigin, 'https://shared.wallet.acme.app'];
        const clash = await checkOriginClaims(tx, { selfId: null, claims });
        if (clash) return 'clash';
        // widen the race window: without the lock both would pass the check
        await tx.execute(sql`SELECT pg_sleep(0.2)`);
        await tx.insert(tenants).values({ slug, walletOrigin, rpId: new URL(walletOrigin).hostname, rpName: slug, expectedOrigins: claims });
        return 'created';
      });
    expect((await Promise.all([claim('one'), claim('two')])).sort()).toEqual(['clash', 'created']);
  });

  it('maps a unique violation to the tenant field it is about', async () => {
    await loadTenantFixtures(db, [acme()]);
    const error = await db
      .insert(tenants)
      .values({ slug: 'acme', walletOrigin: 'https://other.app', rpId: 'other.app', rpName: 'x', expectedOrigins: [] })
      .catch((e: unknown) => e);
    expect(tenantUniqueViolation(error)).toBe('slug');
    expect(tenantUniqueViolation(new Error('unrelated'))).toBeNull();
  });
});
