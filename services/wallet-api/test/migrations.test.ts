import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDb } from '../src/db/index.js';
import { runMigrations } from '../src/migrate.js';
import { pruneExpiredChallenges } from '../src/services/housekeeping.js';
import { stopPostgres } from './postgres.js';

const MIGRATIONS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations');

/**
 * 0007 adds the tenant lifecycle to a table that already holds live tenants, so it must backfill
 * every existing row as an active, seed-managed tenant — anything else would suspend or orphan a
 * running deployment's tenants on upgrade.
 */
describe('migration 0007_tenant_lifecycle', () => {
  let container: StartedPostgreSqlContainer;
  let client: pg.Client;

  beforeAll(async () => {
    container = await new PostgreSqlContainer('postgres:17-alpine').start();
    // apply everything before 0007, as an upgraded deployment would have it
    const before = fs.mkdtempSync(path.join(os.tmpdir(), 'giano-migrations-'));
    for (const file of fs.readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql') && f < '0007')) {
      fs.copyFileSync(path.join(MIGRATIONS_DIR, file), path.join(before, file));
    }
    await runMigrations(container.getConnectionUri(), before);
    client = new pg.Client({ connectionString: container.getConnectionUri() });
    await client.connect();
    const { rows } = await client.query(
      `INSERT INTO tenants (slug, wallet_origin, rp_id, rp_name, expected_origins)
       VALUES ('acme', 'https://wallet.acme.app', 'wallet.acme.app', 'Acme', ARRAY['https://wallet.acme.app'])
       RETURNING id`,
    );
    await client.query(`INSERT INTO tenant_admin_keys (tenant_id, key_hash) VALUES ($1, 'abc')`, [rows[0].id]);
  });

  afterAll(async () => {
    await client?.end();
    await stopPostgres(container);
  });

  it('backfills existing tenants as active, seed-managed, version 1, and their keys as seed-created', async () => {
    expect(await runMigrations(container.getConnectionUri())).toEqual(['0007_tenant_lifecycle.sql']);
    const tenant = await client.query(`SELECT status, managed_by, version, status_changed_at FROM tenants WHERE slug = 'acme'`);
    expect(tenant.rows[0]).toEqual({ status: 'active', managed_by: 'seed', version: 1, status_changed_at: null });
    const key = await client.query(`SELECT created_by FROM tenant_admin_keys`);
    expect(key.rows[0].created_by).toBe('seed');
  });

  it('refuses a status or owner outside the lifecycle', async () => {
    await expect(client.query(`UPDATE tenants SET status = 'archived'`)).rejects.toThrow(/check constraint/);
    await expect(client.query(`UPDATE tenants SET managed_by = 'tenant'`)).rejects.toThrow(/check constraint/);
  });

  it('creates the operator and history tables', async () => {
    const { rows } = await client.query(
      `SELECT table_name FROM information_schema.tables
       WHERE table_name IN ('operator_challenges', 'operator_sessions', 'tenant_history') ORDER BY table_name`,
    );
    expect(rows.map((r) => r.table_name)).toEqual(['operator_challenges', 'operator_sessions', 'tenant_history']);
  });

  it('is a no-op on a second run', async () => {
    expect(await runMigrations(container.getConnectionUri())).toEqual([]);
  });

  it('housekeeping drops challenges expired over a day ago and keeps younger ones', async () => {
    const { rows } = await client.query(`SELECT id FROM tenants WHERE slug = 'acme'`);
    const tenantId = rows[0].id;
    for (const [challenge, age] of [['old', '2 days'], ['recent', '1 hour']]) {
      await client.query(
        `INSERT INTO challenges (challenge, kind, tenant_id, expires_at) VALUES ($1, 'registration', $2, now() - $3::interval)`,
        [challenge, tenantId, age],
      );
      await client.query(
        `INSERT INTO operator_challenges (nonce, address, message, expires_at) VALUES ($1, '0xabc', 'm', now() - $2::interval)`,
        [challenge, age],
      );
    }
    const { db, pool } = createDb(container.getConnectionUri());
    try {
      await pruneExpiredChallenges(db);
    } finally {
      await pool.end();
    }
    expect((await client.query(`SELECT challenge FROM challenges`)).rows.map((r) => r.challenge)).toEqual(['recent']);
    expect((await client.query(`SELECT nonce FROM operator_challenges`)).rows.map((r) => r.nonce)).toEqual(['recent']);
  });
});
