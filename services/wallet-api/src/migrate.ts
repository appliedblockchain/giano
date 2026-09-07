/**
 * One-shot plain-SQL migration runner. Applies migrations/*.sql in filename order,
 * recording applied files in the `migrations` table. Safe to run repeatedly and
 * concurrently (advisory lock). Bundled into the image as dist/migrate.js.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const MIGRATION_LOCK_KEY = 0x67_69_61_6e_6f; // "giano"

export async function runMigrations(databaseUrl: string, migrationsDir?: string): Promise<string[]> {
  const dir =
    migrationsDir ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  const applied: string[] = [];
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_KEY]);
    await client.query(
      'CREATE TABLE IF NOT EXISTS migrations (filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())',
    );
    for (const file of files) {
      const { rowCount } = await client.query('SELECT 1 FROM migrations WHERE filename = $1', [file]);
      if (rowCount) continue;
      const sql = fs.readFileSync(path.join(dir, file), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING', [file]);
        await client.query('COMMIT');
        applied.push(file);
      } catch (error) {
        await client.query('ROLLBACK');
        throw new Error(`Migration ${file} failed: ${(error as Error).message}`);
      }
    }
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_KEY]);
  } finally {
    await client.end();
  }
  return applied;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error('DATABASE_URL is required');
    process.exit(1);
  }
  runMigrations(databaseUrl)
    .then((applied) => {
      console.log(applied.length ? `Applied: ${applied.join(', ')}` : 'No pending migrations');
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
