import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import type pg from 'pg';
import type { PublicClient } from 'viem';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createDb, type Db } from '../src/db/index.js';
import { runMigrations } from '../src/migrate.js';
import type { PaymasterReader } from '../src/services/paymaster-contract.js';
import { createPaymasterWatcher, type PaymasterWatcher } from '../src/services/paymaster-watcher.js';
import type { LedgerService } from '../src/services/sponsorship-ledger.js';

/**
 * The watcher's singleton lock across replicas.
 *
 * A rolling deploy starts the new replica while the old one still holds the lock, so the new one
 * comes up in standby. These tests pin down that it does not stay there: whoever holds the lock
 * going away — drained or cut off — hands the watcher to the standby, and two replicas never
 * watch the same chain at once. The chain is a stub with no events; only the lock is under test.
 */

const CHAIN_ID = 31337;
const LOCK_RETRY_MS = 200;

const client = { getBlockNumber: async () => 0n, getLogs: async () => [] } as unknown as PublicClient;
const paymaster = {
  address: '0x0000000000000000000000000000000000000001',
  treasury: async () => 0n,
  deposit: async () => 0n,
} as unknown as PaymasterReader;
const ledger = { settle: async () => {}, expireStale: async () => {} } as unknown as LedgerService;

type Replica = { watcher: PaymasterWatcher; pool: pg.Pool; active: () => boolean };

async function waitFor(condition: () => boolean, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for the watcher lock to move');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe('paymaster watcher lock', () => {
  let container: StartedPostgreSqlContainer;
  let admin: { db: Db; pool: pg.Pool };
  const replicas: Replica[] = [];

  beforeAll(async () => {
    container = await new PostgreSqlContainer('postgres:17-alpine').start();
    await runMigrations(container.getConnectionUri());
    admin = createDb(container.getConnectionUri());
  });

  afterEach(async () => {
    for (const replica of replicas.splice(0)) {
      await replica.watcher.stop();
      await replica.pool.end();
    }
  });

  afterAll(async () => {
    await admin?.pool.end();
    await container?.stop();
  });

  /** One wallet-api replica: its own pool, as each process has. */
  function replica(): Replica {
    const { db, pool } = createDb(container.getConnectionUri());
    let active = false;
    const watcher = createPaymasterWatcher({
      db,
      pool,
      client,
      paymaster,
      ledger,
      chainId: CHAIN_ID,
      pollMs: 50,
      lockRetryMs: LOCK_RETRY_MS,
      confirmations: 0,
      reconcileIntervalMs: 50,
      tenantSlug: async () => undefined,
      metrics: {
        setBalance: () => {},
        setInvariant: () => {},
        setLag: () => {},
        setDivergence: () => {},
        setActive: (value) => {
          active = value;
        },
      },
    });
    const created = { watcher, pool, active: () => active };
    replicas.push(created);
    return created;
  }

  it('a standby replica takes over once the holder stops, as after a rolling deploy', async () => {
    const old = replica();
    await old.watcher.start();
    expect(old.active()).toBe(true);

    const next = replica();
    await next.watcher.start();
    expect(next.active()).toBe(false);

    await old.watcher.stop();
    await waitFor(() => next.active());
    expect(old.active()).toBe(false);
  });

  it('a standby replica takes over when the holder loses its connection, and the holder steps down', async () => {
    const first = replica();
    await first.watcher.start();
    const second = replica();
    await second.watcher.start();
    expect([first.active(), second.active()]).toEqual([true, false]);

    // Postgres frees an advisory lock with its session: cutting the holder's connection is what a
    // network partition or a database failover looks like from the replica's side.
    await admin.pool.query(`SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' AND granted`);

    await waitFor(() => !first.active() && second.active());
    // The old holder keeps competing for the lock but cannot take it while the new one holds it.
    await new Promise((resolve) => setTimeout(resolve, LOCK_RETRY_MS * 3));
    expect([first.active(), second.active()]).toEqual([false, true]);
  });
});
