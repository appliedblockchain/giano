import { sql } from 'drizzle-orm';
import { createPublicClient, http } from 'viem';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { createDb } from './db/index.js';
import { runMigrations } from './migrate.js';
import { createPaymasterReader } from './services/paymaster-contract.js';
import { createPaymasterWatcher, type PaymasterWatcher } from './services/paymaster-watcher.js';
import { createLedgerService } from './services/sponsorship-ledger.js';
import { seedTenants } from './services/tenants.js';
import { tenants as tenantsTable } from './db/schema.js';
import { eq } from 'drizzle-orm';

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

/**
 * The chain watcher runs inside this process, behind a Postgres advisory lock so exactly one
 * replica ingests. It is enabled separately from sponsorship itself: a deployment can serve
 * sponsorship requests while a single designated replica does the watching.
 *
 * Nothing before this point is safe to point at real money — until the watcher runs, the
 * accounting invariant is not being checked at all.
 */
let watcher: PaymasterWatcher | undefined;
if (config.SPONSORSHIP_ENABLED && config.PAYMASTER_WATCHER_ENABLED) {
  const paymaster = createPaymasterReader({
    client: createPublicClient({ transport: http(config.RPC_URL) }),
    address: config.SPONSORSHIP_PAYMASTER_ADDRESS!,
  });

  const slugCache = new Map<string, string | undefined>();

  watcher = createPaymasterWatcher({
    db,
    pool,
    client: createPublicClient({ transport: http(config.RPC_URL) }),
    paymaster,
    ledger: createLedgerService(db),
    chainId: config.CHAIN_ID,
    pollMs: config.PAYMASTER_WATCHER_POLL_MS,
    confirmations: config.PAYMASTER_WATCHER_CONFIRMATIONS,
    reconcileIntervalMs: config.PAYMASTER_RECONCILE_INTERVAL_MS,
    async tenantSlug(tenantUuid) {
      if (slugCache.has(tenantUuid)) return slugCache.get(tenantUuid);
      const [row] = await db.select({ slug: tenantsTable.slug }).from(tenantsTable).where(eq(tenantsTable.id, tenantUuid));
      slugCache.set(tenantUuid, row?.slug);
      return row?.slug;
    },
    metrics: {
      setBalance(slug, balanceWei, reservedWei, deficitWei) {
        app.metrics.tenantBalanceWei.set({ tenant: slug }, Number(balanceWei));
        app.metrics.tenantReservedWei.set({ tenant: slug }, Number(reservedWei));
        app.metrics.tenantAvailableWei.set({ tenant: slug }, Number(balanceWei - reservedWei));
        app.metrics.tenantDeficitWei.set({ tenant: slug }, Number(deficitWei));
      },
      setInvariant({ breach, slackWei, depositWei, treasuryWei }) {
        app.metrics.paymasterInvariantBreach.set(breach ? 1 : 0);
        app.metrics.paymasterInvariantSlackWei.set(Number(slackWei));
        app.metrics.paymasterDepositWei.set(Number(depositWei));
        app.metrics.paymasterTreasuryWei.set(Number(treasuryWei));
      },
      setLag(blocks, seconds) {
        app.metrics.paymasterWatcherLagBlocks.set(Number(blocks));
        app.metrics.paymasterWatcherLagSeconds.set(seconds);
      },
      setDivergence(wei) {
        app.metrics.paymasterReconciliationDivergenceWei.set(Number(wei));
      },
    },
    logger: app.log,
  });

  await watcher.start();
}

const shutdown = async (signal: string) => {
  app.log.info({ signal }, 'shutting down');
  await watcher?.stop();
  await app.close();
  await pool.end();
  process.exit(0);
};
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

await app.listen({ host: config.HOST, port: config.PORT });
