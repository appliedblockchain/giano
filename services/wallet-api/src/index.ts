import { sql } from 'drizzle-orm';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { createDb } from './db/index.js';
import { runMigrations } from './migrate.js';
import { describeFailure, isFatalFailure, verifyChain } from './services/chain-verify.js';
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
const registry = app.chains;

// ── Chain verification at boot (§3.5, §4.2) ──────────────────────────────────────
//
// Every configured chain is verified against the chain ITSELF, before serving traffic:
// endpoint identity, EntryPoint, canonical factory and implementation, paymaster where
// sponsorship is enabled, and the live factory cross-check. Structural misconfiguration
// refuses start-up; mere unreachability does not (S7, MC-92): the deployment starts,
// marks that chain unavailable, serves its other chains and retries in the background.
{
  const probeAddresses = new Map<number, string>();
  let fatal = false;
  for (const chain of registry.all) {
    const verification = await verifyChain(chain.descriptor, chain.publicClient);
    for (const failure of verification.failures) {
      const line = describeFailure(chain.chainId, failure);
      if (isFatalFailure(failure)) {
        fatal = true;
        app.log.fatal({ chainId: chain.chainId, failure }, line);
      } else {
        app.log.warn({ chainId: chain.chainId, failure }, line);
      }
    }
    if (verification.failures.some((failure) => failure.kind === 'unreachable')) {
      chain.status = 'unavailable';
    }
    if (verification.probeAddress) probeAddresses.set(chain.chainId, verification.probeAddress.toLowerCase());
  }
  // MC-22: every served chain's factory must derive the SAME address for the same owner.
  // Comparing addresses alone would miss a factory at the right address running different
  // code; this catches it.
  if (new Set(probeAddresses.values()).size > 1) {
    fatal = true;
    app.log.fatal(
      { probeAddresses: Object.fromEntries(probeAddresses) },
      'address-identity violation: the served chains derive DIFFERENT account addresses for the same owner (MC-16, MC-22)',
    );
  }
  if (fatal) {
    app.log.fatal('refusing to start: a configured chain failed structural verification — see the failures above (MC-20, MC-49)');
    process.exit(1);
  }
}

for (const chain of registry.all) {
  app.metrics.chainAvailable.set({ chain: String(chain.chainId) }, chain.status === 'ready' ? 1 : 0);
}

// Background prober: re-runs the reachability half of verifyChain and flips status
// (MC-54). It never re-runs the structural half as a status flip — a factory that ceases
// to match canonical is an alert and a page (MC-104), not a silent 'unavailable'.
const CHAIN_PROBE_INTERVAL_MS = 15_000;
const prober = setInterval(() => {
  for (const chain of registry.all) {
    if (chain.status === 'ready') {
      // Reachability only: a factory that ceases to match canonical is a page (MC-104),
      // never a silent flip to 'unavailable'.
      void chain.publicClient
        .getChainId()
        .then((reported) => {
          if (reported !== chain.chainId) {
            app.log.error({ chainId: chain.chainId, reported }, 'ALERT: chain endpoint reports a different chain id than declared');
            chain.status = 'unavailable';
          }
          app.metrics.chainAvailable.set({ chain: String(chain.chainId) }, chain.status === 'ready' ? 1 : 0);
        })
        .catch((error: Error) => {
          app.log.warn({ chainId: chain.chainId, error: error.message }, 'chain became unreachable');
          chain.status = 'unavailable';
          app.metrics.chainAvailable.set({ chain: String(chain.chainId) }, 0);
        });
    } else {
      // A chain coming BACK must pass the full structural verification before it is served
      // again — it may have missed the boot-time gate entirely (it was unreachable then),
      // and an endpoint swapped out during the outage must not slip in unverified.
      void verifyChain(chain.descriptor, chain.publicClient)
        .then((verification) => {
          const fatalFailures = verification.failures.filter(isFatalFailure);
          if (verification.reachable && fatalFailures.length === 0) {
            app.log.info({ chainId: chain.chainId }, 'chain is reachable and verified — serving it again');
            chain.status = 'ready';
          } else if (verification.reachable) {
            for (const failure of fatalFailures) {
              app.log.error({ chainId: chain.chainId, failure }, `ALERT: ${describeFailure(chain.chainId, failure)}`);
            }
          }
          app.metrics.chainAvailable.set({ chain: String(chain.chainId) }, chain.status === 'ready' ? 1 : 0);
        })
        .catch(() => {
          app.metrics.chainAvailable.set({ chain: String(chain.chainId) }, 0);
        });
    }
  }
}, CHAIN_PROBE_INTERVAL_MS);
prober.unref();

/**
 * The chain watchers run inside this process, behind a Postgres advisory lock so exactly one
 * replica ingests. Enabled separately from sponsorship itself: a deployment can serve
 * sponsorship requests while a single designated replica does the watching.
 *
 * One watcher PER CHAIN, as independent loops (MC-73): each has its own cursor, its own
 * confirmation depth and its own lag metrics, so one chain falling behind or being
 * unreachable never stalls another.
 *
 * Nothing before this point is safe to point at real money — until the watcher runs, the
 * accounting invariant is not being checked at all.
 */
const watchers: PaymasterWatcher[] = [];
if (config.SPONSORSHIP_ENABLED && config.PAYMASTER_WATCHER_ENABLED) {
  const slugCache = new Map<string, string | undefined>();
  const tenantSlug = async (tenantUuid: string) => {
    if (slugCache.has(tenantUuid)) return slugCache.get(tenantUuid);
    const [row] = await db.select({ slug: tenantsTable.slug }).from(tenantsTable).where(eq(tenantsTable.id, tenantUuid));
    slugCache.set(tenantUuid, row?.slug);
    return row?.slug;
  };

  for (const chain of registry.all) {
    if (!chain.paymaster) continue;
    const chainLabel = String(chain.chainId);
    const watcher = createPaymasterWatcher({
      db,
      pool,
      client: chain.publicClient,
      paymaster: chain.paymaster,
      ledger: createLedgerService(db),
      chainId: chain.chainId,
      pollMs: config.PAYMASTER_WATCHER_POLL_MS,
      confirmations: config.PAYMASTER_WATCHER_CONFIRMATIONS,
      reconcileIntervalMs: config.PAYMASTER_RECONCILE_INTERVAL_MS,
      tenantSlug,
      metrics: {
        setBalance(slug, balanceWei, reservedWei, deficitWei) {
          app.metrics.tenantBalanceWei.set({ tenant: slug, chain: chainLabel }, Number(balanceWei));
          app.metrics.tenantReservedWei.set({ tenant: slug, chain: chainLabel }, Number(reservedWei));
          app.metrics.tenantAvailableWei.set({ tenant: slug, chain: chainLabel }, Number(balanceWei - reservedWei));
          app.metrics.tenantDeficitWei.set({ tenant: slug, chain: chainLabel }, Number(deficitWei));
        },
        setInvariant({ breach, slackWei, depositWei, treasuryWei }) {
          app.metrics.paymasterInvariantBreach.set({ chain: chainLabel }, breach ? 1 : 0);
          app.metrics.paymasterInvariantSlackWei.set({ chain: chainLabel }, Number(slackWei));
          app.metrics.paymasterDepositWei.set({ chain: chainLabel }, Number(depositWei));
          app.metrics.paymasterTreasuryWei.set({ chain: chainLabel }, Number(treasuryWei));
        },
        setLag(blocks, seconds) {
          app.metrics.paymasterWatcherLagBlocks.set({ chain: chainLabel }, Number(blocks));
          app.metrics.paymasterWatcherLagSeconds.set({ chain: chainLabel }, seconds);
        },
        setDivergence(wei) {
          app.metrics.paymasterReconciliationDivergenceWei.set({ chain: chainLabel }, Number(wei));
        },
      },
      logger: app.log.child({ chainId: chain.chainId }),
    });
    watchers.push(watcher);
    await watcher.start();
  }
}

const shutdown = async (signal: string) => {
  app.log.info({ signal }, 'shutting down');
  clearInterval(prober);
  await Promise.all(watchers.map((watcher) => watcher.stop()));
  await app.close();
  await pool.end();
  process.exit(0);
};
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

await app.listen({ host: config.HOST, port: config.PORT });
