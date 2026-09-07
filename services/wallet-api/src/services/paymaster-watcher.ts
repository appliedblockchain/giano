import { and, eq, sql } from 'drizzle-orm';
import type { Address, Log, PublicClient } from 'viem';
import { parseAbiItem } from 'viem';
import pg from 'pg';
import type { Db } from '../db/index.js';
import { paymasterState, paymasterTenants, sponsorshipSettlements } from '../db/schema.js';
import type { PaymasterReader } from './paymaster-contract.js';
import type { LedgerService } from './sponsorship-ledger.js';

/**
 * The chain watcher.
 *
 * Everything the ledger knows about money comes from here. Balances are written straight through
 * from the `newBalance` each event carries, rather than accumulated as deltas, so the cache
 * *converges* on chain truth instead of drifting from it — a missed event corrects itself on the
 * next one for that tenant, and a reorged-away log is corrected the same way.
 *
 * Losing the watcher degrades rather than breaks: settlements queue up on chain, reservations
 * expire by TTL rather than by settlement, and authorisation keeps working against a slightly
 * stale balance. That is why the lag is a metric with an alert rather than a fatal condition.
 */

export type WatcherOptions = {
  db: Db;
  /** A dedicated pool: the advisory lock must be held by one connection for the process lifetime. */
  pool: pg.Pool;
  client: PublicClient;
  paymaster: PaymasterReader;
  ledger: LedgerService;
  chainId: number;
  pollMs: number;
  confirmations: number;
  reconcileIntervalMs: number;
  /** Tenant slug for a uuid, for metric labels. Absent for a tenant this deployment does not know. */
  tenantSlug: (tenantUuid: string) => Promise<string | undefined>;
  metrics?: WatcherMetrics;
  logger?: { info: (o: unknown, m?: string) => void; warn: (o: unknown, m?: string) => void; error: (o: unknown, m?: string) => void };
};

export type WatcherMetrics = {
  setBalance: (slug: string, balanceWei: bigint, reservedWei: bigint, deficitWei: bigint) => void;
  setInvariant: (args: { breach: boolean; slackWei: bigint; depositWei: bigint; treasuryWei: bigint }) => void;
  setLag: (blocks: bigint, seconds: number) => void;
  setDivergence: (wei: bigint) => void;
};

/**
 * `giano.paymaster.watcher` — distinct from the migration lock. Exactly one replica may ingest,
 * or a rolling deploy would process the same log twice.
 */
const WATCHER_LOCK_KEY = 0x67_70_6d_77;

/** Blocks to look back on a cold start, so a brief outage does not need a manual backfill. */
const COLD_START_LOOKBACK = 5_000n;

const EVENTS = {
  sponsored: parseAbiItem(
    'event Sponsored(bytes16 indexed tenantId, address indexed sender, bytes32 indexed userOpHash, uint256 gasCostWei, uint256 feeWei, uint256 overheadWei, uint256 newBalance, bool success)',
  ),
  deficit: parseAbiItem(
    'event SponsorshipDeficit(bytes16 indexed tenantId, bytes32 indexed userOpHash, uint256 shortfallWei, uint256 totalDeficitWei)',
  ),
  funded: parseAbiItem(
    'event TenantFunded(bytes16 indexed tenantId, address indexed from, uint256 amount, uint256 deficitCleared, uint256 newBalance)',
  ),
  withdrawn: parseAbiItem('event TenantWithdrawn(bytes16 indexed tenantId, address indexed to, uint256 amount, uint256 newBalance)'),
  registered: parseAbiItem('event TenantRegistered(bytes16 indexed tenantId, address indexed withdrawAddress, string slug)'),
} as const;

export type PaymasterWatcher = {
  start: () => Promise<void>;
  stop: () => Promise<void>;
  /** One ingestion pass. Exposed so tests can drive it deterministically. */
  pollOnce: () => Promise<{ from: bigint; to: bigint; events: number }>;
  /** One reconciliation pass. */
  reconcileOnce: () => Promise<{ breach: boolean; slackWei: bigint; divergenceWei: bigint }>;
};

/** UUID → the 16-byte id the contract keys on. */
function uuidToBytes16(tenantUuid: string): `0x${string}` {
  return `0x${tenantUuid.replace(/-/g, '').toLowerCase()}`;
}

/** bytes16 tenant id → the UUID form the database keys on. */
function bytes16ToUuid(id: string): string {
  const hex = id.replace(/^0x/, '').padStart(32, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export function createPaymasterWatcher(options: WatcherOptions): PaymasterWatcher {
  const { db, client, paymaster, ledger, chainId } = options;
  const log = options.logger ?? { info: () => {}, warn: () => {}, error: () => {} };

  let lockConnection: pg.PoolClient | undefined;
  let pollTimer: NodeJS.Timeout | undefined;
  let reconcileTimer: NodeJS.Timeout | undefined;
  let stopping = false;

  async function cursor(): Promise<bigint | null> {
    const [row] = await db.select({ block: paymasterState.lastSyncedBlock }).from(paymasterState).where(eq(paymasterState.chainId, chainId));
    return row?.block ?? null;
  }

  async function setCursor(block: bigint): Promise<void> {
    await db
      .insert(paymasterState)
      .values({ chainId, paymasterAddress: paymaster.address.toLowerCase(), lastSyncedBlock: block })
      .onConflictDoUpdate({ target: paymasterState.chainId, set: { lastSyncedBlock: block } });
  }

  /**
   * Writes a tenant's balance from what the event says it now is.
   *
   * `GREATEST(block, existing)` is the reorg and out-of-order guard: a log replayed from an older
   * block must not overwrite a newer balance, and re-processing the same log is then a no-op
   * rather than a correction in the wrong direction.
   */
  async function applyBalance(args: {
    tenantUuid: string;
    balanceWei: bigint;
    deficitWei?: bigint;
    blockNumber: bigint;
    withdrawAddress?: Address;
  }): Promise<void> {
    // `INSERT … SELECT FROM tenants` rather than `INSERT … VALUES`: the paymaster is shared, so it
    // can legitimately carry tenants this deployment has no row for — another deployment against
    // the same chain, or a tenant since removed. Their events are not our business, and one of
    // them must not fail the whole ingestion pass for everybody else.
    await db.execute(sql`
      INSERT INTO paymaster_tenants (tenant_id, chain_id, paymaster_address, balance_wei, deficit_wei, withdraw_address, last_synced_block, last_synced_at)
      SELECT
        t.id, ${chainId}, ${paymaster.address.toLowerCase()},
        ${args.balanceWei.toString()}, ${(args.deficitWei ?? 0n).toString()},
        ${args.withdrawAddress?.toLowerCase() ?? null}, ${args.blockNumber.toString()}, now()
      FROM tenants t
      WHERE t.id = ${args.tenantUuid}
      ON CONFLICT (tenant_id, chain_id) DO UPDATE SET
        balance_wei = CASE WHEN EXCLUDED.last_synced_block >= COALESCE(paymaster_tenants.last_synced_block, 0)
                           THEN EXCLUDED.balance_wei ELSE paymaster_tenants.balance_wei END,
        deficit_wei = CASE WHEN ${args.deficitWei === undefined} THEN paymaster_tenants.deficit_wei
                           WHEN EXCLUDED.last_synced_block >= COALESCE(paymaster_tenants.last_synced_block, 0)
                           THEN EXCLUDED.deficit_wei ELSE paymaster_tenants.deficit_wei END,
        withdraw_address = COALESCE(EXCLUDED.withdraw_address, paymaster_tenants.withdraw_address),
        last_synced_block = GREATEST(EXCLUDED.last_synced_block, COALESCE(paymaster_tenants.last_synced_block, 0)),
        last_synced_at = now()
    `);
  }

  async function ingestSponsored(entry: Log<bigint, number, false, typeof EVENTS.sponsored>): Promise<void> {
    const { tenantId, sender, userOpHash, gasCostWei, feeWei, overheadWei, newBalance, success } = entry.args as {
      tenantId: `0x${string}`;
      sender: Address;
      userOpHash: `0x${string}`;
      gasCostWei: bigint;
      feeWei: bigint;
      overheadWei: bigint;
      newBalance: bigint;
      success: boolean;
    };
    const tenantUuid = bytes16ToUuid(tenantId);

    // Keyed on (chain, userop hash), so re-processing a log after a reorg or a restart is a no-op
    // rather than a double count.
    // Same reasoning as `applyBalance`: an operation billed to a tenant this deployment does not
    // know is recorded without the reference rather than dropped, so the chain-level fact survives
    // even when the local tenant row does not.
    const knownTenant = await db.execute(sql`SELECT 1 FROM tenants WHERE id = ${tenantUuid}`);

    await db
      .insert(sponsorshipSettlements)
      .values({
        chainId,
        useropHash: userOpHash,
        tenantId: knownTenant.rows.length > 0 ? tenantUuid : null,
        sender: sender.toLowerCase(),
        gasCostWei: gasCostWei.toString(),
        feeWei: feeWei.toString(),
        overheadWei: overheadWei.toString(),
        totalWei: (gasCostWei + feeWei + overheadWei).toString(),
        success,
        blockNumber: entry.blockNumber!,
        logIndex: entry.logIndex!,
      })
      .onConflictDoNothing({ target: [sponsorshipSettlements.chainId, sponsorshipSettlements.useropHash] });

    await applyBalance({ tenantUuid, balanceWei: newBalance, blockNumber: entry.blockNumber! });
    await ledger.settle({ chainId, sender, useropHash: userOpHash });
  }

  return {
    async pollOnce() {
      const head = await client.getBlockNumber();
      const to = head > BigInt(options.confirmations) ? head - BigInt(options.confirmations) : 0n;
      const stored = await cursor();
      const from = stored === null ? (to > COLD_START_LOOKBACK ? to - COLD_START_LOOKBACK : 0n) : stored + 1n;

      if (to < from) {
        options.metrics?.setLag(0n, 0);
        return { from, to, events: 0 };
      }

      const address = paymaster.address;
      const [sponsored, deficits, funded, withdrawn, registered] = await Promise.all([
        client.getLogs({ address, event: EVENTS.sponsored, fromBlock: from, toBlock: to }),
        client.getLogs({ address, event: EVENTS.deficit, fromBlock: from, toBlock: to }),
        client.getLogs({ address, event: EVENTS.funded, fromBlock: from, toBlock: to }),
        client.getLogs({ address, event: EVENTS.withdrawn, fromBlock: from, toBlock: to }),
        client.getLogs({ address, event: EVENTS.registered, fromBlock: from, toBlock: to }),
      ]);

      // Registrations first, then funding, then spending: a settlement for a tenant whose row does
      // not exist yet would otherwise be dropped by the insert.
      for (const entry of registered) {
        const args = entry.args as { tenantId: `0x${string}`; withdrawAddress: Address; slug: string };
        await applyBalance({
          tenantUuid: bytes16ToUuid(args.tenantId),
          balanceWei: 0n,
          blockNumber: entry.blockNumber!,
          withdrawAddress: args.withdrawAddress,
        });
      }

      for (const entry of funded) {
        const args = entry.args as { tenantId: `0x${string}`; newBalance: bigint };
        await applyBalance({
          tenantUuid: bytes16ToUuid(args.tenantId),
          balanceWei: args.newBalance,
          // Funding clears a deficit on chain, so the cached deficit clears with it — which is
          // what un-blocks that tenant's authorisations again.
          deficitWei: 0n,
          blockNumber: entry.blockNumber!,
        });
      }

      for (const entry of withdrawn) {
        const args = entry.args as { tenantId: `0x${string}`; newBalance: bigint };
        await applyBalance({ tenantUuid: bytes16ToUuid(args.tenantId), balanceWei: args.newBalance, blockNumber: entry.blockNumber! });
      }

      for (const entry of sponsored) {
        await ingestSponsored(entry as never);
      }

      for (const entry of deficits) {
        const args = entry.args as { tenantId: `0x${string}`; totalDeficitWei: bigint; shortfallWei: bigint };
        const tenantUuid = bytes16ToUuid(args.tenantId);
        // A deficit means the pooled deposit — other tenants' money — absorbed a shortfall. It is
        // recorded, alerted and blocks this tenant from authorising again until it funds.
        await db
          .update(paymasterTenants)
          .set({ deficitWei: args.totalDeficitWei.toString() })
          .where(and(eq(paymasterTenants.tenantId, tenantUuid), eq(paymasterTenants.chainId, chainId)));
        log.error(
          { alert: 'sponsorship-deficit', tenantId: tenantUuid, shortfallWei: args.shortfallWei.toString() },
          'a sponsored operation settled for more than the tenant held',
        );
      }

      await setCursor(to);
      await ledger.expireStale();
      options.metrics?.setLag(head - to, 0);

      const total = sponsored.length + deficits.length + funded.length + withdrawn.length + registered.length;
      if (total > 0) log.info({ from: from.toString(), to: to.toString(), events: total }, 'paymaster events ingested');
      return { from, to, events: total };
    },

    /**
     * The accounting invariant, plus the drawdown check.
     *
     * Balances are re-read **from the contract** here, not accumulated from events, and that is
     * deliberate. Event ingestion gives the per-operation breakdown a tenant reconciles against
     * (R-43), but it cannot be the source of truth for a balance: a cold start only looks back a
     * bounded number of blocks, and on a real chain a tenant's funding transaction may be millions
     * of blocks behind the head. A cache built only from events would then read zero and every
     * sponsorship would be refused for "insufficient balance" — a stack that comes up looking
     * healthy and cannot sponsor anything.
     *
     * Reading the contract makes the cache converge on chain truth on every pass, whatever the
     * event history looks like.
     */
    async reconcileOnce() {
      const [treasury, deposit, blockNumber] = await Promise.all([paymaster.treasury(), paymaster.deposit(), client.getBlockNumber()]);

      // Every tenant this deployment could bill: one that has a ledger row, and one that has
      // configured sponsorship but has not been seen on chain yet.
      const known = await db.execute(sql`
        SELECT tenant_id FROM paymaster_tenants WHERE chain_id = ${chainId}
        UNION
        SELECT tenant_id FROM tenant_sponsorship WHERE chain_id = ${chainId}
      `);

      let tenantTotal = 0n;
      for (const row of known.rows as Array<{ tenant_id: string }>) {
        let onChain: Awaited<ReturnType<PaymasterReader['tenant']>>;
        try {
          onChain = await paymaster.tenant(uuidToBytes16(row.tenant_id));
        } catch (error) {
          log.warn({ err: error, tenantId: row.tenant_id }, 'could not read a tenant from the paymaster');
          continue;
        }

        // An unregistered tenant is not an error: it has configured rules but nobody has
        // registered it on chain yet, so it holds nothing and can sponsor nothing.
        if (!onChain.registered) continue;

        tenantTotal += onChain.balanceWei;
        await applyBalance({
          tenantUuid: row.tenant_id,
          balanceWei: onChain.balanceWei,
          deficitWei: onChain.deficitWei,
          blockNumber,
          withdrawAddress: onChain.withdrawAddress,
        });

        if (options.metrics) {
          const slug = await options.tenantSlug(row.tenant_id);
          if (slug) {
            const view = await ledger.getBalanceView(row.tenant_id, chainId);
            options.metrics.setBalance(slug, view.balanceWei, view.reservedWei, view.deficitWei);
          }
        }
      }

      const claims = tenantTotal + treasury;
      const breach = claims > deposit;
      const slackWei = deposit - claims;

      /*
       * Attributed spend against actual drawdown.
       *
       * Expressed as a change in slack rather than by summing settlements, and that is the whole
       * trick. Slack is `deposit − claims`. Every *explained* movement leaves it flat or growing:
       * funding raises both sides equally, a settlement lowers the ledger by at least what it
       * lowered the deposit by (the overhead allowance is a deliberate over-charge), and a
       * withdrawal lowers both by the same amount.
       *
       * So slack can only *shrink* if money left the deposit that no event accounted for — which
       * is the signature of sponsorships being issued that this backend never recorded, i.e. a
       * leaked signing key. Comparing sums of settlements against the deposit could not see that
       * without also modelling funding, withdrawals and fee collection; this needs none of them.
       */
      const [previous] = await db
        .select({ slack: paymasterState.invariantSlackWei })
        .from(paymasterState)
        .where(eq(paymasterState.chainId, chainId));

      const previousSlack = previous?.slack == null ? undefined : BigInt(previous.slack);
      const divergenceWei = previousSlack !== undefined && slackWei < previousSlack ? previousSlack - slackWei : 0n;

      await db
        .insert(paymasterState)
        .values({
          chainId,
          paymasterAddress: paymaster.address.toLowerCase(),
          treasuryWei: treasury.toString(),
          depositWei: deposit.toString(),
          invariantSlackWei: slackWei.toString(),
          checkedAt: new Date(),
        })
        .onConflictDoUpdate({
          target: paymasterState.chainId,
          set: {
            treasuryWei: treasury.toString(),
            depositWei: deposit.toString(),
            invariantSlackWei: slackWei.toString(),
            checkedAt: new Date(),
          },
        });

      options.metrics?.setInvariant({ breach, slackWei, depositWei: deposit, treasuryWei: treasury });
      options.metrics?.setDivergence(divergenceWei);

      if (breach) {
        log.error(
          { alert: 'paymaster-invariant-breach', claims: claims.toString(), deposit: deposit.toString() },
          'INSOLVENCY: tenant balances plus treasury exceed the paymaster deposit',
        );
      }
      if (divergenceWei > 0n) {
        log.error(
          { alert: 'paymaster-unexplained-drawdown', divergenceWei: divergenceWei.toString() },
          'the deposit fell by more than the observed events account for — sponsorships may be being issued that this backend did not record',
        );
      }

      return { breach, slackWei, divergenceWei };
    },

    /**
     * Acquires the singleton lock and starts polling. If another replica already holds the lock
     * this returns quietly — that is the intended outcome of a rolling deploy, not an error.
     */
    async start() {
      lockConnection = await options.pool.connect();
      const { rows } = await lockConnection.query<{ locked: boolean }>('SELECT pg_try_advisory_lock($1) AS locked', [WATCHER_LOCK_KEY]);
      if (!rows[0]?.locked) {
        lockConnection.release();
        lockConnection = undefined;
        log.info({ watcher: 'standby' }, 'another replica is running the paymaster watcher');
        return;
      }

      log.info({ watcher: 'active', paymaster: paymaster.address }, 'paymaster watcher started');

      const runPoll = async () => {
        if (stopping) return;
        try {
          await this.pollOnce();
        } catch (error) {
          log.warn({ err: error }, 'paymaster watcher poll failed');
        }
      };
      const runReconcile = async () => {
        if (stopping) return;
        try {
          await this.reconcileOnce();
        } catch (error) {
          log.warn({ err: error }, 'paymaster reconciliation failed');
        }
      };

      await runPoll();
      await runReconcile();
      pollTimer = setInterval(runPoll, options.pollMs);
      reconcileTimer = setInterval(runReconcile, options.reconcileIntervalMs);
      pollTimer.unref?.();
      reconcileTimer.unref?.();
    },

    async stop() {
      stopping = true;
      if (pollTimer) clearInterval(pollTimer);
      if (reconcileTimer) clearInterval(reconcileTimer);
      if (lockConnection) {
        await lockConnection.query('SELECT pg_advisory_unlock($1)', [WATCHER_LOCK_KEY]);
        lockConnection.release();
        lockConnection = undefined;
      }
    },
  };
}

export { bytes16ToUuid, uuidToBytes16 };
