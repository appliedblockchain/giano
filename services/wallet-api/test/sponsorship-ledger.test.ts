import { eq, sql } from 'drizzle-orm';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createDb, type Db } from '../src/db/index.js';
import { runMigrations } from '../src/migrate.js';
import { paymasterTenants, sponsorshipReservations, tenants } from '../src/db/schema.js';
import { createLedgerService, type LedgerService } from '../src/services/sponsorship-ledger.js';

/**
 * The reservation ledger, against a real Postgres.
 *
 * The concurrency test here is the executable form of the decision the whole segregation design
 * rests on. It must not be skipped, and it must not pass merely because the test happens to
 * serialise the requests: the reservations are issued with `Promise.all` precisely so that a
 * read-then-write implementation would fail it.
 */

const CHAIN_ID = 31337;
const PAYMASTER = '0x15a2075f2407427c5dd0bde9d1966c48bd70e2f2';
const SENDER = '0x1111111111111111111111111111111111111234';
const OTHER_SENDER = '0x5555555555555555555555555555555555555555';

describe('reservation ledger', () => {
  let container: StartedPostgreSqlContainer;
  let db: Db;
  let pool: { end: () => Promise<void> };
  let ledger: LedgerService;
  let tenantA: string;
  let tenantB: string;

  beforeAll(async () => {
    container = await new PostgreSqlContainer('postgres:17-alpine').start();
    await runMigrations(container.getConnectionUri());
    ({ db, pool } = createDb(container.getConnectionUri()));
    ledger = createLedgerService(db);

    const rows = await db
      .insert(tenants)
      .values([
        { slug: 'ledger-a', walletOrigin: 'http://a.test', rpId: 'a.test', rpName: 'A', expectedOrigins: ['http://a.test'] },
        { slug: 'ledger-b', walletOrigin: 'http://b.test', rpId: 'b.test', rpName: 'B', expectedOrigins: ['http://b.test'] },
      ])
      .returning({ id: tenants.id, slug: tenants.slug });
    tenantA = rows.find((r) => r.slug === 'ledger-a')!.id;
    tenantB = rows.find((r) => r.slug === 'ledger-b')!.id;
  }, 120_000);

  afterAll(async () => {
    await pool.end();
    await container.stop();
  });

  beforeEach(async () => {
    await db.delete(sponsorshipReservations);
    await db.delete(paymasterTenants);
  });

  async function fund(tenantId: string, balanceWei: bigint, deficitWei = 0n) {
    await db.insert(paymasterTenants).values({
      tenantId,
      chainId: CHAIN_ID,
      paymasterAddress: PAYMASTER,
      balanceWei: balanceWei.toString(),
      deficitWei: deficitWei.toString(),
    });
  }

  const request = (tenantId: string, nonce: bigint, totalWei: bigint) => ({
    tenantId,
    chainId: CHAIN_ID,
    sender: SENDER,
    nonce,
    maxCostWei: totalWei,
    feeWei: 0n,
    overheadWei: 0n,
    ttlSeconds: 300,
  });

  it('reports a zero view for a tenant with no row, rather than throwing', async () => {
    expect(await ledger.getBalanceView(tenantA, CHAIN_ID)).toEqual({ balanceWei: 0n, reservedWei: 0n, deficitWei: 0n });
  });

  it('refuses a tenant with no row at all — the join is what makes deny-by-default hold here', async () => {
    const result = await ledger.reserve(request(tenantA, 0n, 1n));
    expect(result.reserved).toBe(false);
  });

  it('reserves against an available balance and reports it as reserved', async () => {
    await fund(tenantA, 1000n);
    const result = await ledger.reserve(request(tenantA, 0n, 400n));
    expect(result.reserved).toBe(true);

    const view = await ledger.getBalanceView(tenantA, CHAIN_ID);
    expect(view.balanceWei).toBe(1000n);
    expect(view.reservedWei).toBe(400n);
  });

  it('refuses when the total exceeds the balance', async () => {
    await fund(tenantA, 100n);
    const result = await ledger.reserve(request(tenantA, 0n, 101n));
    expect(result).toEqual({ reserved: false, cause: 'insufficient-available-balance' });
  });

  it('allows a reservation for exactly the whole balance', async () => {
    await fund(tenantA, 100n);
    expect((await ledger.reserve(request(tenantA, 0n, 100n))).reserved).toBe(true);
  });

  /**
   * The scenario D5 describes, and the reason this ledger exists at all.
   *
   * Three operations, each individually affordable, collectively not. On chain each one would pass
   * validation, because at validation time nothing has been debited — and they would settle
   * together for more than the tenant holds. The contract could not resolve that after the fact,
   * because refusing to settle would revert transactions the network had already executed and
   * charged for. So the third one has to be refused *before its signature exists*.
   */
  it('never lets concurrent reservations collectively overdraw a balance', async () => {
    await fund(tenantA, 10n);

    const results = await Promise.all([
      ledger.reserve(request(tenantA, 1n, 5n)),
      ledger.reserve(request(tenantA, 2n, 5n)),
      ledger.reserve(request(tenantA, 3n, 5n)),
    ]);

    const granted = results.filter((r) => r.reserved);
    expect(granted).toHaveLength(2);
    expect(results.filter((r) => !r.reserved)).toHaveLength(1);

    const view = await ledger.getBalanceView(tenantA, CHAIN_ID);
    expect(view.reservedWei).toBe(10n);
    expect(view.reservedWei).toBeLessThanOrEqual(view.balanceWei);
  });

  it('holds under heavier contention', async () => {
    await fund(tenantA, 100n);
    const results = await Promise.all(Array.from({ length: 40 }, (_, i) => ledger.reserve(request(tenantA, BigInt(i), 10n))));

    expect(results.filter((r) => r.reserved)).toHaveLength(10);
    const view = await ledger.getBalanceView(tenantA, CHAIN_ID);
    expect(view.reservedWei).toBe(100n);
  });

  it("keeps one tenant's reservations out of another's available balance", async () => {
    await fund(tenantA, 100n);
    await fund(tenantB, 100n);

    await ledger.reserve({ ...request(tenantA, 1n, 100n), sender: SENDER });

    expect((await ledger.getBalanceView(tenantB, CHAIN_ID)).reservedWei).toBe(0n);
    expect((await ledger.reserve({ ...request(tenantB, 1n, 100n), sender: OTHER_SENDER })).reserved).toBe(true);
  });

  /**
   * A Giano wallet address is derived from the passkey and is tenant-agnostic, so the same wallet
   * really can transact under two tenants. The EntryPoint nonce, however, is per *sender* — so for
   * any (sender, nonce) pair at most one operation can ever land, whichever tenant authorised it.
   *
   * The live-reservation index is therefore deliberately tenant-agnostic: two live authorisations
   * for one operation would reserve funds twice for something that can only happen once. The
   * second request is refused rather than double-reserved.
   */
  it('refuses a second live authorisation for the same operation even from a different tenant', async () => {
    await fund(tenantA, 1000n);
    await fund(tenantB, 1000n);

    expect((await ledger.reserve({ ...request(tenantA, 4n, 10n), sender: SENDER })).reserved).toBe(true);
    expect(await ledger.reserve({ ...request(tenantB, 4n, 10n), sender: SENDER })).toEqual({
      reserved: false,
      cause: 'duplicate-in-flight',
    });

    // And the refusal costs the other tenant nothing: its balance is untouched.
    expect((await ledger.getBalanceView(tenantB, CHAIN_ID)).reservedWei).toBe(0n);
  });

  it('refuses a second live reservation for the same operation', async () => {
    await fund(tenantA, 1000n);
    expect((await ledger.reserve(request(tenantA, 7n, 10n))).reserved).toBe(true);
    const second = await ledger.reserve(request(tenantA, 7n, 10n));
    expect(second).toEqual({ reserved: false, cause: 'duplicate-in-flight' });
  });

  it('blocks every reservation while a deficit stands', async () => {
    await fund(tenantA, 1_000_000n, 1n);
    expect((await ledger.reserve(request(tenantA, 0n, 1n))).reserved).toBe(false);
  });

  describe('release and expiry', () => {
    it('frees the funds immediately when a request fails after reserving', async () => {
      await fund(tenantA, 100n);
      const result = await ledger.reserve(request(tenantA, 1n, 100n));
      expect(result.reserved).toBe(true);

      await ledger.release((result as { id: string }).id);

      expect((await ledger.getBalanceView(tenantA, CHAIN_ID)).reservedWei).toBe(0n);
      expect((await ledger.reserve(request(tenantA, 2n, 100n))).reserved).toBe(true);
    });

    it('sweeps a reservation whose authorisation can no longer be used', async () => {
      await fund(tenantA, 100n);
      const result = await ledger.reserve(request(tenantA, 1n, 100n));
      await db
        .update(sponsorshipReservations)
        .set({ expiresAt: new Date(Date.now() - 1000) })
        .where(eq(sponsorshipReservations.id, (result as { id: string }).id));

      // An expired reservation stops counting against the balance even before the sweep runs, so
      // a stalled sweeper cannot lock a tenant out of its own funds.
      expect((await ledger.getBalanceView(tenantA, CHAIN_ID)).reservedWei).toBe(0n);

      expect(await ledger.expireStale()).toBe(1);
      const [row] = await db.select().from(sponsorshipReservations).where(eq(sponsorshipReservations.id, (result as { id: string }).id));
      expect(row.state).toBe('expired');
    });

    /**
     * The expiry has to be computed in the database's clock domain, not this process's.
     *
     * Every read compares `expires_at` against `now()`. If it were *written* from the application
     * clock, a replica running behind the database would insert a reservation already expired in
     * database time — it would stop counting against the balance while its authorisation was still
     * valid on-chain, which is an overdraw that no amount of locking catches.
     *
     * The assertion is exact on purpose. Postgres `now()` is the transaction timestamp, so a
     * reservation whose `expires_at` and `created_at` both come from it differs by precisely the
     * TTL. Computed from `Date.now()` instead, the difference would carry the latency of the two
     * queries that precede the insert, and would not be exact.
     */
    it('computes the expiry in database time, not this process\'s clock', async () => {
      await fund(tenantA, 100n);
      const result = await ledger.reserve(request(tenantA, 7n, 1n));

      const { rows } = await db.execute<{ drift_seconds: string }>(
        sql`SELECT EXTRACT(EPOCH FROM (expires_at - created_at))::text AS drift_seconds
            FROM sponsorship_reservations WHERE id = ${(result as { id: string }).id}`,
      );
      expect(Number(rows[0].drift_seconds)).toBe(300);
    });

    it('lets the same operation be re-authorised once its reservation expired', async () => {
      await fund(tenantA, 100n);
      const first = await ledger.reserve(request(tenantA, 1n, 100n));
      await db
        .update(sponsorshipReservations)
        .set({ expiresAt: new Date(Date.now() - 1000) })
        .where(eq(sponsorshipReservations.id, (first as { id: string }).id));
      await ledger.expireStale();

      expect((await ledger.reserve(request(tenantA, 1n, 100n))).reserved).toBe(true);
    });
  });

  describe('settlement', () => {
    it('settles by userop hash once one has been attached', async () => {
      await fund(tenantA, 100n);
      const result = await ledger.reserve(request(tenantA, 1n, 50n));
      const id = (result as { id: string }).id;
      await ledger.attachUseropHash(id, '0xabc');

      expect(await ledger.settle({ chainId: CHAIN_ID, sender: SENDER, useropHash: '0xabc' })).toBe(id);
      expect((await ledger.getBalanceView(tenantA, CHAIN_ID)).reservedWei).toBe(0n);
    });

    // The signature binds (sender, nonce), so that pair is always available even when the wallet
    // never told us the hash — which is the normal case for an operation submitted outside the relay.
    it('falls back to (sender, nonce) when no hash was recorded', async () => {
      await fund(tenantA, 100n);
      const result = await ledger.reserve(request(tenantA, 9n, 50n));

      const settled = await ledger.settle({ chainId: CHAIN_ID, sender: SENDER, nonce: 9n, useropHash: '0xdef' });
      expect(settled).toBe((result as { id: string }).id);

      const [row] = await db.select().from(sponsorshipReservations).where(eq(sponsorshipReservations.id, settled!));
      expect(row.state).toBe('settled');
      expect(row.useropHash).toBe('0xdef');
    });

    it('is idempotent, so re-processing a log after a reorg changes nothing', async () => {
      await fund(tenantA, 100n);
      const result = await ledger.reserve(request(tenantA, 1n, 50n));
      await ledger.attachUseropHash((result as { id: string }).id, '0xabc');

      expect(await ledger.settle({ chainId: CHAIN_ID, sender: SENDER, useropHash: '0xabc' })).not.toBeNull();
      expect(await ledger.settle({ chainId: CHAIN_ID, sender: SENDER, useropHash: '0xabc' })).toBeNull();
    });

    it('reports no match for an operation it never authorised', async () => {
      expect(await ledger.settle({ chainId: CHAIN_ID, sender: SENDER, nonce: 1n, useropHash: '0xnope' })).toBeNull();
    });
  });

  describe('ensureTenantRow', () => {
    it('creates a zero-balance row so the refusal names the real problem', async () => {
      await ledger.ensureTenantRow({ tenantId: tenantA, chainId: CHAIN_ID, paymasterAddress: PAYMASTER });
      expect(await ledger.getBalanceView(tenantA, CHAIN_ID)).toEqual({ balanceWei: 0n, reservedWei: 0n, deficitWei: 0n });
    });

    it('never clobbers a balance the watcher already wrote', async () => {
      await fund(tenantA, 500n);
      await ledger.ensureTenantRow({ tenantId: tenantA, chainId: CHAIN_ID, paymasterAddress: PAYMASTER });
      expect((await ledger.getBalanceView(tenantA, CHAIN_ID)).balanceWei).toBe(500n);
    });
  });
});
