import { and, eq, gt, sql } from 'drizzle-orm';
import type { Db } from '../db/index.js';
import { paymasterTenants, sponsorshipReservations } from '../db/schema.js';
import type { BalanceView } from './sponsorship-rules.js';

/**
 * The reservation ledger.
 *
 * This exists because the chain cannot be the primary gate for a tenant's balance. On-chain
 * validation sees one operation at a time and checks it against a balance nothing has yet
 * debited, so three individually-affordable operations can each pass validation and then settle
 * together for more than the tenant holds. The contract cannot resolve that after the fact —
 * refusing to settle would revert transactions the network has already executed and charged for —
 * so the only place to stop it is *before the third signature is issued*.
 *
 * Which makes the atomicity below the point of the whole file, not an optimisation: the check and
 * the write are one statement, so the outcome is correct under any number of concurrent requests
 * and any number of `wallet-api` replicas.
 */

export type ReservationRequest = {
  tenantId: string;
  chainId: number;
  sender: string;
  nonce: bigint;
  maxCostWei: bigint;
  feeWei: bigint;
  overheadWei: bigint;
  ttlSeconds: number;
};

export type ReservationResult =
  | { reserved: true; id: string; totalWei: bigint }
  | { reserved: false; cause: 'insufficient-available-balance' | 'duplicate-in-flight' };

export type LedgerService = {
  getBalanceView: (tenantId: string, chainId: number) => Promise<BalanceView>;
  reserve: (request: ReservationRequest) => Promise<ReservationResult>;
  release: (id: string) => Promise<void>;
  attachUseropHash: (id: string, useropHash: string) => Promise<void>;
  settle: (args: { chainId: number; sender: string; nonce?: bigint; useropHash: string }) => Promise<string | null>;
  expireStale: () => Promise<number>;
  ensureTenantRow: (args: { tenantId: string; chainId: number; paymasterAddress: string }) => Promise<void>;
};

export function createLedgerService(db: Db): LedgerService {
  return {
    /**
     * `available = balance − reserved` is computed, never stored, so it cannot go stale. The
     * deficit comes back separately because it is a different kind of "no": insufficient balance
     * clears when the tenant funds, a deficit is a hole the pooled deposit already absorbed.
     */
    async getBalanceView(tenantId, chainId) {
      // Two plain queries rather than one correlated subquery. A subquery correlating on
      // `paymaster_tenants.tenant_id` from inside a scan of `sponsorship_reservations r` binds the
      // unqualified column to `r` — the innermost scope — turning the predicate into
      // `r.tenant_id = r.tenant_id` and silently summing *every* tenant's reservations.
      const [row] = await db
        .select({ balanceWei: paymasterTenants.balanceWei, deficitWei: paymasterTenants.deficitWei })
        .from(paymasterTenants)
        .where(and(eq(paymasterTenants.tenantId, tenantId), eq(paymasterTenants.chainId, chainId)));

      if (!row) return { balanceWei: 0n, reservedWei: 0n, deficitWei: 0n };

      const [reserved] = await db
        .select({ total: sql<string>`COALESCE(SUM(${sponsorshipReservations.totalWei}), 0)::text` })
        .from(sponsorshipReservations)
        .where(
          and(
            eq(sponsorshipReservations.tenantId, tenantId),
            eq(sponsorshipReservations.chainId, chainId),
            eq(sponsorshipReservations.state, 'reserved'),
            // An expired reservation stops counting immediately, so a stalled sweeper can never
            // lock a tenant out of its own funds.
            gt(sponsorshipReservations.expiresAt, sql`now()`),
          ),
        );

      return {
        balanceWei: BigInt(row.balanceWei),
        reservedWei: BigInt(reserved?.total ?? '0'),
        deficitWei: BigInt(row.deficitWei),
      };
    },

    /**
     * Reserves, or refuses.
     *
     * The affordability test and the write are serialised per tenant by a row lock on that
     * tenant's `paymaster_tenants` row. That lock is load-bearing, not defensive.
     *
     * The obvious implementation — a single `INSERT … SELECT` whose `WHERE` compares the balance
     * against `SUM(reserved)` — looks atomic and is not. Under `READ COMMITTED` each statement
     * evaluates against a snapshot taken when it began, so two concurrent statements both see a
     * reservation set that predates the other's insert, both find the balance sufficient, and both
     * commit. Measured on Postgres 17, three concurrent requests for 5 wei against a balance of 10
     * were all three granted.
     *
     * Locking the tenant row first fixes it because `READ COMMITTED` takes a *fresh* snapshot for
     * every statement: whichever request acquires the lock second sees the first one's committed
     * reservation when it re-reads the sum. The cost is that one tenant's concurrent
     * authorisations serialise — which is exactly what is wanted here, since serialising the
     * affordability decision is the entire purpose.
     */
    async reserve(request) {
      const total = request.maxCostWei + request.feeWei + request.overheadWei;

      try {
        return await db.transaction(async (tx) => {
          const locked = await tx.execute(sql`
            SELECT balance_wei::text AS balance_wei, deficit_wei::text AS deficit_wei
            FROM paymaster_tenants
            WHERE tenant_id = ${request.tenantId} AND chain_id = ${request.chainId}
            FOR UPDATE
          `);

          const row = locked.rows[0] as { balance_wei: string; deficit_wei: string } | undefined;
          // No row means this tenant was never registered against the paymaster, which is
          // deny-by-default expressed in the storage layer.
          if (!row) return { reserved: false as const, cause: 'insufficient-available-balance' as const };
          if (BigInt(row.deficit_wei) > 0n) return { reserved: false as const, cause: 'insufficient-available-balance' as const };

          const sums = await tx.execute(sql`
            SELECT COALESCE(SUM(total_wei), 0)::text AS reserved
            FROM sponsorship_reservations
            WHERE tenant_id = ${request.tenantId}
              AND chain_id = ${request.chainId}
              AND state = 'reserved'
              AND expires_at > now()
          `);
          const reserved = BigInt((sums.rows[0] as { reserved: string }).reserved);

          if (BigInt(row.balance_wei) - reserved < total) {
            return { reserved: false as const, cause: 'insufficient-available-balance' as const };
          }

          const inserted = await tx
            .insert(sponsorshipReservations)
            .values({
              tenantId: request.tenantId,
              chainId: request.chainId,
              sender: request.sender.toLowerCase(),
              nonce: request.nonce.toString(),
              maxCostWei: request.maxCostWei.toString(),
              feeWei: request.feeWei.toString(),
              overheadWei: request.overheadWei.toString(),
              totalWei: total.toString(),
              state: 'reserved',
              // Database time, not this process's clock. Every read compares `expires_at`
              // against `now()`, so writing it from the application clock would let a replica
              // running behind the database insert a reservation that is *already* expired in
              // database time — it would stop counting against the balance while its
              // authorisation was still valid on-chain, which is an overdraw that no amount of
              // locking catches. One clock domain, expressed in one statement.
              expiresAt: sql`now() + make_interval(secs => ${request.ttlSeconds})`,
            })
            .returning({ id: sponsorshipReservations.id });

          return { reserved: true as const, id: inserted[0].id, totalWei: total };
        });
      } catch (error) {
        // The partial unique index on (chain_id, sender, nonce) WHERE state = 'reserved' turns a
        // double authorisation for the same operation into a database error rather than a
        // double-count against the balance.
        if (isUniqueViolation(error)) return { reserved: false, cause: 'duplicate-in-flight' };
        throw error;
      }
    },

    /**
     * Called when signing or submission failed inside the request. Releasing immediately rather
     * than waiting for the TTL matters: a failed submission that held funds for minutes would
     * look to the tenant exactly like a balance that had been spent.
     */
    async release(id) {
      await db
        .update(sponsorshipReservations)
        .set({ state: 'released' })
        .where(and(eq(sponsorshipReservations.id, id), eq(sponsorshipReservations.state, 'reserved')));
    },

    async attachUseropHash(id, useropHash) {
      await db.update(sponsorshipReservations).set({ useropHash }).where(eq(sponsorshipReservations.id, id));
    },

    /**
     * Settles the reservation a `Sponsored` event corresponds to. Matched on the userop hash when
     * the reservation recorded one, otherwise on (sender, nonce) — the pair the authorisation
     * signature itself binds.
     */
    async settle({ chainId, sender, nonce, useropHash }) {
      const byHash = await db
        .update(sponsorshipReservations)
        .set({ state: 'settled', settledAt: new Date() })
        .where(
          and(
            eq(sponsorshipReservations.chainId, chainId),
            eq(sponsorshipReservations.useropHash, useropHash),
            eq(sponsorshipReservations.state, 'reserved'),
          ),
        )
        .returning({ id: sponsorshipReservations.id });
      if (byHash[0]) return byHash[0].id;

      if (nonce === undefined) return null;
      const byNonce = await db
        .update(sponsorshipReservations)
        .set({ state: 'settled', settledAt: new Date(), useropHash })
        .where(
          and(
            eq(sponsorshipReservations.chainId, chainId),
            eq(sponsorshipReservations.sender, sender.toLowerCase()),
            eq(sponsorshipReservations.nonce, nonce.toString()),
            eq(sponsorshipReservations.state, 'reserved'),
          ),
        )
        .returning({ id: sponsorshipReservations.id });
      return byNonce[0]?.id ?? null;
    },

    /**
     * Sweeps reservations whose authorisation can no longer be used. The TTL is deliberately
     * longer than the authorisation's own validity window, so this can never free funds an
     * operation might still legitimately spend.
     */
    async expireStale() {
      const rows = await db.execute(sql`
        UPDATE sponsorship_reservations
        SET state = 'expired'
        WHERE state = 'reserved' AND expires_at <= now()
        RETURNING id
      `);
      return rows.rows.length;
    },

    /**
     * The reservation statement joins against `paymaster_tenants`, so a tenant with no row can
     * never be authorised. Registering the row with a zero balance keeps that true while making
     * the refusal "insufficient balance" rather than a silent absence.
     */
    async ensureTenantRow({ tenantId, chainId, paymasterAddress }) {
      await db
        .insert(paymasterTenants)
        .values({ tenantId, chainId, paymasterAddress: paymasterAddress.toLowerCase() })
        .onConflictDoNothing({ target: [paymasterTenants.tenantId, paymasterTenants.chainId] });
    },
  };
}

function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { code?: string }).code === '23505';
}
