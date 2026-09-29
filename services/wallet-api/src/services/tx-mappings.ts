import { mappingCovers, validateMapping, type Mapping, type ValidationIssue } from '@appliedblockchain/giano-tx-describe';
import { and, desc, eq } from 'drizzle-orm';
import type { Db } from '../db/index.js';
import { tenantTxMappings, tenantTxMappingsHistory } from '../db/schema.js';

/**
 * Transaction display mappings: the ERC-7730 descriptors a tenant publishes so the wallet can
 * explain calls to its contracts.
 *
 * Mirrors the sponsorship rules in shape and in trust model. A mapping is validated on write
 * with per-path issues and nothing partial is ever stored; it is validated *again* when served,
 * because a row written under yesterday's rules must not become today's explanation of a
 * transaction. A row that fails is omitted from what the wallet gets and flagged in what the
 * admin sees, so the operator can fix it while no user is shown a description the service no
 * longer trusts.
 */

/** Descriptors are small; a registry entry is a few KiB. Anything larger is not a mapping. */
export const MAX_MAPPING_BYTES = 64 * 1024;

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

export function normaliseContract(input: string): string | null {
  return ADDRESS_RE.test(input) ? input.toLowerCase() : null;
}

export type MappingCheck = { ok: true; descriptor: Mapping } | { ok: false; issues: ValidationIssue[] };

/**
 * Validates a descriptor and its binding to the key it is being stored under. A descriptor that
 * is valid but binds some other contract, or the same contract on another chain only, is
 * refused: served by (chain, contract), it would never match anything, and a tenant that made
 * the mistake should hear about it now.
 */
export function checkMapping(descriptor: unknown, chainId: number, contract: string): MappingCheck {
  const validation = validateMapping(descriptor);
  if (!validation.ok) return { ok: false, issues: validation.issues };
  const mapping = descriptor as Mapping;
  if (!mappingCovers(mapping, chainId, contract)) {
    return {
      ok: false,
      issues: [
        {
          path: 'context.contract.deployments',
          message: `the descriptor does not bind chain ${chainId} and contract ${contract}; add { "chainId": ${chainId}, "address": "${contract}" } to its deployments`,
        },
      ],
    };
  }
  return { ok: true, descriptor: mapping };
}

export type StoredMapping = {
  id: string;
  contract: string;
  descriptor: unknown;
  updatedAt: Date;
  updatedByKeyHash: string | null;
  /** Re-validated on read: false means the row is not served. */
  valid: boolean;
  issues: ValidationIssue[];
};

export function createTxMappingService(db: Db) {
  const revalidate = (row: typeof tenantTxMappings.$inferSelect): StoredMapping => {
    const check = checkMapping(row.descriptor, row.chainId, row.contract);
    return {
      id: row.id,
      contract: row.contract,
      descriptor: row.descriptor,
      updatedAt: row.updatedAt,
      updatedByKeyHash: row.updatedByKeyHash,
      valid: check.ok,
      issues: check.ok ? [] : check.issues,
    };
  };

  return {
    async list(tenantId: string, chainId: number): Promise<StoredMapping[]> {
      const rows = await db
        .select()
        .from(tenantTxMappings)
        .where(and(eq(tenantTxMappings.tenantId, tenantId), eq(tenantTxMappings.chainId, chainId)))
        .orderBy(tenantTxMappings.contract);
      return rows.map(revalidate);
    },

    async get(tenantId: string, chainId: number, contract: string): Promise<StoredMapping | null> {
      const [row] = await db
        .select()
        .from(tenantTxMappings)
        .where(and(eq(tenantTxMappings.tenantId, tenantId), eq(tenantTxMappings.chainId, chainId), eq(tenantTxMappings.contract, contract)))
        .limit(1);
      return row ? revalidate(row) : null;
    },

    /** Writes (or replaces) a mapping and records it in history, in one transaction. */
    async put(tenantId: string, chainId: number, contract: string, descriptor: Mapping, keyHash: string | null): Promise<StoredMapping> {
      return db.transaction(async (tx) => {
        await tx.insert(tenantTxMappingsHistory).values({ tenantId, chainId, contract, action: 'put', descriptor, createdByKeyHash: keyHash });
        const [row] = await tx
          .insert(tenantTxMappings)
          .values({ tenantId, chainId, contract, descriptor, updatedByKeyHash: keyHash })
          .onConflictDoUpdate({
            target: [tenantTxMappings.tenantId, tenantTxMappings.chainId, tenantTxMappings.contract],
            set: { descriptor, updatedAt: new Date(), updatedByKeyHash: keyHash },
          })
          .returning();
        return revalidate(row!);
      });
    },

    /** Deletes a mapping and records the deletion. False when there was nothing to delete. */
    async remove(tenantId: string, chainId: number, contract: string, keyHash: string | null): Promise<boolean> {
      return db.transaction(async (tx) => {
        const deleted = await tx
          .delete(tenantTxMappings)
          .where(and(eq(tenantTxMappings.tenantId, tenantId), eq(tenantTxMappings.chainId, chainId), eq(tenantTxMappings.contract, contract)))
          .returning({ id: tenantTxMappings.id });
        if (deleted.length === 0) return false;
        await tx.insert(tenantTxMappingsHistory).values({ tenantId, chainId, contract, action: 'delete', descriptor: null, createdByKeyHash: keyHash });
        return true;
      });
    },

    async history(tenantId: string, chainId: number, limit: number) {
      return db
        .select()
        .from(tenantTxMappingsHistory)
        .where(and(eq(tenantTxMappingsHistory.tenantId, tenantId), eq(tenantTxMappingsHistory.chainId, chainId)))
        .orderBy(desc(tenantTxMappingsHistory.createdAt), desc(tenantTxMappingsHistory.id))
        .limit(limit);
    },

    /**
     * What the wallet gets: every currently valid descriptor, plus the keys of any that failed
     * re-validation so the caller can log them. `updatedAt` is the newest row's, valid or not,
     * so a client cache key changes whenever anything changed.
     */
    async listForServing(tenantId: string, chainId: number): Promise<{ mappings: Mapping[]; invalid: string[]; updatedAt: Date | null }> {
      const rows = await this.list(tenantId, chainId);
      const updatedAt = rows.reduce<Date | null>((latest, row) => (latest && latest > row.updatedAt ? latest : row.updatedAt), null);
      return {
        mappings: rows.filter((r) => r.valid).map((r) => r.descriptor as Mapping),
        invalid: rows.filter((r) => !r.valid).map((r) => r.contract),
        updatedAt,
      };
    },
  };
}

export type TxMappingService = ReturnType<typeof createTxMappingService>;
