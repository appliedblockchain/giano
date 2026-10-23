import { count, desc, eq, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '../db/index.js';
import { operatorHistory, operators, operatorSessions } from '../db/schema.js';
import type { OperatorSeed } from '../environments.js';
import type { OperatorContext } from './operator-sessions.js';
import { TenantWriteError, type Tx } from './tenants.js';

/**
 * The operators (specs/OPERATOR-ADMIN-SPECS.md §4.1). A row, not configuration: the init step seeds
 * an environment's bootstrap operators into an empty table, and from then on only a signed-in
 * operator changes it. Two guards keep a deployment administrable — nobody removes the last
 * operator, and nobody removes themselves — and every change is recorded in operator_history.
 */

export type Operator = typeof operators.$inferSelect;

export const operatorInputSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9-]{1,64}$/, 'lowercase id, e.g. ops-oncall'),
    address: z
      .string()
      .regex(/^0x[0-9a-fA-F]{40}$/, 'expected a 0x address')
      .transform((address) => address.toLowerCase()),
  })
  .strict();

export type OperatorInput = z.infer<typeof operatorInputSchema>;

const actorOf = (operator: OperatorContext) => `operator:${operator.id}:${operator.address}`;

/** Serialises every write to the operators, so the last-operator check cannot race. */
async function lockOperatorWrites(tx: Tx): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext('giano:operators'))`);
}

/**
 * Writes `seeds` only when no operator exists, recording each as `bootstrap` by
 * `bootstrap:<environment>`. Returns the ids written — empty when the table already had an
 * operator. Safe to run on every task start and from concurrent replicas.
 */
export async function bootstrapOperators(db: Db, environment: string, seeds: readonly OperatorSeed[]): Promise<string[]> {
  return db.transaction(async (tx) => {
    await lockOperatorWrites(tx);
    const [{ n }] = await tx.select({ n: count() }).from(operators);
    if (Number(n) > 0 || seeds.length === 0) return [];
    const actor = `bootstrap:${environment}`;
    const rows = seeds.map((seed) => operatorInputSchema.parse(seed));
    await tx.insert(operators).values(rows.map((row) => ({ ...row, addedBy: actor })));
    await tx.insert(operatorHistory).values(rows.map((row) => ({ operatorId: row.id, address: row.address, action: 'bootstrap' as const, actor })));
    return rows.map((row) => row.id);
  });
}

export function createOperatorService(db: Db) {
  return {
    async list(): Promise<Operator[]> {
      return db.select().from(operators).orderBy(operators.createdAt, operators.id);
    },

    async byAddress(address: string): Promise<Operator | undefined> {
      const [row] = await db.select().from(operators).where(eq(operators.address, address.toLowerCase()));
      return row;
    },

    async add(input: OperatorInput, by: OperatorContext): Promise<Operator> {
      return db.transaction(async (tx) => {
        await lockOperatorWrites(tx);
        const [taken] = await tx
          .select()
          .from(operators)
          .where(sql`${operators.id} = ${input.id} OR ${operators.address} = ${input.address}`);
        if (taken) {
          const field = taken.id === input.id ? 'id' : 'address';
          throw new TenantWriteError(409, 'conflict', `an operator with that ${field} already exists`, { field });
        }
        const [row] = await tx
          .insert(operators)
          .values({ ...input, addedBy: actorOf(by) })
          .returning();
        await tx.insert(operatorHistory).values({ operatorId: row.id, address: row.address, action: 'add', actor: actorOf(by), operatorSessionId: by.sessionId });
        return row;
      });
    },

    /** Refuses the last operator and yourself; revokes the removed operator's open sessions. */
    async remove(id: string, by: OperatorContext): Promise<void> {
      await db.transaction(async (tx) => {
        await lockOperatorWrites(tx);
        const [row] = await tx.select().from(operators).where(eq(operators.id, id));
        if (!row) throw new TenantWriteError(404, 'not-found', `operator "${id}" not found`);
        if (row.address === by.address) throw new TenantWriteError(409, 'self-removal', 'you cannot remove yourself; ask another operator');
        const [{ n }] = await tx.select({ n: count() }).from(operators);
        if (Number(n) <= 1) throw new TenantWriteError(409, 'last-operator', 'the last operator cannot be removed');
        await tx.delete(operators).where(eq(operators.id, id));
        await tx
          .update(operatorSessions)
          .set({ revokedAt: sql`now()` })
          .where(sql`${operatorSessions.address} = ${row.address} AND ${operatorSessions.revokedAt} IS NULL`);
        await tx.insert(operatorHistory).values({ operatorId: row.id, address: row.address, action: 'remove', actor: actorOf(by), operatorSessionId: by.sessionId });
      });
    },

    /** Newest first. */
    async history(limit: number) {
      return db.select().from(operatorHistory).orderBy(desc(operatorHistory.createdAt), desc(operatorHistory.id)).limit(limit);
    },
  };
}

export type OperatorService = ReturnType<typeof createOperatorService>;
