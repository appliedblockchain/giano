import { lt, sql } from 'drizzle-orm';
import type { Db } from '../db/index.js';
import { operatorChallenges } from '../db/schema.js';
import { createChallengeService } from './challenges.js';

/** How often the sweep runs. Rows it removes are already a day past their expiry. */
export const HOUSEKEEPING_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Drops ceremony and operator sign-in challenges that expired more than a day ago. Every replica
 * may run it: the deletes are idempotent, and a challenge that old can no longer be consumed.
 * The day of slack keeps a just-expired row around for anyone reading the logs of a failed attempt.
 */
export async function pruneExpiredChallenges(db: Db): Promise<void> {
  // the TTL is irrelevant to prune(), which only deletes
  await createChallengeService(db, 0).prune();
  await db.delete(operatorChallenges).where(lt(operatorChallenges.expiresAt, sql`now() - interval '1 day'`));
}
