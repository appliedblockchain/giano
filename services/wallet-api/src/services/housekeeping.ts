import { lt, sql } from "drizzle-orm";
import type { Db } from "../db/index.js";
import { platformAdminChallenges } from "../db/schema.js";
import { createChallengeService } from "./challenges.js";

/** How often the sweep runs. Rows it removes are already a day past their expiry. */
export const HOUSEKEEPING_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Drops ceremony and platform admin sign-in challenges that expired more than a day ago. Every replica
 * may run it: the deletes are idempotent, and a challenge that old can no longer be consumed.
 * The day of slack keeps a just-expired row around for anyone reading the logs of a failed attempt.
 */
export async function pruneExpiredChallenges(db: Db): Promise<void> {
	// the TTL is irrelevant to prune(), which only deletes
	await createChallengeService(db, 0).prune();
	await db
		.delete(platformAdminChallenges)
		.where(
			lt(platformAdminChallenges.expiresAt, sql`now() - interval '1 day'`),
		);
}
