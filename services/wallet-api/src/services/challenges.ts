import { randomBytes } from 'node:crypto';
import { and, eq, gt, isNull, lt, sql } from 'drizzle-orm';
import type { Db } from '../db/index.js';
import { challenges } from '../db/schema.js';

export type ChallengeKind = 'registration' | 'authentication';

const base64url = (buf: Buffer) => buf.toString('base64url');

export function createChallengeService(db: Db, ttlSeconds: number) {
  return {
    /** Issues a new one-time challenge (base64url of 32 random bytes), bound to a tenant. */
    async issue(kind: ChallengeKind, userId: string | null, tenantId: string): Promise<string> {
      const challenge = base64url(randomBytes(32));
      await db.insert(challenges).values({
        challenge,
        kind,
        tenantId,
        userId,
        expiresAt: new Date(Date.now() + ttlSeconds * 1000),
      });
      return challenge;
    },

    /**
     * Atomically consumes a challenge: only succeeds if it exists, is of the right
     * kind, has not been consumed, and has not expired. Single UPDATE … RETURNING
     * makes replay a guaranteed failure even under concurrency. The returned tenant
     * and user bindings MUST be enforced by the caller (C3).
     */
    async consume(challenge: string, kind: ChallengeKind): Promise<{ userId: string | null; tenantId: string } | null> {
      const rows = await db
        .update(challenges)
        .set({ consumedAt: sql`now()` })
        .where(
          and(
            eq(challenges.challenge, challenge),
            eq(challenges.kind, kind),
            isNull(challenges.consumedAt),
            gt(challenges.expiresAt, sql`now()`),
          ),
        )
        .returning({ userId: challenges.userId, tenantId: challenges.tenantId });
      return rows[0] ?? null;
    },

    /** Housekeeping: drop long-expired rows. */
    async prune(): Promise<void> {
      await db.delete(challenges).where(lt(challenges.expiresAt, sql`now() - interval '1 day'`));
    },
  };
}

export type ChallengeService = ReturnType<typeof createChallengeService>;
