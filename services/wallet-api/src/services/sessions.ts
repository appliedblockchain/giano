import { createHash, randomBytes } from 'node:crypto';
import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import type { Db } from '../db/index.js';
import { credentials, sessions, users } from '../db/schema.js';

const sha256hex = (value: string) => createHash('sha256').update(value).digest('hex');

export type SessionContext = {
  sessionId: string;
  /**
   * Derived from the user's tenant_id: users are created inside a tenant-scoped
   * ceremony and never move, so no denormalized column on sessions is needed.
   */
  tenantId: string;
  userId: string;
  externalUserId: string;
  credentialId: string;
  walletAddress: string;
};

export function createSessionService(db: Db, ttlSeconds: number) {
  return {
    /** Creates a session and returns the opaque bearer token (only ever returned here). */
    async create(userId: string, credentialId: string): Promise<{ token: string; expiresAt: Date }> {
      const token = randomBytes(32).toString('base64url');
      const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
      await db.insert(sessions).values({
        userId,
        credentialId,
        tokenHash: sha256hex(token),
        expiresAt,
      });
      return { token, expiresAt };
    },

    /** Resolves a bearer token to its session context; null if unknown/expired/revoked. */
    async resolve(token: string): Promise<SessionContext | null> {
      const rows = await db
        .select({
          sessionId: sessions.id,
          tenantId: users.tenantId,
          userId: sessions.userId,
          externalUserId: users.externalId,
          credentialId: sessions.credentialId,
          walletAddress: credentials.walletAddress,
        })
        .from(sessions)
        .innerJoin(users, eq(users.id, sessions.userId))
        .innerJoin(credentials, eq(credentials.id, sessions.credentialId))
        .where(and(eq(sessions.tokenHash, sha256hex(token)), isNull(sessions.revokedAt), gt(sessions.expiresAt, sql`now()`)))
        .limit(1);
      return rows[0] ?? null;
    },

    async revoke(sessionId: string): Promise<void> {
      await db.update(sessions).set({ revokedAt: sql`now()` }).where(eq(sessions.id, sessionId));
    },

    async revokeAllForUser(userId: string): Promise<void> {
      await db.update(sessions).set({ revokedAt: sql`now()` }).where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)));
    },
  };
}

export type SessionService = ReturnType<typeof createSessionService>;
