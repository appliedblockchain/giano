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
    /**
     * Creates a session scoped to the WALLET the credential belongs to (WM-33): the
     * wallet address is captured onto the session row at issue time, so any credential
     * that is an owner of a wallet opens a session that can act for that wallet — the
     * relay's sender-binding rule needs no exception (WM-34). Refused for a credential
     * whose owner key was removed on-chain (WM-31).
     */
    async create(userId: string, credentialId: string): Promise<{ token: string; expiresAt: Date }> {
      const credential = await db.query.credentials.findFirst({ where: eq(credentials.id, credentialId) });
      if (!credential) throw new Error(`session refused: credential ${credentialId} is not registered`);
      if (credential.removedAt) throw new Error('session refused: credential is no longer an owner of the wallet');
      const token = randomBytes(32).toString('base64url');
      const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
      await db.insert(sessions).values({
        userId,
        credentialId,
        walletAddress: credential.walletAddress,
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
          // The session's OWN wallet binding (WM-33) — not the credential's column, which
          // exists for registry display; the two are equal today but scoped differently.
          walletAddress: sessions.walletAddress,
        })
        .from(sessions)
        .innerJoin(users, eq(users.id, sessions.userId))
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

    /**
     * Revokes every live session held by one credential — what makes a removed owner's
     * sessions stop working the moment the registry learns of the removal (WM-30, WM-31).
     */
    async revokeAllForCredential(credentialDbId: string): Promise<void> {
      await db
        .update(sessions)
        .set({ revokedAt: sql`now()` })
        .where(and(eq(sessions.credentialId, credentialDbId), isNull(sessions.revokedAt)));
    },
  };
}

export type SessionService = ReturnType<typeof createSessionService>;
