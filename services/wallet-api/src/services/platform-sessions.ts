import { randomBytes } from 'node:crypto';
import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import { getAddress, recoverMessageAddress, type Hex } from 'viem';
import { createSiweMessage, generateSiweNonce, parseSiweMessage } from 'viem/siwe';
import type { Db } from '../db/index.js';
import { platformAdminChallenges, platformAdminSessions } from '../db/schema.js';
import { sha256hex } from './tenants.js';

/**
 * Platform admin sign-in with an Ethereum wallet (EIP-4361; specs/PLATFORM-ADMIN-SPECS.md §4).
 *
 * The server writes every sign-in message and keeps its exact text on the challenge row, and
 * verify accepts only that text (H-l). One string comparison therefore checks domain, uri,
 * version, chainId, statement and the time window against values only the server chose —
 * `validateSiweMessage` is not used, because in viem 2.31.6 it skips issuedAt, uri, version and
 * chainId, and checks no time at all when expirationTime is absent.
 *
 * Who is a platform admin is the platform admins table, read on every sign-in and every resolve: removing an
 * platform admin ends their sessions on the next request.
 */

export type PlatformAdminIdentity = { id: string; address: string };
export type PlatformAdminContext = PlatformAdminIdentity & { sessionId: string };

/** Why a sign-in or session failed: recorded in metrics and logs only, never told to the caller. */
export type PlatformAuthFailure = 'malformed-message' | 'bad-signature' | 'not-admin' | 'challenge-invalid';

export type PlatformSessionOptions = {
  /** The platform admin with this lowercase address, if there is one. */
  adminByAddress: (address: string) => Promise<PlatformAdminIdentity | undefined>;
  domain: string;
  uri: string;
  challengeTtlSeconds: number;
  sessionTtlSeconds: number;
};

export function createPlatformSessionService(db: Db, options: PlatformSessionOptions) {
  const minutes = Math.round(options.sessionTtlSeconds / 60);

  return {
    /**
     * A sign-in message for `address`. An address that is not a platform admin gets a message of the
     * same shape and nothing is stored, so the endpoint does not reveal who the platform admins are.
     */
    async issueChallenge({ address, chainId }: { address: string; chainId: number }): Promise<{ message: string }> {
      const issuedAt = new Date();
      const expirationTime = new Date(issuedAt.getTime() + options.challengeTtlSeconds * 1000);
      const nonce = generateSiweNonce();
      const message = createSiweMessage({
        domain: options.domain,
        uri: options.uri,
        address: getAddress(address),
        version: '1',
        chainId,
        nonce,
        statement: `Sign in to the Giano platform console. This grants access to tenant administration for ${minutes} minutes.`,
        issuedAt,
        expirationTime,
      });
      const lower = address.toLowerCase();
      if (await options.adminByAddress(lower)) {
        await db.insert(platformAdminChallenges).values({ nonce, address: lower, message, expiresAt: expirationTime });
      }
      return { message };
    },

    /**
     * Checks, in order: the message parses; the signature recovers (ECDSA only, so no RPC — sign-in
     * works when every chain is down) to the message's address; that address is a platform admin; and
     * the challenge is consumed atomically, which only succeeds for the exact issued text, unused
     * and unexpired. The consume is the only write.
     */
    async verify({ message, signature }: { message: string; signature: Hex }): Promise<
      { ok: true; admin: PlatformAdminIdentity; chainId: number } | { ok: false; reason: PlatformAuthFailure }
    > {
      let parsed: ReturnType<typeof parseSiweMessage>;
      try {
        parsed = parseSiweMessage(message);
      } catch {
        return { ok: false, reason: 'malformed-message' };
      }
      if (!parsed.address || !parsed.nonce || parsed.chainId === undefined) return { ok: false, reason: 'malformed-message' };

      let signer: string;
      try {
        signer = await recoverMessageAddress({ message, signature });
      } catch {
        return { ok: false, reason: 'bad-signature' };
      }
      const address = parsed.address.toLowerCase();
      if (signer.toLowerCase() !== address) return { ok: false, reason: 'bad-signature' };

      const admin = await options.adminByAddress(address);
      if (!admin) return { ok: false, reason: 'not-admin' };

      const consumed = await db
        .update(platformAdminChallenges)
        .set({ usedAt: sql`now()` })
        .where(
          and(
            eq(platformAdminChallenges.nonce, parsed.nonce),
            eq(platformAdminChallenges.address, address),
            eq(platformAdminChallenges.message, message),
            isNull(platformAdminChallenges.usedAt),
            gt(platformAdminChallenges.expiresAt, sql`now()`),
          ),
        )
        .returning({ nonce: platformAdminChallenges.nonce });
      if (consumed.length === 0) return { ok: false, reason: 'challenge-invalid' };

      return { ok: true, admin: { id: admin.id, address }, chainId: parsed.chainId };
    },

    /** A `gps_` bearer token, stored only as its sha256. Absolute lifetime, never renewed. */
    async createSession(args: { admin: PlatformAdminIdentity; chainId: number; ip?: string; userAgent?: string }): Promise<{ token: string; expiresAt: Date }> {
      const token = `gps_${randomBytes(32).toString('base64url')}`;
      const expiresAt = new Date(Date.now() + options.sessionTtlSeconds * 1000);
      await db.insert(platformAdminSessions).values({
        tokenHash: sha256hex(token),
        adminId: args.admin.id,
        address: args.admin.address,
        chainId: args.chainId,
        expiresAt,
        ip: args.ip ?? null,
        userAgent: args.userAgent ?? null,
      });
      return { token, expiresAt };
    },

    /**
     * An unrevoked, unexpired session whose address is still a platform admin — so removing an
     * platform admin ends their sessions at once. The id comes from the current platform admin, not the row.
     */
    async resolve(token: string): Promise<PlatformAdminContext | null> {
      const [row] = await db
        .select({ id: platformAdminSessions.id, address: platformAdminSessions.address })
        .from(platformAdminSessions)
        .where(and(eq(platformAdminSessions.tokenHash, sha256hex(token)), isNull(platformAdminSessions.revokedAt), gt(platformAdminSessions.expiresAt, sql`now()`)))
        .limit(1);
      if (!row) return null;
      const admin = await options.adminByAddress(row.address);
      if (!admin) return null;
      return { id: admin.id, address: admin.address, sessionId: row.id };
    },

    async revoke(sessionId: string): Promise<void> {
      await db.update(platformAdminSessions).set({ revokedAt: sql`now()` }).where(eq(platformAdminSessions.id, sessionId));
    },
  };
}

export type PlatformSessionService = ReturnType<typeof createPlatformSessionService>;
