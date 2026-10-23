import { randomBytes } from 'node:crypto';
import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import { getAddress, recoverMessageAddress, type Hex } from 'viem';
import { createSiweMessage, generateSiweNonce, parseSiweMessage } from 'viem/siwe';
import type { OperatorEntry } from '../config.js';
import type { Db } from '../db/index.js';
import { operatorChallenges, operatorSessions } from '../db/schema.js';
import { sha256hex } from './tenants.js';

/**
 * Operator sign-in with an Ethereum wallet (EIP-4361; specs/OPERATOR-ADMIN-SPECS.md §4).
 *
 * The server writes every sign-in message and keeps its exact text on the challenge row, and
 * verify accepts only that text (H-l). One string comparison therefore checks domain, uri,
 * version, chainId, statement and the time window against values only the server chose —
 * `validateSiweMessage` is not used, because in viem 2.31.6 it skips issuedAt, uri, version and
 * chainId, and checks no time at all when expirationTime is absent.
 *
 * Who is an operator is the configured list, read on every resolve: a database write can create a
 * session row, but a session whose address the current configuration does not list is worthless.
 */

export type OperatorIdentity = { id: string; address: string };
export type OperatorContext = OperatorIdentity & { sessionId: string };

/** Why a sign-in or session failed: recorded in metrics and logs only, never told to the caller. */
export type OperatorAuthFailure = 'malformed-message' | 'bad-signature' | 'not-operator' | 'challenge-invalid';

export type OperatorSessionOptions = {
  operators: OperatorEntry[];
  domain: string;
  uri: string;
  challengeTtlSeconds: number;
  sessionTtlSeconds: number;
};

export function createOperatorSessionService(db: Db, options: OperatorSessionOptions) {
  const byAddress = new Map(options.operators.map((operator) => [operator.address, operator]));
  const minutes = Math.round(options.sessionTtlSeconds / 60);

  return {
    /**
     * A sign-in message for `address`. An address that is not an operator gets a message of the
     * same shape and nothing is stored, so the endpoint does not reveal who the operators are.
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
        statement: `Sign in to the Giano operator console. This grants access to tenant administration for ${minutes} minutes.`,
        issuedAt,
        expirationTime,
      });
      const lower = address.toLowerCase();
      if (byAddress.has(lower)) {
        await db.insert(operatorChallenges).values({ nonce, address: lower, message, expiresAt: expirationTime });
      }
      return { message };
    },

    /**
     * Checks, in order: the message parses; the signature recovers (ECDSA only, so no RPC — sign-in
     * works when every chain is down) to the message's address; that address is an operator; and
     * the challenge is consumed atomically, which only succeeds for the exact issued text, unused
     * and unexpired. The consume is the only write.
     */
    async verify({ message, signature }: { message: string; signature: Hex }): Promise<
      { ok: true; operator: OperatorIdentity; chainId: number } | { ok: false; reason: OperatorAuthFailure }
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

      const operator = byAddress.get(address);
      if (!operator) return { ok: false, reason: 'not-operator' };

      const consumed = await db
        .update(operatorChallenges)
        .set({ usedAt: sql`now()` })
        .where(
          and(
            eq(operatorChallenges.nonce, parsed.nonce),
            eq(operatorChallenges.address, address),
            eq(operatorChallenges.message, message),
            isNull(operatorChallenges.usedAt),
            gt(operatorChallenges.expiresAt, sql`now()`),
          ),
        )
        .returning({ nonce: operatorChallenges.nonce });
      if (consumed.length === 0) return { ok: false, reason: 'challenge-invalid' };

      return { ok: true, operator: { id: operator.id, address }, chainId: parsed.chainId };
    },

    /** A `gos_` bearer token, stored only as its sha256. Absolute lifetime, never renewed. */
    async createSession(args: { operator: OperatorIdentity; chainId: number; ip?: string; userAgent?: string }): Promise<{ token: string; expiresAt: Date }> {
      const token = `gos_${randomBytes(32).toString('base64url')}`;
      const expiresAt = new Date(Date.now() + options.sessionTtlSeconds * 1000);
      await db.insert(operatorSessions).values({
        tokenHash: sha256hex(token),
        operatorId: args.operator.id,
        address: args.operator.address,
        chainId: args.chainId,
        expiresAt,
        ip: args.ip ?? null,
        userAgent: args.userAgent ?? null,
      });
      return { token, expiresAt };
    },

    /**
     * An unrevoked, unexpired session whose address the CURRENT configuration still lists — so
     * removing an operator from the list ends their sessions at the next restart. The id comes
     * from the current entry, not from the row.
     */
    async resolve(token: string): Promise<OperatorContext | null> {
      const [row] = await db
        .select({ id: operatorSessions.id, address: operatorSessions.address })
        .from(operatorSessions)
        .where(and(eq(operatorSessions.tokenHash, sha256hex(token)), isNull(operatorSessions.revokedAt), gt(operatorSessions.expiresAt, sql`now()`)))
        .limit(1);
      if (!row) return null;
      const operator = byAddress.get(row.address);
      if (!operator) return null;
      return { id: operator.id, address: operator.address, sessionId: row.id };
    },

    async revoke(sessionId: string): Promise<void> {
      await db.update(operatorSessions).set({ revokedAt: sql`now()` }).where(eq(operatorSessions.id, sessionId));
    },
  };
}

export type OperatorSessionService = ReturnType<typeof createOperatorSessionService>;
