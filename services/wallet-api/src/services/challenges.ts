import { randomBytes } from "node:crypto";
import { and, eq, gt, isNull, lt, sql } from "drizzle-orm";
import type { Db } from "../db/index.js";
import { challenges } from "../db/schema.js";

/**
 * What a challenge may be redeemed for. `pending-addition` is issued only by the claim step of a
 * cross-device owner addition and consumed only by its fill step, so a claim code can never yield
 * a challenge that full registration (which grants a session) accepts.
 */
export type ChallengeKind =
	| "registration"
	| "authentication"
	| "pending-addition";

const base64url = (buf: Buffer) => buf.toString("base64url");

export function createChallengeService(db: Db, ttlSeconds: number) {
	return {
		/**
		 * Issues a new one-time challenge (base64url of 32 random bytes), bound to a tenant.
		 * `externalId` records the external user id the challenge was requested for. It is set
		 * even when that user does not exist yet (userId null), so registration can bind to it.
		 */
		async issue(
			kind: ChallengeKind,
			userId: string | null,
			tenantId: string,
			externalId: string | null = null,
		): Promise<string> {
			const challenge = base64url(randomBytes(32));
			await db.insert(challenges).values({
				challenge,
				kind,
				tenantId,
				userId,
				externalId,
				expiresAt: new Date(Date.now() + ttlSeconds * 1000),
			});
			return challenge;
		},

		/**
		 * Atomically consumes a challenge: only succeeds if it exists, is of the right
		 * kind, has not been consumed, and has not expired. Single UPDATE … RETURNING
		 * makes replay a guaranteed failure even under concurrency. The returned tenant
		 * and user bindings (userId and externalId) MUST be enforced by the caller (C3).
		 */
		async consume(
			challenge: string,
			kind: ChallengeKind,
		): Promise<{
			userId: string | null;
			tenantId: string;
			externalId: string | null;
		} | null> {
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
				.returning({
					userId: challenges.userId,
					tenantId: challenges.tenantId,
					externalId: challenges.externalId,
				});
			return rows[0] ?? null;
		},

		/** Housekeeping: drop long-expired rows. */
		async prune(): Promise<void> {
			await db
				.delete(challenges)
				.where(lt(challenges.expiresAt, sql`now() - interval '1 day'`));
		},
	};
}

export type ChallengeService = ReturnType<typeof createChallengeService>;
