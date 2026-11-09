import { createHash, randomBytes } from "node:crypto";
import { and, eq, gt, inArray, isNull, ne, type SQL, sql } from "drizzle-orm";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { credentials, sessions, users } from "../db/schema.js";
import { appendTenantHistory, type Tx } from "./tenants.js";

const sha256hex = (value: string) =>
	createHash("sha256").update(value).digest("hex");

/** How stale `last_used_at` may get before a request writes it again (design D1). */
const TOUCH_RESOLUTION_SECONDS = 60;

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

/**
 * A resolved session, and whether its last use is due to be written. The write is left to the
 * caller, after every check on the request has passed: a request wallet-api refuses must not keep
 * a session from going idle (design D1).
 */
export type ResolvedSession = SessionContext & { touchDue: boolean };

export type SessionServiceOptions = {
	/** Absolute lifetime: activity never extends it. */
	ttlSeconds: number;
	/** A session unused for this long stops resolving. */
	idleTimeoutSeconds: number;
	/** Live sessions one user may hold; issuing past it revokes the ones used longest ago. */
	maxPerUser: number;
};

/** Which sessions an admin revocation reaches, always within one tenant. */
export type SessionSelector =
	| { userId: string }
	| { externalUserId: string }
	| { walletAddress: string };

/**
 * The body of an admin revocation (G5 R3): exactly one of the user's id in the tenant, or a
 * wallet address, which reaches every session acting for that wallet whoever opened it.
 */
export const adminRevocationSchema = z
	.object({
		externalUserId: z.string().min(1).max(256).optional(),
		walletAddress: z
			.string()
			.regex(/^0x[0-9a-fA-F]{40}$/, "must be a 20-byte hex address")
			.optional(),
	})
	.refine(
		(body) =>
			(body.externalUserId === undefined) !==
			(body.walletAddress === undefined),
		"name exactly one of externalUserId or walletAddress",
	);

export type AdminRevocation = z.infer<typeof adminRevocationSchema>;

export function createSessionService(db: Db, options: SessionServiceOptions) {
	const { ttlSeconds, idleTimeoutSeconds, maxPerUser } = options;

	/**
	 * Live = neither revoked nor past its absolute or idle expiry. The one predicate behind
	 * resolve(), the cap and every revocation, so "live" never means two things.
	 */
	const live = () =>
		and(
			isNull(sessions.revokedAt),
			gt(sessions.expiresAt, sql`now()`),
			gt(
				sessions.lastUsedAt,
				sql`now() - make_interval(secs => ${idleTimeoutSeconds})`,
			),
		);

	/** The last use is over a minute old: one condition for deciding a write is due, and for making it. */
	const touchDue = () =>
		sql`${sessions.lastUsedAt} < now() - make_interval(secs => ${TOUCH_RESOLUTION_SECONDS})`;

	const usersOfTenant = (executor: Db | Tx, tenantId: string, extra?: SQL) =>
		executor
			.select({ id: users.id })
			.from(users)
			.where(and(eq(users.tenantId, tenantId), extra));

	/**
	 * Revokes the live sessions one selector reaches inside one tenant, and returns how many
	 * (design D4). A selector naming nothing in the tenant revokes nothing, so a tenant can
	 * never reach another tenant's sessions. A wallet is matched case-insensitively and
	 * reaches every session acting for it, whichever user and credential opened it. Pass a
	 * transaction to write an audit entry atomically with the revocation. A plain function, so
	 * it can be passed around without its object.
	 */
	const revokeLive = async (
		tenantId: string,
		selector: SessionSelector,
		executor: Db | Tx = db,
	): Promise<number> => {
		// Every branch narrows the tenant's users the same way, so the boundary has one shape.
		const scope =
			"walletAddress" in selector
				? and(
						sql`lower(${sessions.walletAddress}) = ${selector.walletAddress.toLowerCase()}`,
						inArray(sessions.userId, usersOfTenant(executor, tenantId)),
					)
				: inArray(
						sessions.userId,
						usersOfTenant(
							executor,
							tenantId,
							"userId" in selector
								? eq(users.id, selector.userId)
								: eq(users.externalId, selector.externalUserId),
						),
					);
		const revoked = await executor
			.update(sessions)
			.set({ revokedAt: sql`now()` })
			.where(and(scope, live()))
			.returning({ id: sessions.id });
		return revoked.length;
	};

	return {
		/**
		 * Creates a session scoped to the WALLET the credential belongs to (WM-33): the
		 * wallet address is captured onto the session row at issue time, so any credential
		 * that is an owner of a wallet opens a session that can act for that wallet — the
		 * relay's sender-binding rule needs no exception (WM-34). Refused for a credential
		 * whose owner key was removed on-chain (WM-31).
		 *
		 * Enforces the per-user cap in the same transaction (G5 R4, design D3): the user row is
		 * locked so two concurrent sign-ins cannot both see room under the cap, and the live
		 * sessions beyond it, the ones used longest ago, are revoked. The new session is never
		 * one of them, even if another request touched an older session after this one started.
		 */
		async create(
			userId: string,
			credentialId: string,
		): Promise<{ token: string; expiresAt: Date }> {
			const credential = await db.query.credentials.findFirst({
				where: eq(credentials.id, credentialId),
			});
			if (!credential)
				throw new Error(
					`session refused: credential ${credentialId} is not registered`,
				);
			if (credential.removedAt)
				throw new Error(
					"session refused: credential is no longer an owner of the wallet",
				);
			const token = randomBytes(32).toString("base64url");
			const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
			await db.transaction(async (tx) => {
				await tx
					.select({ id: users.id })
					.from(users)
					.where(eq(users.id, userId))
					.for("update");
				const [created] = await tx
					.insert(sessions)
					.values({
						userId,
						credentialId,
						walletAddress: credential.walletAddress,
						tokenHash: sha256hex(token),
						expiresAt,
					})
					.returning({ id: sessions.id });
				const overflow = tx
					.select({ id: sessions.id })
					.from(sessions)
					.where(
						and(
							eq(sessions.userId, userId),
							ne(sessions.id, created.id),
							live(),
						),
					)
					.orderBy(
						sql`${sessions.lastUsedAt} DESC`,
						sql`${sessions.createdAt} DESC`,
					)
					.offset(maxPerUser - 1);
				await tx
					.update(sessions)
					.set({ revokedAt: sql`now()` })
					.where(inArray(sessions.id, overflow));
			});
			return { token, expiresAt };
		},

		/**
		 * Resolves a bearer token to its session context; null if unknown, revoked, past its
		 * absolute expiry or idle for longer than the idle timeout. It writes nothing: whether the
		 * last use is due to be refreshed comes back as `touchDue`, and the caller calls `touch()`
		 * once the request has passed every check (a request refused for a foreign origin or a
		 * suspended tenant must not keep the session alive).
		 */
		async resolve(token: string): Promise<ResolvedSession | null> {
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
					touchDue: sql<boolean>`${touchDue()}`,
				})
				.from(sessions)
				.innerJoin(users, eq(users.id, sessions.userId))
				.where(and(eq(sessions.tokenHash, sha256hex(token)), live()))
				.limit(1);
			return rows[0] ?? null;
		},

		/**
		 * Records a use of the session, but writes only when the stored value is over a minute old
		 * (design D1): a busy session costs one write a minute, and the guard makes a concurrent
		 * second write a no-op.
		 */
		async touch(sessionId: string): Promise<void> {
			await db
				.update(sessions)
				.set({ lastUsedAt: sql`now()` })
				.where(and(eq(sessions.id, sessionId), touchDue()));
		},

		async revoke(sessionId: string): Promise<void> {
			await db
				.update(sessions)
				.set({ revokedAt: sql`now()` })
				.where(eq(sessions.id, sessionId));
		},

		revokeLive,

		/**
		 * An admin revocation (G5 R3): revokes the live sessions the body selects inside the tenant
		 * and appends a `user-sessions-revoke` tenant history entry in the same transaction, even
		 * when nothing was revoked. The tenant does not change, so before and after stay empty.
		 *
		 * `tenant` is the tenant's id, or a step that locks the tenant inside this transaction and
		 * returns its id, refusing a state that does not allow the revocation: the platform route's
		 * check then holds until the entry is written, so a tenant deleted meanwhile records nothing.
		 */
		async revokeAndRecord(
			tenant: string | ((tx: Tx) => Promise<string>),
			body: AdminRevocation,
			by: { actor: string; platformAdminSessionId?: string },
		): Promise<number> {
			// A wallet is matched ignoring case, so it is recorded in one case too: 0xABC… and 0xabc…
			// are the same revocation in the history.
			const selector: SessionSelector =
				body.externalUserId !== undefined
					? { externalUserId: body.externalUserId }
					: { walletAddress: String(body.walletAddress).toLowerCase() };
			const [kind, value] = Object.entries(selector)[0];
			return db.transaction(async (tx) => {
				const tenantId = typeof tenant === "string" ? tenant : await tenant(tx);
				const revoked = await revokeLive(tenantId, selector, tx);
				await appendTenantHistory(tx, {
					tenantId,
					action: "user-sessions-revoke",
					actor: by.actor,
					platformAdminSessionId: by.platformAdminSessionId,
					before: null,
					after: null,
					detail: { selector: kind, value, revoked },
				});
				return revoked;
			});
		},

		/** Sign out everywhere (G5 R2): every live session of the user, across credentials and wallets. */
		async revokeAllForUser(tenantId: string, userId: string): Promise<number> {
			return revokeLive(tenantId, { userId });
		},

		/**
		 * Revokes every live session held by one credential — what makes a removed owner's
		 * sessions stop working the moment the registry learns of the removal (WM-30, WM-31).
		 */
		async revokeAllForCredential(credentialDbId: string): Promise<void> {
			await db
				.update(sessions)
				.set({ revokedAt: sql`now()` })
				.where(and(eq(sessions.credentialId, credentialDbId), live()));
		},
	};
}

export type SessionService = ReturnType<typeof createSessionService>;
