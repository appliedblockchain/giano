import { and, count, desc, eq, gt, isNull, sql } from "drizzle-orm";
import { z } from "zod";
import type { Db } from "../db/index.js";
import {
	platformAdminHistory,
	platformAdminSessions,
	platformAdmins,
} from "../db/schema.js";
import type { PlatformAdminSeed } from "../environments.js";
import type { PlatformAdminContext } from "./platform-sessions.js";
import { TenantWriteError, type Tx } from "./tenants.js";

/**
 * The platform admins (specs/PLATFORM-ADMIN-SPECS.md §4.1). A row, not configuration: the init step seeds
 * an environment's bootstrap platform admins into an empty table, and from then on only a signed-in
 * platform admin changes it. Two guards keep a deployment administrable — nobody removes the last
 * platform admin, and nobody removes themselves — and every change is recorded in platform_admin_history.
 */

export type PlatformAdmin = typeof platformAdmins.$inferSelect;

/** A platform admin with when they last signed in and how many of their sessions are open (D15). */
export type PlatformAdminWithSessions = PlatformAdmin & {
	lastSignInAt: Date | null;
	activeSessions: number;
};

/** How far back an admin's sessions are listed. */
export const SESSION_HISTORY_DAYS = 30;

/** A session as an admin sees it: never its token, nor the token's hash. */
export type PlatformAdminSessionView = {
	id: string;
	createdAt: Date;
	expiresAt: Date;
	revokedAt: Date | null;
	chainId: number;
	userAgent: string | null;
};

export const platformAdminInputSchema = z
	.object({
		id: z
			.string()
			.regex(/^[a-z0-9-]{1,64}$/, "lowercase id, e.g. admin-oncall"),
		address: z
			.string()
			.regex(/^0x[0-9a-fA-F]{40}$/, "expected a 0x address")
			.transform((address) => address.toLowerCase()),
	})
	.strict();

export type PlatformAdminInput = z.infer<typeof platformAdminInputSchema>;

const actorOf = (admin: PlatformAdminContext) =>
	`platform-admin:${admin.id}:${admin.address}`;

/** Serialises every write to the platform admins, so the last-platform admin check cannot race. */
async function lockAdminWrites(tx: Tx): Promise<void> {
	await tx.execute(
		sql`SELECT pg_advisory_xact_lock(hashtext('giano:platform-admins'))`,
	);
}

/**
 * Writes `seeds` only when no platform admin exists, recording each as `bootstrap` by
 * `bootstrap:<environment>`. Returns the ids written — empty when the table already had an
 * platform admin. Safe to run on every task start and from concurrent replicas.
 */
export async function bootstrapAdmins(
	db: Db,
	environment: string,
	seeds: readonly PlatformAdminSeed[],
): Promise<string[]> {
	return db.transaction(async (tx) => {
		await lockAdminWrites(tx);
		const [{ n }] = await tx.select({ n: count() }).from(platformAdmins);
		if (Number(n) > 0 || seeds.length === 0) return [];
		const actor = `bootstrap:${environment}`;
		const rows = seeds.map((seed) => platformAdminInputSchema.parse(seed));
		await tx
			.insert(platformAdmins)
			.values(rows.map((row) => ({ ...row, addedBy: actor })));
		await tx.insert(platformAdminHistory).values(
			rows.map((row) => ({
				adminId: row.id,
				address: row.address,
				action: "bootstrap" as const,
				actor,
			})),
		);
		return rows.map((row) => row.id);
	});
}

export function createPlatformAdminService(db: Db) {
	async function adminById(id: string): Promise<PlatformAdmin> {
		const [row] = await db
			.select()
			.from(platformAdmins)
			.where(eq(platformAdmins.id, id));
		if (!row)
			throw new TenantWriteError(
				404,
				"not-found",
				`platform admin "${id}" not found`,
			);
		return row;
	}

	return {
		/**
		 * Oldest first, each with their last sign-in and open sessions. Sessions are matched by address,
		 * as a session is resolved (an admin's id can be reused after removal; an address is who signed).
		 */
		async list(): Promise<PlatformAdminWithSessions[]> {
			const [admins, sessions] = await Promise.all([
				db
					.select()
					.from(platformAdmins)
					.orderBy(platformAdmins.createdAt, platformAdmins.id),
				db
					.select({
						address: platformAdminSessions.address,
						// node-postgres returns an aggregate timestamptz as a string, not a Date.
						lastSignInAt: sql<string>`max(${platformAdminSessions.createdAt})`,
						activeSessions: sql<number>`count(*) filter (where ${platformAdminSessions.revokedAt} is null and ${platformAdminSessions.expiresAt} > now())`,
					})
					.from(platformAdminSessions)
					.groupBy(platformAdminSessions.address),
			]);
			const byAddress = new Map(sessions.map((row) => [row.address, row]));
			return admins.map((admin) => {
				const found = byAddress.get(admin.address);
				return {
					...admin,
					lastSignInAt: found ? new Date(found.lastSignInAt) : null,
					activeSessions: Number(found?.activeSessions ?? 0),
				};
			});
		},

		/**
		 * The admin's sessions from the last {@link SESSION_HISTORY_DAYS} days, newest first. The browser
		 * each was signed from only for the caller's own: another admin sees when, not where. Not the IP:
		 * sign-in records `request.ip`, which behind the console's proxy is the proxy's address.
		 */
		async sessions(
			id: string,
			by: PlatformAdminContext,
		): Promise<PlatformAdminSessionView[]> {
			const admin = await adminById(id);
			const rows = await db
				.select({
					id: platformAdminSessions.id,
					createdAt: platformAdminSessions.createdAt,
					expiresAt: platformAdminSessions.expiresAt,
					revokedAt: platformAdminSessions.revokedAt,
					chainId: platformAdminSessions.chainId,
					userAgent: platformAdminSessions.userAgent,
				})
				.from(platformAdminSessions)
				.where(
					and(
						eq(platformAdminSessions.address, admin.address),
						gt(
							platformAdminSessions.createdAt,
							sql`now() - make_interval(days => ${SESSION_HISTORY_DAYS})`,
						),
					),
				)
				.orderBy(
					desc(platformAdminSessions.createdAt),
					desc(platformAdminSessions.id),
				);
			return admin.address === by.address
				? rows
				: rows.map((row) => ({ ...row, userAgent: null }));
		},

		/**
		 * Ends one of the caller's own sessions (D15). Another admin's is refused: removing them is the
		 * recorded way to end all of theirs. Ending one already ended or expired is a no-op: an
		 * expired session stays "expired", not "ended".
		 */
		async endSession(
			id: string,
			sessionId: string,
			by: PlatformAdminContext,
		): Promise<void> {
			const admin = await adminById(id);
			if (admin.address !== by.address)
				throw new TenantWriteError(
					403,
					"not-your-session",
					"you can end only your own sessions; removing an admin ends all of theirs",
				);
			const [session] = await db
				.select({ id: platformAdminSessions.id })
				.from(platformAdminSessions)
				.where(
					and(
						eq(platformAdminSessions.id, sessionId),
						eq(platformAdminSessions.address, admin.address),
					),
				);
			if (!session)
				throw new TenantWriteError(
					404,
					"not-found",
					`session "${sessionId}" not found`,
				);
			await db
				.update(platformAdminSessions)
				.set({ revokedAt: sql`now()` })
				.where(
					and(
						eq(platformAdminSessions.id, sessionId),
						isNull(platformAdminSessions.revokedAt),
						gt(platformAdminSessions.expiresAt, sql`now()`),
					),
				);
		},

		async byAddress(address: string): Promise<PlatformAdmin | undefined> {
			const [row] = await db
				.select()
				.from(platformAdmins)
				.where(eq(platformAdmins.address, address.toLowerCase()));
			return row;
		},

		async add(
			input: PlatformAdminInput,
			by: PlatformAdminContext,
		): Promise<PlatformAdmin> {
			return db.transaction(async (tx) => {
				await lockAdminWrites(tx);
				const [taken] = await tx
					.select()
					.from(platformAdmins)
					.where(
						sql`${platformAdmins.id} = ${input.id} OR ${platformAdmins.address} = ${input.address}`,
					);
				if (taken) {
					const field = taken.id === input.id ? "id" : "address";
					throw new TenantWriteError(
						409,
						"conflict",
						`a platform admin with that ${field} already exists`,
						{ field },
					);
				}
				const [row] = await tx
					.insert(platformAdmins)
					.values({ ...input, addedBy: actorOf(by) })
					.returning();
				await tx.insert(platformAdminHistory).values({
					adminId: row.id,
					address: row.address,
					action: "add",
					actor: actorOf(by),
					platformAdminSessionId: by.sessionId,
				});
				return row;
			});
		},

		/** Refuses the last platform admin and yourself; revokes the removed platform admin's open sessions. */
		async remove(id: string, by: PlatformAdminContext): Promise<void> {
			await db.transaction(async (tx) => {
				await lockAdminWrites(tx);
				const [row] = await tx
					.select()
					.from(platformAdmins)
					.where(eq(platformAdmins.id, id));
				if (!row)
					throw new TenantWriteError(
						404,
						"not-found",
						`platform admin "${id}" not found`,
					);
				if (row.address === by.address)
					throw new TenantWriteError(
						409,
						"self-removal",
						"you cannot remove yourself; ask another platform admin",
					);
				const [{ n }] = await tx.select({ n: count() }).from(platformAdmins);
				if (Number(n) <= 1)
					throw new TenantWriteError(
						409,
						"last-admin",
						"the last platform admin cannot be removed",
					);
				await tx.delete(platformAdmins).where(eq(platformAdmins.id, id));
				await tx
					.update(platformAdminSessions)
					.set({ revokedAt: sql`now()` })
					.where(
						sql`${platformAdminSessions.address} = ${row.address} AND ${platformAdminSessions.revokedAt} IS NULL`,
					);
				await tx.insert(platformAdminHistory).values({
					adminId: row.id,
					address: row.address,
					action: "remove",
					actor: actorOf(by),
					platformAdminSessionId: by.sessionId,
				});
			});
		},

		/** Newest first. */
		async history(limit: number) {
			return db
				.select()
				.from(platformAdminHistory)
				.orderBy(
					desc(platformAdminHistory.createdAt),
					desc(platformAdminHistory.id),
				)
				.limit(limit);
		},
	};
}

export type PlatformAdminService = ReturnType<
	typeof createPlatformAdminService
>;
