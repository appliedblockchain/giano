import { count, desc, eq, sql } from "drizzle-orm";
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
	return {
		async list(): Promise<PlatformAdmin[]> {
			return db
				.select()
				.from(platformAdmins)
				.orderBy(platformAdmins.createdAt, platformAdmins.id);
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
