import { and, asc, eq, gt, inArray, isNull, lte, or, sql } from "drizzle-orm";
import type { Address, Hex } from "viem";
import type { Db } from "../db/index.js";
import {
	tenantSponsorship,
	tenantSponsorshipRuleEvents,
	tenantSponsorshipRules,
} from "../db/schema.js";
import type { SponsorshipRule } from "./sponsorship-config.js";

/**
 * Reads and writes a tenant's sponsorship rules (openspec sponsorship-rules-api).
 *
 * A rule is active when it has no expiry, or its expiry is later than `now`. An expired rule is
 * treated as absent everywhere: evaluation, the cap and the default listing.
 */

type Executor = Pick<Db, "select">;
/** A transaction: every rule write runs in one, under the tenant's rule lock. */
export type Tx = Parameters<Parameters<Db["transaction"]>[0]>[0];

export type RuleRow = typeof tenantSponsorshipRules.$inferSelect;
type RuleAction = (typeof tenantSponsorshipRuleEvents.$inferInsert)["action"];

/** An allowlist entry as the deprecated settings field holds it. */
export type AllowlistEntry = { contract: Address; functions: "all" | Hex[] };

/** Why a rule write was refused. The route maps each code to its status. */
export type RuleWriteErrorCode =
	| "duplicate-contract"
	| "client-reference-conflict"
	| "rule-limit-reached"
	| "allowlist-conflict";

export class RuleWriteError extends Error {
	constructor(
		readonly code: RuleWriteErrorCode,
		message: string,
		readonly rule?: RuleRow,
	) {
		super(message);
	}
}

/** The condition "active at `now`" on a rules query. */
export function activeAt(now: Date) {
	return or(
		isNull(tenantSponsorshipRules.expiresAt),
		gt(tenantSponsorshipRules.expiresAt, now),
	);
}

/**
 * What evaluation needs: the tenant's active rules for the given contracts, and whether it has any
 * active rule at all. Reading only the operation's targets keeps evaluation independent of how
 * many rules a tenant has.
 */
export async function readActiveRules(
	db: Executor,
	args: {
		tenantId: string;
		chainId: number;
		contracts: readonly string[];
		now: Date;
	},
): Promise<{ rules: SponsorshipRule[]; hasActiveRules: boolean }> {
	const scope = and(
		eq(tenantSponsorshipRules.tenantId, args.tenantId),
		eq(tenantSponsorshipRules.chainId, args.chainId),
		activeAt(args.now),
	);
	const contracts = [...new Set(args.contracts.map((c) => c.toLowerCase()))];
	const [rows, [any]] = await Promise.all([
		contracts.length === 0
			? Promise.resolve([])
			: db
					.select({
						id: tenantSponsorshipRules.id,
						contract: tenantSponsorshipRules.contract,
						functions: tenantSponsorshipRules.functions,
					})
					.from(tenantSponsorshipRules)
					.where(
						and(scope, inArray(tenantSponsorshipRules.contract, contracts)),
					),
		db
			.select({ id: tenantSponsorshipRules.id })
			.from(tenantSponsorshipRules)
			.where(scope)
			.limit(1),
	]);
	return {
		rules: rows.map((row) => ({
			id: row.id,
			contract: row.contract as Address,
			functions: row.functions === "all" ? "all" : (row.functions as Hex[]),
		})),
		hasActiveRules: any !== undefined,
	};
}

/**
 * Serialises rule writes of one tenant on one chain, until the transaction ends. Writes of other
 * tenants do not wait. This is what makes the cap and the client-reference lookup hold under
 * concurrent requests (design D4).
 */
export async function lockTenantRules(
	tx: Tx,
	tenantId: string,
	chainId: number,
): Promise<void> {
	await tx.execute(
		sql`SELECT pg_advisory_xact_lock(hashtextextended(${`sponsorship-rules:${tenantId}:${chainId}`}, 0))`,
	);
}

/** The rule as an API response and an event record show it. */
export function ruleView(row: RuleRow) {
	return {
		id: row.id,
		contract: row.contract as Address,
		functions: row.functions,
		clientReference: row.clientReference,
		expiresAt: row.expiresAt?.toISOString() ?? null,
		createdAt: row.createdAt.toISOString(),
		updatedAt: row.updatedAt.toISOString(),
	};
}

export async function recordRuleEvent(
	tx: Tx,
	row: RuleRow,
	action: RuleAction,
	keyHash: string | null,
): Promise<void> {
	await tx.insert(tenantSponsorshipRuleEvents).values({
		tenantId: row.tenantId,
		chainId: row.chainId,
		ruleId: row.id,
		action,
		rule: ruleView(row),
		createdByKeyHash: keyHash,
	});
}

/** The number of active rules a tenant has on a chain. */
export async function countActiveRules(
	tx: Tx,
	tenantId: string,
	chainId: number,
	now: Date,
): Promise<number> {
	const [row] = await tx
		.select({ count: sql<number>`count(*)::int` })
		.from(tenantSponsorshipRules)
		.where(
			and(
				eq(tenantSponsorshipRules.tenantId, tenantId),
				eq(tenantSponsorshipRules.chainId, chainId),
				activeAt(now),
			),
		);
	return row?.count ?? 0;
}

/**
 * A legacy rule is one the deprecated `allowlist` field manages: no client reference and no expiry.
 * The field could not express either, so a rule with one belongs to the rules API alone.
 */
function isLegacy(row: Pick<RuleRow, "clientReference" | "expiresAt">) {
	return row.clientReference === null && row.expiresAt === null;
}

function sameFunctions(a: "all" | string[], b: "all" | string[]): boolean {
	if (a === "all" || b === "all") return a === b;
	const left = new Set(a.map((x) => x.toLowerCase()));
	const right = new Set(b.map((x) => x.toLowerCase()));
	return left.size === right.size && [...left].every((x) => right.has(x));
}

/** The legacy rules, oldest first, as the deprecated `allowlist` field shows them. */
export async function legacyAllowlist(
	tx: Tx,
	tenantId: string,
	chainId: number,
): Promise<AllowlistEntry[]> {
	const rows = await tx
		.select()
		.from(tenantSponsorshipRules)
		.where(
			and(
				eq(tenantSponsorshipRules.tenantId, tenantId),
				eq(tenantSponsorshipRules.chainId, chainId),
				isNull(tenantSponsorshipRules.clientReference),
				isNull(tenantSponsorshipRules.expiresAt),
			),
		)
		.orderBy(
			asc(tenantSponsorshipRules.createdAt),
			asc(tenantSponsorshipRules.id),
		);
	return rows.map((row) => ({
		contract: row.contract as Address,
		functions: row.functions === "all" ? "all" : (row.functions as Hex[]),
	}));
}

/**
 * Rewrites the `allowlist` mirror in the stored settings from the legacy rules (design D8). A tenant
 * with no settings row has nothing to mirror into: it sponsors nothing, before or after a rollback.
 */
export async function rewriteAllowlistMirror(
	tx: Tx,
	tenantId: string,
	chainId: number,
): Promise<void> {
	const allowlist = await legacyAllowlist(tx, tenantId, chainId);
	await tx
		.update(tenantSponsorship)
		.set({
			config: sql`jsonb_set(${tenantSponsorship.config}, '{allowlist}', ${JSON.stringify(allowlist)}::jsonb)`,
		})
		.where(
			and(
				eq(tenantSponsorship.tenantId, tenantId),
				eq(tenantSponsorship.chainId, chainId),
			),
		);
}

/**
 * Removes expired rules of a tenant on a chain, at most `limit` of them, recording each removal
 * (design D3). Returns the contracts it freed.
 */
export async function removeExpiredRules(
	tx: Tx,
	args: { tenantId: string; chainId: number; now: Date; limit: number },
): Promise<void> {
	const expired = await tx
		.select({ id: tenantSponsorshipRules.id })
		.from(tenantSponsorshipRules)
		.where(
			and(
				eq(tenantSponsorshipRules.tenantId, args.tenantId),
				eq(tenantSponsorshipRules.chainId, args.chainId),
				lte(tenantSponsorshipRules.expiresAt, args.now),
			),
		)
		.limit(args.limit);
	if (expired.length === 0) return;
	const removed = await tx
		.delete(tenantSponsorshipRules)
		.where(
			inArray(
				tenantSponsorshipRules.id,
				expired.map((row) => row.id),
			),
		)
		.returning();
	for (const row of removed)
		await recordRuleEvent(tx, row, "expired-removed", null);
}

/**
 * The deprecated `allowlist` write: makes the legacy rules equal to `allowlist`, leaving every other
 * rule alone. Call it inside the settings transaction, so the settings and the rules change
 * together. Refuses a contract that already has a non-legacy rule, and a result over the cap.
 */
export async function replaceLegacyRules(
	tx: Tx,
	args: {
		tenantId: string;
		chainId: number;
		allowlist: AllowlistEntry[];
		keyHash: string | null;
		now: Date;
		maxRules: number;
	},
): Promise<void> {
	const { tenantId, chainId, keyHash, now } = args;
	await lockTenantRules(tx, tenantId, chainId);
	await removeExpiredRules(tx, { tenantId, chainId, now, limit: 500 });

	const existing = await tx
		.select()
		.from(tenantSponsorshipRules)
		.where(
			and(
				eq(tenantSponsorshipRules.tenantId, tenantId),
				eq(tenantSponsorshipRules.chainId, chainId),
			),
		);
	const byContract = new Map(existing.map((row) => [row.contract, row]));
	const wanted = new Map(
		args.allowlist.map((entry) => [entry.contract.toLowerCase(), entry]),
	);

	for (const [contract] of wanted) {
		const row = byContract.get(contract);
		if (row && !isLegacy(row))
			throw new RuleWriteError(
				"allowlist-conflict",
				`${contract} already has a rule with a client reference or an expiry (${row.id}); change it through /v1/admin/sponsorship/rules`,
				row,
			);
	}

	const others = existing.filter(
		(row) => !isLegacy(row) && (row.expiresAt === null || row.expiresAt > now),
	).length;
	if (others + wanted.size > args.maxRules)
		throw new RuleWriteError(
			"rule-limit-reached",
			`the allowlist would make ${others + wanted.size} active rules, over the limit of ${args.maxRules}`,
		);

	for (const row of existing) {
		if (!isLegacy(row) || wanted.has(row.contract)) continue;
		await tx
			.delete(tenantSponsorshipRules)
			.where(eq(tenantSponsorshipRules.id, row.id));
		await recordRuleEvent(tx, row, "deleted", keyHash);
	}

	for (const [contract, entry] of wanted) {
		const row = byContract.get(contract);
		if (!row) {
			const [created] = await tx
				.insert(tenantSponsorshipRules)
				.values({
					tenantId,
					chainId,
					contract,
					functions: entry.functions,
					createdByKeyHash: keyHash,
					updatedByKeyHash: keyHash,
				})
				.returning();
			await recordRuleEvent(tx, created, "created", keyHash);
		} else if (!sameFunctions(row.functions, entry.functions)) {
			const [updated] = await tx
				.update(tenantSponsorshipRules)
				.set({
					functions: entry.functions,
					updatedAt: now,
					updatedByKeyHash: keyHash,
				})
				.where(eq(tenantSponsorshipRules.id, row.id))
				.returning();
			await recordRuleEvent(tx, updated, "updated", keyHash);
		}
	}
}
