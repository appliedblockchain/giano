import {
	and,
	asc,
	desc,
	eq,
	gt,
	inArray,
	isNull,
	lt,
	lte,
	or,
	sql,
} from "drizzle-orm";
import type { Address, Hex } from "viem";
import type { Db } from "../db/index.js";
import {
	tenantSponsorship,
	tenantSponsorshipRuleEvents,
	tenantSponsorshipRules,
} from "../db/schema.js";
import type {
	RuleCreate,
	RulePatch,
	SponsorshipRule,
} from "./sponsorship-config.js";

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

// ── the rules API ─────────────────────────────────────────────────────────────

/** How many expired rules one write removes, besides an expired rule for its own contract. */
const EXPIRED_REMOVAL_BATCH = 500;

type Scope = { tenantId: string; chainId: number };

function inScope({ tenantId, chainId }: Scope) {
	return and(
		eq(tenantSponsorshipRules.tenantId, tenantId),
		eq(tenantSponsorshipRules.chainId, chainId),
	);
}

function isActive(row: Pick<RuleRow, "expiresAt">, now: Date): boolean {
	return row.expiresAt === null || row.expiresAt > now;
}

/** True when a create repeats the rule it would have made: same contract, functions and expiry. */
function sameRule(row: RuleRow, input: RuleCreate): boolean {
	return (
		row.contract === input.contract.toLowerCase() &&
		sameFunctions(row.functions, input.functions) &&
		(row.expiresAt?.getTime() ?? null) === (input.expiresAt?.getTime() ?? null)
	);
}

/**
 * Creates one rule (design D2 to D5). A create that repeats a client reference returns the rule
 * that reference already names instead of adding one, when it describes the same rule.
 */
export async function createRule(
	db: Db,
	args: Scope & {
		input: RuleCreate;
		keyHash: string | null;
		now: Date;
		maxRules: number;
	},
): Promise<{ created: boolean; rule: RuleRow }> {
	const { tenantId, chainId, input, keyHash, now } = args;
	const contract = input.contract.toLowerCase();
	return db.transaction(async (tx) => {
		await lockTenantRules(tx, tenantId, chainId);

		if (input.clientReference !== undefined) {
			const [named] = await tx
				.select()
				.from(tenantSponsorshipRules)
				.where(
					and(
						inScope(args),
						eq(tenantSponsorshipRules.clientReference, input.clientReference),
					),
				);
			if (named) {
				if (sameRule(named, input)) return { created: false, rule: named };
				throw new RuleWriteError(
					"client-reference-conflict",
					`the client reference ${input.clientReference} already names a different rule (${named.id})`,
					named,
				);
			}
		}

		// An expired rule for this contract must not block the new one, whatever the batch size.
		const [sameContract] = await tx
			.select()
			.from(tenantSponsorshipRules)
			.where(and(inScope(args), eq(tenantSponsorshipRules.contract, contract)));
		if (sameContract && isActive(sameContract, now))
			throw new RuleWriteError(
				"duplicate-contract",
				`${contract} already has an active rule (${sameContract.id}); change that rule instead`,
				sameContract,
			);
		if (sameContract) {
			await tx
				.delete(tenantSponsorshipRules)
				.where(eq(tenantSponsorshipRules.id, sameContract.id));
			await recordRuleEvent(tx, sameContract, "expired-removed", null);
		}
		await removeExpiredRules(tx, {
			tenantId,
			chainId,
			now,
			limit: EXPIRED_REMOVAL_BATCH,
		});

		if ((await countActiveRules(tx, tenantId, chainId, now)) >= args.maxRules)
			throw new RuleWriteError(
				"rule-limit-reached",
				`this tenant already has ${args.maxRules} active rules on this chain, the limit; remove or expire some first`,
			);

		const [rule] = await tx
			.insert(tenantSponsorshipRules)
			.values({
				tenantId,
				chainId,
				contract,
				functions: input.functions,
				clientReference: input.clientReference ?? null,
				expiresAt: input.expiresAt ?? null,
				createdByKeyHash: keyHash,
				updatedByKeyHash: keyHash,
			})
			.returning();
		await recordRuleEvent(tx, rule, "created", keyHash);
		if (isLegacy(rule)) await rewriteAllowlistMirror(tx, tenantId, chainId);
		return { created: true, rule };
	});
}

/** A page cursor: the position of the last rule or event a page returned. */
function encodeCursor(row: { createdAt: Date; id: string }): string {
	return Buffer.from(`${row.createdAt.toISOString()}|${row.id}`).toString(
		"base64url",
	);
}

function decodeCursor(cursor: string): { createdAt: Date; id: string } | null {
	const [at, id] = Buffer.from(cursor, "base64url").toString("utf8").split("|");
	const createdAt = new Date(at ?? "");
	if (!id || Number.isNaN(createdAt.getTime())) return null;
	return { createdAt, id };
}

export class BadCursorError extends Error {}

/** Lists rules newest first, a page at a time. Expired rules only with `includeExpired`. */
export async function listRules(
	db: Db,
	args: Scope & {
		now: Date;
		contract?: string;
		clientReference?: string;
		includeExpired: boolean;
		limit: number;
		cursor?: string;
	},
): Promise<{ rules: RuleRow[]; nextCursor: string | null }> {
	const conditions = [inScope(args)];
	if (!args.includeExpired) conditions.push(activeAt(args.now));
	if (args.contract)
		conditions.push(
			eq(tenantSponsorshipRules.contract, args.contract.toLowerCase()),
		);
	if (args.clientReference)
		conditions.push(
			eq(tenantSponsorshipRules.clientReference, args.clientReference),
		);
	if (args.cursor !== undefined) {
		const after = decodeCursor(args.cursor);
		if (!after) throw new BadCursorError("not a cursor this API returned");
		conditions.push(
			or(
				lt(tenantSponsorshipRules.createdAt, after.createdAt),
				and(
					eq(tenantSponsorshipRules.createdAt, after.createdAt),
					lt(tenantSponsorshipRules.id, after.id),
				),
			),
		);
	}
	const rows = await db
		.select()
		.from(tenantSponsorshipRules)
		.where(and(...conditions))
		.orderBy(
			desc(tenantSponsorshipRules.createdAt),
			desc(tenantSponsorshipRules.id),
		)
		.limit(args.limit + 1);
	const page = rows.slice(0, args.limit);
	return {
		rules: page,
		nextCursor:
			rows.length > args.limit ? encodeCursor(page[page.length - 1]) : null,
	};
}

export async function getRule(
	db: Db,
	args: Scope & { id: string },
): Promise<RuleRow | undefined> {
	const [row] = await db
		.select()
		.from(tenantSponsorshipRules)
		.where(and(inScope(args), eq(tenantSponsorshipRules.id, args.id)));
	return row;
}

/**
 * Changes a rule's functions or expiry. A patch that makes an expired rule active again counts
 * toward the cap. Returns undefined when the tenant has no such rule on this chain.
 */
export async function patchRule(
	db: Db,
	args: Scope & {
		id: string;
		patch: RulePatch;
		keyHash: string | null;
		now: Date;
		maxRules: number;
	},
): Promise<RuleRow | undefined> {
	const { tenantId, chainId, patch, keyHash, now } = args;
	return db.transaction(async (tx) => {
		await lockTenantRules(tx, tenantId, chainId);
		const [row] = await tx
			.select()
			.from(tenantSponsorshipRules)
			.where(and(inScope(args), eq(tenantSponsorshipRules.id, args.id)));
		if (!row) return undefined;

		const expiresAt =
			patch.expiresAt === undefined ? row.expiresAt : patch.expiresAt;
		if (
			!isActive(row, now) &&
			isActive({ expiresAt }, now) &&
			(await countActiveRules(tx, tenantId, chainId, now)) >= args.maxRules
		)
			throw new RuleWriteError(
				"rule-limit-reached",
				`this tenant already has ${args.maxRules} active rules on this chain, the limit`,
			);

		const [updated] = await tx
			.update(tenantSponsorshipRules)
			.set({
				functions: patch.functions ?? row.functions,
				expiresAt,
				updatedAt: now,
				updatedByKeyHash: keyHash,
			})
			.where(eq(tenantSponsorshipRules.id, row.id))
			.returning();
		await recordRuleEvent(tx, updated, "updated", keyHash);
		if (isLegacy(row) || isLegacy(updated))
			await rewriteAllowlistMirror(tx, tenantId, chainId);
		return updated;
	});
}

/** Removes a rule. Returns false when the tenant has no such rule on this chain. */
export async function deleteRule(
	db: Db,
	args: Scope & { id: string; keyHash: string | null },
): Promise<boolean> {
	return db.transaction(async (tx) => {
		await lockTenantRules(tx, args.tenantId, args.chainId);
		const [removed] = await tx
			.delete(tenantSponsorshipRules)
			.where(and(inScope(args), eq(tenantSponsorshipRules.id, args.id)))
			.returning();
		if (!removed) return false;
		await recordRuleEvent(tx, removed, "deleted", args.keyHash);
		if (isLegacy(removed))
			await rewriteAllowlistMirror(tx, args.tenantId, args.chainId);
		return true;
	});
}

export type RuleEventRow = typeof tenantSponsorshipRuleEvents.$inferSelect;

/** Rule events newest first, a page at a time. */
export async function listRuleEvents(
	db: Db,
	args: Scope & { limit: number; cursor?: string },
): Promise<{ events: RuleEventRow[]; nextCursor: string | null }> {
	const conditions = [
		eq(tenantSponsorshipRuleEvents.tenantId, args.tenantId),
		eq(tenantSponsorshipRuleEvents.chainId, args.chainId),
	];
	if (args.cursor !== undefined) {
		const after = decodeCursor(args.cursor);
		if (!after) throw new BadCursorError("not a cursor this API returned");
		const position = or(
			lt(tenantSponsorshipRuleEvents.createdAt, after.createdAt),
			and(
				eq(tenantSponsorshipRuleEvents.createdAt, after.createdAt),
				lt(tenantSponsorshipRuleEvents.id, after.id),
			),
		);
		if (position) conditions.push(position);
	}
	const rows = await db
		.select()
		.from(tenantSponsorshipRuleEvents)
		.where(and(...conditions))
		.orderBy(
			desc(tenantSponsorshipRuleEvents.createdAt),
			desc(tenantSponsorshipRuleEvents.id),
		)
		.limit(args.limit + 1);
	const page = rows.slice(0, args.limit);
	return {
		events: page,
		nextCursor:
			rows.length > args.limit ? encodeCursor(page[page.length - 1]) : null,
	};
}
