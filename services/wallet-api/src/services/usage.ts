import { and, eq, gte, inArray, lt, sql } from "drizzle-orm";
import type { Db } from "../db/index.js";
import {
	sponsorshipDecisions,
	sponsorshipSettlements,
	tenants,
} from "../db/schema.js";

/**
 * Sponsorship usage per chain and tenant (B4, openspec platform-usage-metrics): what wallet-api
 * decided and what settled, from the rows it already records. It never reads the chain.
 */

/** The longest range one request may cover. */
export const USAGE_MAX_DAYS = 90;
/** The range when the caller names none. */
export const USAGE_DEFAULT_DAYS = 7;

/**
 * Who a refusal is about. A tenant's own sponsorship rules and its own balance are the tenant's to
 * fix; the platform's outages and its emergency stop (both recorded as `temporarily-unavailable`)
 * are the platform's. Split, so the Overview does not blame the platform for a tenant's rules.
 *
 * `sponsorship-disabled` is the tenant's own switch: the only one recorded comes from the rules
 * engine (`enabled: false`, which the tenant sets, and which a tenant with no configuration gets).
 * The platform-level "this chain sponsors nothing" refusal returns before a decision is recorded.
 */
export type RefusalCategory = "rules" | "funds" | "platform" | "other";

const CATEGORY: Record<string, RefusalCategory> = {
	"no-sponsorship-config": "rules",
	"contract-not-allowed": "rules",
	"function-not-allowed": "rules",
	"wallet-management-not-sponsored": "rules",
	"cost-exceeds-cap": "rules",
	"insufficient-balance": "funds",
	"tenant-in-deficit": "funds",
	"sponsorship-disabled": "rules",
	"temporarily-unavailable": "platform",
};

export const refusalCategory = (reason: string | null): RefusalCategory =>
	(reason && CATEGORY[reason]) || "other";

export type UsageFigures = {
	decisions: {
		allowed: number;
		refused: number;
		refusedBy: Record<RefusalCategory, number>;
		byReason: Record<string, number>;
	};
	settled: number;
	reverted: number;
	gasWei: string;
	feeWei: string;
	overheadWei: string;
};

export type Usage = {
	chainId: number;
	since: Date;
	until: Date;
	/** This deployment's tenants only: what `unknownTenant` holds is not in it. */
	total: UsageFigures;
	/**
	 * One per tenant of this deployment that had a decision or a settlement in the range. Tenants
	 * are never hard-deleted, so a deleted tenant keeps its id and slug.
	 */
	tenants: (UsageFigures & { tenantId: string; slug: string })[];
	/**
	 * Settlements for a tenant id this deployment does not know (recorded with no tenant): on a shared
	 * paymaster, another deployment's operations. Reported apart, never added to `total`.
	 */
	unknownTenant: UsageFigures;
};

const empty = (): UsageFigures => ({
	decisions: {
		allowed: 0,
		refused: 0,
		refusedBy: { rules: 0, funds: 0, platform: 0, other: 0 },
		byReason: {},
	},
	settled: 0,
	reverted: 0,
	gasWei: "0",
	feeWei: "0",
	overheadWei: "0",
});

/**
 * The two aggregate queries, built apart so a test can EXPLAIN exactly what readUsage runs and see
 * that each stays on its (chain, time) index.
 */
export function usageQueries(
	db: Db,
	query: { chainId: number; since: Date; until: Date },
) {
	const { chainId, since, until } = query;
	return {
		decisions: db
			.select({
				tenantId: sponsorshipDecisions.tenantId,
				outcome: sponsorshipDecisions.outcome,
				reason: sponsorshipDecisions.reason,
				count: sql<number>`count(*)::int`,
			})
			.from(sponsorshipDecisions)
			.where(
				and(
					eq(sponsorshipDecisions.chainId, chainId),
					gte(sponsorshipDecisions.createdAt, since),
					lt(sponsorshipDecisions.createdAt, until),
				),
			)
			.groupBy(
				sponsorshipDecisions.tenantId,
				sponsorshipDecisions.outcome,
				sponsorshipDecisions.reason,
			),
		settlements: db
			.select({
				tenantId: sponsorshipSettlements.tenantId,
				settled: sql<number>`count(*)::int`,
				reverted: sql<number>`(count(*) filter (where not ${sponsorshipSettlements.success}))::int`,
				gasWei: sql<string>`coalesce(sum(${sponsorshipSettlements.gasCostWei}), 0)::text`,
				feeWei: sql<string>`coalesce(sum(${sponsorshipSettlements.feeWei}), 0)::text`,
				overheadWei: sql<string>`coalesce(sum(${sponsorshipSettlements.overheadWei}), 0)::text`,
			})
			.from(sponsorshipSettlements)
			.where(
				and(
					eq(sponsorshipSettlements.chainId, chainId),
					gte(sponsorshipSettlements.observedAt, since),
					lt(sponsorshipSettlements.observedAt, until),
				),
			)
			.groupBy(sponsorshipSettlements.tenantId),
	};
}

export async function readUsage(
	db: Db,
	query: { chainId: number; since: Date; until: Date },
): Promise<Usage> {
	const { chainId, since, until } = query;
	const queries = usageQueries(db, query);
	const [decisions, settlements] = await Promise.all([
		queries.decisions,
		queries.settlements,
	]);

	const ids = [
		...new Set(
			[...decisions, ...settlements]
				.map((row) => row.tenantId)
				.filter((id): id is string => id !== null),
		),
	];
	const slugs = new Map(
		(ids.length > 0
			? await db
					.select({ id: tenants.id, slug: tenants.slug })
					.from(tenants)
					.where(inArray(tenants.id, ids))
			: []
		).map((row) => [row.id, row.slug]),
	);

	const total = empty();
	const unknownTenant = empty();
	const perTenant = new Map<string, UsageFigures>();
	// A row with no tenant, or one the registry does not have, is not this deployment's usage.
	const known = (tenantId: string | null): tenantId is string =>
		tenantId !== null && slugs.has(tenantId);
	const targets = (tenantId: string | null): UsageFigures[] => {
		if (!known(tenantId)) return [unknownTenant];
		let figures = perTenant.get(tenantId);
		if (!figures) {
			figures = empty();
			perTenant.set(tenantId, figures);
		}
		return [total, figures];
	};

	for (const row of decisions) {
		for (const figures of targets(row.tenantId)) {
			if (row.outcome === "allowed") figures.decisions.allowed += row.count;
			else {
				const reason = row.reason ?? "unknown";
				figures.decisions.refused += row.count;
				figures.decisions.refusedBy[refusalCategory(row.reason)] += row.count;
				figures.decisions.byReason[reason] =
					(figures.decisions.byReason[reason] ?? 0) + row.count;
			}
		}
	}
	const add = (a: string, b: string) => (BigInt(a) + BigInt(b)).toString();
	for (const row of settlements) {
		for (const figures of targets(row.tenantId)) {
			figures.settled += row.settled;
			figures.reverted += row.reverted;
			figures.gasWei = add(figures.gasWei, row.gasWei);
			figures.feeWei = add(figures.feeWei, row.feeWei);
			figures.overheadWei = add(figures.overheadWei, row.overheadWei);
		}
	}

	return {
		chainId,
		since,
		until,
		total,
		tenants: [...perTenant.entries()]
			.map(([tenantId, figures]) => ({
				tenantId,
				slug: slugs.get(tenantId) as string,
				...figures,
			}))
			.sort((a, b) => a.slug.localeCompare(b.slug)),
		unknownTenant,
	};
}
