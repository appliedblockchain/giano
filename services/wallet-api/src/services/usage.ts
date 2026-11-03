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
 * fix; the platform's switch and its outages are the platform's. Split, so the Overview does not
 * blame the platform for a tenant's rules.
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
	"sponsorship-disabled": "platform",
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
	total: UsageFigures;
	/** One per tenant that had a decision or a settlement in the range; `slug` null once deleted. */
	tenants: (UsageFigures & { tenantId: string | null; slug: string | null })[];
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

export async function readUsage(
	db: Db,
	query: { chainId: number; since: Date; until: Date },
): Promise<Usage> {
	const { chainId, since, until } = query;
	const [decisions, settlements] = await Promise.all([
		db
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
		db
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
	const perTenant = new Map<string | null, UsageFigures>();
	const of = (tenantId: string | null) => {
		let figures = perTenant.get(tenantId);
		if (!figures) {
			figures = empty();
			perTenant.set(tenantId, figures);
		}
		return figures;
	};

	for (const row of decisions) {
		for (const figures of [total, of(row.tenantId)]) {
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
		for (const figures of [total, of(row.tenantId)]) {
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
				slug: tenantId ? (slugs.get(tenantId) ?? null) : null,
				...figures,
			}))
			.sort((a, b) => (a.slug ?? "~").localeCompare(b.slug ?? "~")),
	};
}
