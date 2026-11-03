import { sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	sponsorshipDecisions,
	sponsorshipSettlements,
	tenants,
} from "../src/db/schema.js";
import { refusalCategory } from "../src/services/usage.js";
import {
	ADMIN,
	PLATFORM_ENV,
	platformSignIn,
	startTestStack,
	stopTestStack,
	TENANT_A,
	TENANT_B,
	type TestContext,
} from "./setup.js";

/**
 * GET /v1/platform/usage (openspec platform-usage-metrics): one chain's sponsorship decisions and
 * settlements over a range, in total and per tenant, from the rows wallet-api records.
 */

const DAY = 86_400_000;
const SENDER = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";

let ctx: TestContext;
let idA: string;
let idB: string;

beforeAll(async () => {
	ctx = await startTestStack(PLATFORM_ENV);
	const rows = await ctx.db
		.select({ id: tenants.id, slug: tenants.slug })
		.from(tenants);
	idA = rows.find((row) => row.slug === TENANT_A.slug)?.id ?? "";
	idB = rows.find((row) => row.slug === TENANT_B.slug)?.id ?? "";
	const now = Date.now();
	const decision = (
		tenantId: string,
		outcome: "allowed" | "refused",
		reason: string | null,
		ageDays: number,
		chainId = 31337,
	) => ({
		tenantId,
		chainId,
		method: "data" as const,
		sender: SENDER,
		outcome,
		reason,
		createdAt: new Date(now - ageDays * DAY),
	});
	await ctx.db.insert(sponsorshipDecisions).values([
		decision(idA, "allowed", null, 1),
		decision(idA, "allowed", null, 2),
		decision(idA, "refused", "contract-not-allowed", 1),
		decision(idA, "refused", "insufficient-balance", 3),
		decision(idB, "refused", "temporarily-unavailable", 1),
		decision(idB, "refused", "sponsorship-disabled", 1),
		// outside the default seven days, and on another chain: neither counts
		decision(idA, "allowed", null, 10),
		decision(idB, "allowed", null, 1, 31338),
	]);
	let hash = 0;
	const settlement = (
		tenantId: string | null,
		success: boolean,
		ageDays: number,
	) => ({
		chainId: 31337,
		useropHash: `0x${(++hash).toString(16).padStart(64, "0")}`,
		tenantId,
		sender: SENDER,
		gasCostWei: "1000",
		feeWei: "10",
		overheadWei: "5",
		totalWei: "1015",
		success,
		blockNumber: BigInt(hash),
		logIndex: 0,
		observedAt: new Date(now - ageDays * DAY),
	});
	await ctx.db.insert(sponsorshipSettlements).values([
		settlement(idA, true, 1),
		settlement(idA, false, 2),
		settlement(idB, true, 1),
		// a tenant since deleted keeps its settlement, without a tenant
		settlement(null, true, 1),
		settlement(idA, true, 40),
	]);
});

afterAll(async () => {
	await stopTestStack(ctx);
});

const get = async (query: string, signedIn = true) =>
	ctx.app.inject({
		method: "GET",
		url: `/v1/platform/usage${query}`,
		headers: signedIn
			? { authorization: `Bearer ${await platformSignIn(ctx.app, ADMIN)}` }
			: {},
	});

describe("GET /v1/platform/usage", () => {
	it("refuses a request without a platform admin session", async () => {
		expect((await get("?chainId=31337", false)).statusCode).toBe(401);
	});

	it("covers the last seven days by default, in total and per tenant, never another chain", async () => {
		const response = await get("?chainId=31337");
		expect(response.statusCode).toBe(200);
		const body = response.json();
		expect(Date.parse(body.until) - Date.parse(body.since)).toBe(7 * DAY);
		expect(body.total).toEqual({
			decisions: {
				allowed: 2,
				refused: 4,
				refusedBy: { rules: 1, funds: 1, platform: 2, other: 0 },
				byReason: {
					"contract-not-allowed": 1,
					"insufficient-balance": 1,
					"temporarily-unavailable": 1,
					"sponsorship-disabled": 1,
				},
			},
			settled: 4,
			reverted: 1,
			gasWei: "4000",
			feeWei: "40",
			overheadWei: "20",
		});
		const bySlug = Object.fromEntries(
			body.tenants.map((tenant: { slug: string | null }) => [
				tenant.slug ?? "deleted",
				tenant,
			]),
		);
		expect(bySlug[TENANT_A.slug]).toMatchObject({
			tenantId: idA,
			decisions: { allowed: 2, refused: 2, refusedBy: { rules: 1, funds: 1 } },
			settled: 2,
			reverted: 1,
			gasWei: "2000",
		});
		expect(bySlug[TENANT_B.slug].decisions.refusedBy.platform).toBe(2);
		expect(bySlug.deleted).toMatchObject({ tenantId: null, settled: 1 });
	});

	it("takes a range, up to 90 days", async () => {
		const until = new Date();
		const since = new Date(until.getTime() - 60 * DAY);
		const body = (
			await get(
				`?chainId=31337&since=${since.toISOString()}&until=${until.toISOString()}`,
			)
		).json();
		expect(body.total.decisions.allowed).toBe(3);
		expect(body.total.settled).toBe(5);
	});

	it("refuses a range longer than 90 days, naming the limit", async () => {
		const until = new Date();
		const since = new Date(until.getTime() - 91 * DAY);
		const response = await get(
			`?chainId=31337&since=${since.toISOString()}&until=${until.toISOString()}`,
		);
		expect(response.statusCode).toBe(400);
		expect(response.json()).toMatchObject({
			error: "range-too-long",
			maxDays: 90,
		});
		expect(response.json().message).toContain("90 days");
	});

	it("answers a chain this deployment does not serve with 404", async () => {
		expect((await get("?chainId=1")).statusCode).toBe(404);
	});

	it("reads the decisions and settlements by chain and time from their indexes", async () => {
		// A busy chain's two years, so the planner has a reason to prefer the time: inside a
		// transaction that is rolled back, so the rows never reach the other tests.
		const plans: string[] = [];
		await ctx.db
			.transaction(async (tx) => {
				await tx.execute(sql`
          INSERT INTO sponsorship_decisions (tenant_id, chain_id, method, sender, outcome, created_at)
          SELECT ${idA}, 31337, 'data', ${SENDER}, 'allowed', now() - (n || ' hours')::interval
          FROM generate_series(1, 20000) AS n`);
				await tx.execute(sql`
          INSERT INTO sponsorship_settlements (chain_id, userop_hash, tenant_id, sender, gas_cost_wei, fee_wei, overhead_wei, total_wei, success, block_number, log_index, observed_at)
          SELECT 31337, 'bulk-' || n, ${idA}, ${SENDER}, 1, 1, 1, 3, true, n, 0, now() - (n || ' hours')::interval
          FROM generate_series(1, 20000) AS n`);
				await tx.execute(sql`ANALYZE sponsorship_decisions`);
				await tx.execute(sql`ANALYZE sponsorship_settlements`);
				for (const query of [
					sql`EXPLAIN SELECT tenant_id, outcome, reason, count(*) FROM sponsorship_decisions WHERE chain_id = 31337 AND created_at >= now() - interval '90 days' AND created_at < now() GROUP BY 1, 2, 3`,
					sql`EXPLAIN SELECT tenant_id, count(*) FROM sponsorship_settlements WHERE chain_id = 31337 AND observed_at >= now() - interval '90 days' AND observed_at < now() GROUP BY 1`,
				]) {
					const result = await tx.execute(query);
					plans.push(
						result.rows.map((row) => Object.values(row)[0]).join("\n"),
					);
				}
				tx.rollback();
			})
			.catch((error: Error) => {
				if (!/rollback/i.test(error.message)) throw error;
			});
		expect(plans[0]).toContain("sponsorship_decisions_chain_created_idx");
		expect(plans[1]).toContain("sponsorship_settlements_chain_observed_idx");
	});
});

describe("refusalCategory", () => {
	it("puts a tenant's rules and funds apart from the platform's switch and outages", () => {
		expect(refusalCategory("function-not-allowed")).toBe("rules");
		expect(refusalCategory("tenant-in-deficit")).toBe("funds");
		expect(refusalCategory("sponsorship-disabled")).toBe("platform");
		expect(refusalCategory("not-your-wallet")).toBe("other");
		expect(refusalCategory(null)).toBe("other");
	});
});
