import assert from "node:assert";
import { eq } from "drizzle-orm";
import type { Address } from "viem";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
	tenantSponsorship,
	tenantSponsorshipRuleEvents,
	tenantSponsorshipRules,
	tenants,
} from "../src/db/schema.js";
import {
	ADMIN_KEY,
	type SponsorshipTestContext,
	startSponsorshipStack,
	stopTestStack,
	TENANT_A,
	TENANT_B,
} from "./setup.js";

/**
 * The sponsorship rules API (openspec sponsorship-rules-api): one rule per record, created, read,
 * changed and removed one at a time, with idempotent creates, expiry and a cap that hold under
 * concurrent requests; and the settings beside them, versioned with If-Match.
 */

const MAX_RULES = 5;

let ctx: SponsorshipTestContext;
let tenantAId: string;

beforeAll(async () => {
	ctx = await startSponsorshipStack({
		SPONSORSHIP_MAX_RULES_PER_CHAIN: String(MAX_RULES),
	});
	const [row] = await ctx.db
		.select({ id: tenants.id })
		.from(tenants)
		.where(eq(tenants.slug, TENANT_A.slug));
	assert(row, "expected tenant A to exist");
	tenantAId = row.id;
}, 180_000);

afterAll(async () => {
	if (ctx) await stopTestStack(ctx);
});

beforeEach(async () => {
	await ctx.db.delete(tenantSponsorshipRules);
	await ctx.db.delete(tenantSponsorshipRuleEvents);
	await ctx.db.delete(tenantSponsorship);
});

/** A distinct contract address for index `n`. */
const contract = (n: number) =>
	`0x${n.toString(16).padStart(40, "0")}` as Address;

type Rule = {
	id: string;
	contract: string;
	functions: "all" | string[];
	clientReference: string | null;
	expiresAt: string | null;
};

function call(
	method: "GET" | "POST" | "PATCH" | "DELETE" | "PUT",
	url: string,
	{
		payload,
		key = ADMIN_KEY,
		headers = {},
	}: { payload?: unknown; key?: string; headers?: Record<string, string> } = {},
) {
	return ctx.app.inject({
		method,
		url,
		headers: { authorization: `Bearer ${key}`, ...headers },
		...(payload === undefined ? {} : { payload: payload as object }),
	});
}

const createRule = (payload: unknown, key?: string) =>
	call("POST", "/v1/admin/sponsorship/rules", { payload, key });

const inAMinute = () => new Date(Date.now() + 60_000).toISOString();

describe("creating a rule", () => {
	it("creates one rule and stores a signature as its selector", async () => {
		const res = await createRule({
			contract: contract(1),
			functions: ["transfer(address,uint256)"],
		});
		expect(res.statusCode).toBe(201);
		expect(res.json()).toMatchObject({
			contract: contract(1),
			functions: ["0xa9059cbb"],
			clientReference: null,
			expiresAt: null,
		});
	});

	it("returns the existing rule for a retried create with the same reference", async () => {
		const body = {
			contract: contract(1),
			functions: "all",
			clientReference: "milestone-1",
			expiresAt: inAMinute(),
		};
		const first = await createRule(body);
		const second = await createRule(body);
		expect(first.statusCode).toBe(201);
		expect(second.statusCode).toBe(200);
		expect((second.json() as Rule).id).toBe((first.json() as Rule).id);
		expect(await ctx.db.select().from(tenantSponsorshipRules)).toHaveLength(1);
	});

	it("refuses a reference reused for another rule", async () => {
		await createRule({
			contract: contract(1),
			functions: "all",
			clientReference: "milestone-1",
		});
		const res = await createRule({
			contract: contract(2),
			functions: "all",
			clientReference: "milestone-1",
		});
		expect(res.statusCode).toBe(409);
		expect(res.json()).toMatchObject({
			error: "client-reference-conflict",
			rule: { contract: contract(1) },
		});
	});

	it("refuses a second active rule for the same contract, naming the first", async () => {
		const first = (
			await createRule({ contract: contract(1), functions: "all" })
		).json() as Rule;
		const res = await createRule({ contract: contract(1), functions: "all" });
		expect(res.statusCode).toBe(409);
		expect(res.json()).toMatchObject({
			error: "duplicate-contract",
			rule: { id: first.id },
		});
	});

	it("does not let an expired rule block a new one for the same contract", async () => {
		await ctx.db.insert(tenantSponsorshipRules).values({
			tenantId: tenantAId,
			chainId: 31337,
			contract: contract(1),
			functions: "all",
			expiresAt: new Date(Date.now() - 1_000),
		});
		const res = await createRule({ contract: contract(1), functions: "all" });
		expect(res.statusCode).toBe(201);
		const events = await ctx.db.select().from(tenantSponsorshipRuleEvents);
		expect(events.map((e) => e.action).sort()).toEqual([
			"created",
			"expired-removed",
		]);
	});

	it("refuses an expiry that is not in the future, and an unknown field", async () => {
		const past = await createRule({
			contract: contract(1),
			functions: "all",
			expiresAt: new Date(Date.now() - 1_000).toISOString(),
		});
		expect(past.statusCode).toBe(400);
		const unknown = await createRule({
			contract: contract(1),
			functions: "all",
			chain: 1,
		});
		expect(unknown.statusCode).toBe(400);
	});

	it("keeps every rule of concurrent creates", async () => {
		const results = await Promise.all(
			[1, 2, 3, 4].map((n) =>
				createRule({ contract: contract(n), functions: "all" }),
			),
		);
		expect(results.map((r) => r.statusCode)).toEqual([201, 201, 201, 201]);
		const list = await call("GET", "/v1/admin/sponsorship/rules");
		expect((list.json() as { rules: Rule[] }).rules).toHaveLength(4);
	});
});

describe("the cap on active rules", () => {
	it("holds under concurrent creates", async () => {
		const results = await Promise.all(
			Array.from({ length: MAX_RULES * 2 }, (_, n) =>
				createRule({ contract: contract(n + 1), functions: "all" }),
			),
		);
		const codes = results.map((r) => r.statusCode);
		expect(codes.filter((c) => c === 201)).toHaveLength(MAX_RULES);
		expect(codes.filter((c) => c === 409)).toHaveLength(MAX_RULES);
		expect(
			results
				.filter((r) => r.statusCode === 409)
				.every(
					(r) => (r.json() as { error: string }).error === "rule-limit-reached",
				),
		).toBe(true);
	});

	it("does not count expired rules", async () => {
		await ctx.db.insert(tenantSponsorshipRules).values({
			tenantId: tenantAId,
			chainId: 31337,
			contract: contract(100),
			functions: "all",
			expiresAt: new Date(Date.now() - 1_000),
		});
		for (let n = 1; n < MAX_RULES; n++)
			await createRule({ contract: contract(n), functions: "all" });
		const res = await createRule({ contract: contract(50), functions: "all" });
		expect(res.statusCode).toBe(201);
	});
});

describe("reading rules", () => {
	it("lists active rules newest first, a page at a time, and filters by reference", async () => {
		for (const n of [1, 2, 3])
			await createRule({
				contract: contract(n),
				functions: "all",
				clientReference: `ref-${n}`,
			});
		const first = (
			await call("GET", "/v1/admin/sponsorship/rules?limit=2")
		).json() as { rules: Rule[]; nextCursor: string | null };
		expect(first.rules.map((r) => r.contract)).toEqual([
			contract(3),
			contract(2),
		]);
		assert(first.nextCursor);
		const second = (
			await call(
				"GET",
				`/v1/admin/sponsorship/rules?limit=2&cursor=${first.nextCursor}`,
			)
		).json() as { rules: Rule[]; nextCursor: string | null };
		expect(second.rules.map((r) => r.contract)).toEqual([contract(1)]);
		expect(second.nextCursor).toBeNull();

		const byRef = (
			await call("GET", "/v1/admin/sponsorship/rules?clientReference=ref-2")
		).json() as { rules: Rule[] };
		expect(byRef.rules.map((r) => r.contract)).toEqual([contract(2)]);
	});

	it("lists expired rules only when asked", async () => {
		await ctx.db.insert(tenantSponsorshipRules).values({
			tenantId: tenantAId,
			chainId: 31337,
			contract: contract(1),
			functions: "all",
			expiresAt: new Date(Date.now() - 1_000),
		});
		const active = (
			await call("GET", "/v1/admin/sponsorship/rules")
		).json() as {
			rules: Rule[];
		};
		const all = (
			await call("GET", "/v1/admin/sponsorship/rules?includeExpired=true")
		).json() as { rules: Rule[] };
		expect(active.rules).toHaveLength(0);
		expect(all.rules).toHaveLength(1);
	});

	it("answers 404 for another tenant's rule", async () => {
		const rule = (
			await createRule({ contract: contract(1), functions: "all" })
		).json() as Rule;
		const own = await call("GET", `/v1/admin/sponsorship/rules/${rule.id}`);
		expect(own.statusCode).toBe(200);
		for (const method of ["GET", "PATCH", "DELETE"] as const) {
			const res = await call(method, `/v1/admin/sponsorship/rules/${rule.id}`, {
				key: TENANT_B.adminKey,
				...(method === "PATCH" ? { payload: { functions: "all" } } : {}),
			});
			expect(res.statusCode).toBe(404);
		}
	});
});

describe("changing and removing a rule", () => {
	it("changes the functions and the expiry, and refuses the contract and reference", async () => {
		const rule = (
			await createRule({ contract: contract(1), functions: "all" })
		).json() as Rule;
		const url = `/v1/admin/sponsorship/rules/${rule.id}`;
		const narrowed = await call("PATCH", url, {
			payload: { functions: ["release()"], expiresAt: inAMinute() },
		});
		expect(narrowed.statusCode).toBe(200);
		expect((narrowed.json() as Rule).functions).toEqual(["0x86d1a69f"]);
		expect((narrowed.json() as Rule).expiresAt).not.toBeNull();

		const cleared = await call("PATCH", url, { payload: { expiresAt: null } });
		expect((cleared.json() as Rule).expiresAt).toBeNull();

		const fixed = await call("PATCH", url, {
			payload: { contract: contract(2) },
		});
		expect(fixed.statusCode).toBe(400);
		const empty = await call("PATCH", url, { payload: {} });
		expect(empty.statusCode).toBe(400);
	});

	it("removes a rule, and records who did", async () => {
		const rule = (
			await createRule({ contract: contract(1), functions: "all" })
		).json() as Rule;
		const removed = await call(
			"DELETE",
			`/v1/admin/sponsorship/rules/${rule.id}`,
		);
		expect(removed.statusCode).toBe(204);
		const again = await call(
			"DELETE",
			`/v1/admin/sponsorship/rules/${rule.id}`,
		);
		expect(again.statusCode).toBe(404);

		const events = (
			await call("GET", "/v1/admin/sponsorship/rules/events")
		).json() as {
			events: Array<{
				action: string;
				ruleId: string;
				createdByKeyHash: string;
			}>;
		};
		expect(events.events.map((e) => e.action)).toEqual(["deleted", "created"]);
		expect(events.events.every((e) => e.ruleId === rule.id)).toBe(true);
		expect(events.events[0].createdByKeyHash).toMatch(/^[0-9a-f]{64}$/);
	});
});

describe("the allowlist mirror", () => {
	it("shows a rule with no reference and no expiry in the deprecated allowlist", async () => {
		await call("PUT", "/v1/admin/sponsorship", {
			payload: { enabled: true, maxCostPerTxWei: "1000" },
		});
		const legacy = (
			await createRule({ contract: contract(1), functions: "all" })
		).json() as Rule;
		await createRule({
			contract: contract(2),
			functions: "all",
			clientReference: "milestone-2",
		});
		const settings = (await call("GET", "/v1/admin/sponsorship")).json() as {
			config: { allowlist: Array<{ contract: string }> };
		};
		expect(settings.config.allowlist.map((e) => e.contract)).toEqual([
			contract(1),
		]);

		await call("DELETE", `/v1/admin/sponsorship/rules/${legacy.id}`);
		const after = (await call("GET", "/v1/admin/sponsorship")).json() as {
			config: { allowlist: unknown[] };
		};
		expect(after.config.allowlist).toEqual([]);
	});
});

describe("versioned settings", () => {
	const settings = { enabled: true, maxCostPerTxWei: "1000" };

	it("starts at version 0, and every write increments it", async () => {
		const before = await call("GET", "/v1/admin/sponsorship");
		expect(before.headers.etag).toBe('"0"');
		expect((before.json() as { version: number }).version).toBe(0);
		const first = await call("PUT", "/v1/admin/sponsorship", {
			payload: settings,
			headers: { "if-match": '"0"' },
		});
		expect(first.statusCode).toBe(200);
		expect(first.headers.etag).toBe('"1"');
		const second = await call("PATCH", "/v1/admin/sponsorship", {
			payload: { maxCostPerTxWei: "2000" },
			headers: { "if-match": '"1"' },
		});
		expect((second.json() as { version: number }).version).toBe(2);
	});

	it("refuses a stale If-Match with the current version, and changes nothing", async () => {
		await call("PUT", "/v1/admin/sponsorship", { payload: settings });
		const stale = await call("PUT", "/v1/admin/sponsorship", {
			payload: {
				...settings,
				allowlist: [{ contract: contract(9), functions: "all" }],
			},
			headers: { "if-match": '"0"' },
		});
		expect(stale.statusCode).toBe(412);
		expect(stale.json()).toMatchObject({
			error: "version-mismatch",
			currentVersion: 1,
		});
		expect(await ctx.db.select().from(tenantSponsorshipRules)).toHaveLength(0);
	});

	it("lets one of two writes from the same version through", async () => {
		await call("PUT", "/v1/admin/sponsorship", { payload: settings });
		const results = await Promise.all(
			["3000", "4000"].map((cap) =>
				call("PATCH", "/v1/admin/sponsorship", {
					payload: { maxCostPerTxWei: cap },
					headers: { "if-match": '"1"' },
				}),
			),
		);
		expect(results.map((r) => r.statusCode).sort()).toEqual([200, 412]);
	});

	it("refuses an If-Match that is not a version", async () => {
		const res = await call("PUT", "/v1/admin/sponsorship", {
			payload: settings,
			headers: { "if-match": "latest" },
		});
		expect(res.statusCode).toBe(412);
	});

	it("still accepts a write without If-Match", async () => {
		const res = await call("PUT", "/v1/admin/sponsorship", {
			payload: settings,
		});
		expect(res.statusCode).toBe(200);
	});
});
