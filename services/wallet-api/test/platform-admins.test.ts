import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { platformAdminHistory, platformAdmins } from "../src/db/schema.js";
import {
	bootstrapAdmins,
	createPlatformAdminService,
} from "../src/services/platform-admins.js";
import {
	ADMIN,
	PLATFORM_ENV,
	platformSignIn,
	SECOND_ADMIN,
	STRANGER,
	startTestStack,
	stopTestStack,
	type TestContext,
} from "./setup.js";

/**
 * The platform admins as rows (specs/PLATFORM-ADMIN-SPECS.md §4.1, openspec change platform admins-in-database):
 * seeded once per environment into an empty table, managed by the platform admins from then on, with
 * every change recorded and the deployment never left without a platform admin.
 */

let ctx: TestContext;

beforeAll(async () => {
	ctx = await startTestStack(PLATFORM_ENV);
});

afterAll(async () => {
	await stopTestStack(ctx);
});

const as = async (
	token: string,
	method: "GET" | "POST" | "DELETE",
	url: string,
	payload?: object,
) =>
	ctx.app.inject({
		method,
		url,
		headers: { authorization: `Bearer ${token}` },
		...(payload ? { payload } : {}),
	});

describe("bootstrap", () => {
	it("writes nothing into a table that already has an admin", async () => {
		expect(
			await bootstrapAdmins(ctx.db, "dev", [
				{ id: "intruder", address: STRANGER.address },
			]),
		).toEqual([]);
		expect(
			await ctx.db
				.select()
				.from(platformAdmins)
				.where(eq(platformAdmins.id, "intruder")),
		).toEqual([]);
	});

	it("seeds an empty table once, recording each as bootstrap, even from replicas booting together", async () => {
		const saved = await ctx.db.select().from(platformAdmins);
		await ctx.db.delete(platformAdmins);
		try {
			const seeds = [
				{
					id: "giovanni",
					address: "0xFebBB1e5b6D66E6281d0d4d4816f76B69365a09d" as const,
				},
			];
			const results = await Promise.all([
				bootstrapAdmins(ctx.db, "dev", seeds),
				bootstrapAdmins(ctx.db, "dev", seeds),
			]);
			expect(results.flat()).toEqual(["giovanni"]);
			const [row] = await ctx.db.select().from(platformAdmins);
			expect(row).toMatchObject({
				id: "giovanni",
				address: "0xfebbb1e5b6d66e6281d0d4d4816f76b69365a09d",
				addedBy: "bootstrap:dev",
			});
			const history = await ctx.db
				.select()
				.from(platformAdminHistory)
				.where(eq(platformAdminHistory.adminId, "giovanni"));
			expect(history.map((h) => [h.action, h.actor])).toEqual([
				["bootstrap", "bootstrap:dev"],
			]);
		} finally {
			await ctx.db.delete(platformAdmins);
			await ctx.db.insert(platformAdmins).values(saved);
		}
	});
});

describe("managing admins from the console", () => {
	it("adds an admin who can sign in at once, and records who added them", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const added = await as(token, "POST", "/v1/platform/admins", {
			id: "admin-new",
			address: STRANGER.address,
		});
		expect(added.statusCode).toBe(201);
		expect(added.json()).toMatchObject({
			id: "admin-new",
			address: STRANGER.address.toLowerCase(),
			addedBy: `platform-admin:admin-test:${ADMIN.address.toLowerCase()}`,
		});
		await expect(platformSignIn(ctx.app, STRANGER)).resolves.toMatch(/^gps_/);

		const list = await as(token, "GET", "/v1/platform/admins");
		expect(list.json().admins.map((o: { id: string }) => o.id)).toEqual([
			"admin-second",
			"admin-test",
			"admin-new",
		]);
	});

	it("refuses a duplicate id or address, and a malformed one", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const byId = await as(token, "POST", "/v1/platform/admins", {
			id: "admin-test",
			address: `0x${"c".repeat(40)}`,
		});
		expect(byId.statusCode).toBe(409);
		expect(byId.json()).toMatchObject({ error: "conflict", field: "id" });
		const byAddress = await as(token, "POST", "/v1/platform/admins", {
			id: "admin-dup",
			address: ADMIN.address.toUpperCase().replace("0X", "0x"),
		});
		expect(byAddress.json()).toMatchObject({
			error: "conflict",
			field: "address",
		});
		expect(
			(
				await as(token, "POST", "/v1/platform/admins", {
					id: "Has Spaces",
					address: `0x${"c".repeat(40)}`,
				})
			).statusCode,
		).toBe(400);
	});

	it("removes an admin, ending their sessions at once; never yourself", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const theirs = await platformSignIn(ctx.app, STRANGER);

		const self = await as(token, "DELETE", "/v1/platform/admins/admin-test");
		expect(self.statusCode).toBe(409);
		expect(self.json().error).toBe("self-removal");

		expect(
			(await as(token, "DELETE", "/v1/platform/admins/admin-new")).statusCode,
		).toBe(204);
		expect((await as(theirs, "GET", "/v1/platform/admins")).statusCode).toBe(
			401,
		);
		expect(
			(await as(token, "DELETE", "/v1/platform/admins/admin-new")).statusCode,
		).toBe(404);

		const history = (
			await as(token, "GET", "/v1/platform/admins/history")
		).json().entries;
		expect(
			history
				.slice(0, 2)
				.map((e: { action: string; adminId: string }) => [e.action, e.adminId]),
		).toEqual([
			["remove", "admin-new"],
			["add", "admin-new"],
		]);
	});

	it("never removes the last admin", async () => {
		const service = createPlatformAdminService(ctx.db);
		const saved = await ctx.db.select().from(platformAdmins);
		await ctx.db
			.delete(platformAdmins)
			.where(eq(platformAdmins.id, "admin-second"));
		try {
			const outsider = {
				id: "admin-gone",
				address: STRANGER.address.toLowerCase(),
				sessionId: (await ctx.db.execute(sql`SELECT gen_random_uuid() AS id`))
					.rows[0].id as string,
			};
			await expect(
				service.remove("admin-test", outsider),
			).rejects.toMatchObject({ code: "last-admin" });
		} finally {
			await ctx.db.delete(platformAdmins);
			await ctx.db.insert(platformAdmins).values(saved);
		}
	});

	it("is an admin-only route: no session, no list", async () => {
		expect(
			(await ctx.app.inject({ method: "GET", url: "/v1/platform/admins" }))
				.statusCode,
		).toBe(401);
		expect(SECOND_ADMIN.address).not.toBe(ADMIN.address);
	});
});

describe("the init step", () => {
	it("refuses tenant fixtures outside a local stack, before touching the database", async () => {
		const run = promisify(execFile);
		const failure = await run("node_modules/.bin/tsx", ["src/init.ts"], {
			env: {
				...process.env,
				DATABASE_URL: "postgres://nobody@127.0.0.1:1/none",
				GIANO_ENVIRONMENT: "dev",
				TENANT_FIXTURES: "[]",
			},
		}).catch((error: { code: number; stderr: string }) => error);
		expect(failure).toMatchObject({
			code: 1,
			stderr: expect.stringContaining('"dev" is not a local stack'),
		});
	});

	it("refuses an unknown environment", async () => {
		const run = promisify(execFile);
		const failure = await run("node_modules/.bin/tsx", ["src/init.ts"], {
			env: {
				...process.env,
				DATABASE_URL: "postgres://nobody@127.0.0.1:1/none",
				GIANO_ENVIRONMENT: "staging",
			},
		}).catch((error: { code: number; stderr: string }) => error);
		expect(failure).toMatchObject({
			code: 1,
			stderr: expect.stringContaining("GIANO_ENVIRONMENT must be one of"),
		});
	});
});
