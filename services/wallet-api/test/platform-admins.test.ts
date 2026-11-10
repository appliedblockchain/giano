import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { eq, sql } from "drizzle-orm";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	platformAdminHistory,
	platformAdminSessions,
	platformAdmins,
} from "../src/db/schema.js";
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

describe("sign-ins and sessions (D15)", () => {
	type Session = {
		id: string;
		createdAt: string;
		revokedAt: string | null;
		userAgent: string | null;
		current: boolean;
	};
	const sessionsOf = async (token: string, id: string) =>
		(await as(token, "GET", `/v1/platform/admins/${id}/sessions`)).json()
			.sessions as Session[];
	const entry = async (token: string, id: string) =>
		(await as(token, "GET", "/v1/platform/admins"))
			.json()
			.admins.find((admin: { id: string }) => admin.id === id);

	/** An admin of its own, at a fresh address, so no other test's sign-ins count for it. */
	const freshAdmin = async (token: string, id: string) => {
		const address = privateKeyToAccount(generatePrivateKey()).address;
		const added = await as(token, "POST", "/v1/platform/admins", {
			id,
			address,
		});
		expect(added.statusCode).toBe(201);
		return address.toLowerCase();
	};
	const pastSession = (adminId: string, address: string, at: Date) =>
		ctx.db.insert(platformAdminSessions).values({
			tokenHash: `test-${adminId}-${at.getTime()}-${Math.random()}`,
			adminId,
			address,
			chainId: 31337,
			createdAt: at,
			expiresAt: new Date(at.getTime() + 3600 * 1000),
		});

	it("lists each admin's last sign-in and open sessions: yesterday's, with none open", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const yesterday = new Date(Date.now() - 24 * 3600 * 1000);
		const address = await freshAdmin(token, "admin-yesterday");
		await pastSession("admin-yesterday", address, yesterday);

		expect(await entry(token, "admin-yesterday")).toMatchObject({
			lastSignInAt: yesterday.toISOString(),
			activeSessions: 0,
		});
		const me = await entry(token, "admin-test");
		expect(me.activeSessions).toBeGreaterThanOrEqual(1);
		expect(Date.parse(me.lastSignInAt)).toBeGreaterThan(Date.now() - 60_000);
	});

	it("lists an admin's last 30 days of sessions, newest first, marking this one, never a token", async () => {
		const old = new Date(Date.now() - 31 * 24 * 3600 * 1000);
		await ctx.db.insert(platformAdminSessions).values({
			tokenHash: `test-old-${Date.now()}`,
			adminId: "admin-test",
			address: ADMIN.address.toLowerCase(),
			chainId: 31337,
			createdAt: old,
			expiresAt: new Date(old.getTime() + 3600 * 1000),
		});
		await platformSignIn(ctx.app, ADMIN);
		const token = await platformSignIn(ctx.app, ADMIN);

		const response = await as(
			token,
			"GET",
			"/v1/platform/admins/admin-test/sessions",
		);
		expect(response.statusCode).toBe(200);
		const sessions = response.json().sessions as (Session &
			Record<string, unknown>)[];
		expect(sessions[0].current).toBe(true);
		expect(sessions.filter((session) => session.current)).toHaveLength(1);
		expect(
			sessions.every(
				(session, i) =>
					i === 0 ||
					Date.parse(sessions[i - 1].createdAt) >=
						Date.parse(session.createdAt),
			),
		).toBe(true);
		expect(
			sessions.some(
				(session) => Date.parse(session.createdAt) <= old.getTime(),
			),
		).toBe(false);
		expect(Object.keys(sessions[0]).sort()).toEqual([
			"chainId",
			"createdAt",
			"current",
			"expiresAt",
			"id",
			"revokedAt",
			"userAgent",
		]);
		expect(response.body).not.toMatch(/gps_|token/i);
	});

	it("ends your own other session: it is refused at once, and yours continues", async () => {
		const mine = await platformSignIn(ctx.app, ADMIN);
		const other = await platformSignIn(ctx.app, ADMIN);
		// the session `other` signs its requests with, as the list marks it for that session
		const target = (await sessionsOf(other, "admin-test")).find(
			(session) => session.current,
		);
		expect(target).toBeDefined();

		const open = (await entry(mine, "admin-test")).activeSessions;

		const ended = await as(
			mine,
			"DELETE",
			`/v1/platform/admins/admin-test/sessions/${target?.id}`,
		);
		expect(ended.statusCode).toBe(204);
		expect((await entry(mine, "admin-test")).activeSessions).toBe(open - 1);
		expect((await as(other, "GET", "/v1/platform/admins")).statusCode).toBe(
			401,
		);
		expect((await as(mine, "GET", "/v1/platform/admins")).statusCode).toBe(200);
		const after = (await sessionsOf(mine, "admin-test")).find(
			(session) => session.id === target?.id,
		);
		expect(after?.revokedAt).not.toBeNull();
		// ending it again changes nothing
		expect(
			(
				await as(
					mine,
					"DELETE",
					`/v1/platform/admins/admin-test/sessions/${target?.id}`,
				)
			).statusCode,
		).toBe(204);
	});

	it("lists another admin's sessions without the browser they were signed from", async () => {
		const theirs = await platformSignIn(ctx.app, SECOND_ADMIN);
		const own = (await sessionsOf(theirs, "admin-second")).find(
			(session) => session.current,
		);
		// the sign-in request carried a user agent, so their own view has it
		expect(own?.userAgent).not.toBeNull();

		const mine = await platformSignIn(ctx.app, ADMIN);
		const seen = await sessionsOf(mine, "admin-second");
		expect(seen.some((session) => session.id === own?.id)).toBe(true);
		expect(seen.every((session) => session.userAgent === null)).toBe(true);
	});

	it("leaves an expired session expired when asked to end it", async () => {
		const mine = await platformSignIn(ctx.app, ADMIN);
		const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000);
		await pastSession("admin-test", ADMIN.address.toLowerCase(), twoHoursAgo);
		const expired = (await sessionsOf(mine, "admin-test")).find(
			(session) => session.createdAt === twoHoursAgo.toISOString(),
		);
		expect(expired).toBeDefined();

		expect(
			(
				await as(
					mine,
					"DELETE",
					`/v1/platform/admins/admin-test/sessions/${expired?.id}`,
				)
			).statusCode,
		).toBe(204);
		const after = (await sessionsOf(mine, "admin-test")).find(
			(session) => session.id === expired?.id,
		);
		expect(after?.revokedAt).toBeNull();
	});

	it("refuses a session id that is not one", async () => {
		const mine = await platformSignIn(ctx.app, ADMIN);
		expect(
			(
				await as(
					mine,
					"DELETE",
					"/v1/platform/admins/admin-test/sessions/not-a-session",
				)
			).statusCode,
		).toBe(400);
	});

	it("matches sessions by address: a reused id does not inherit the old admin's", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const first = await freshAdmin(token, "admin-reused");
		await pastSession(
			"admin-reused",
			first,
			new Date(Date.now() - 3600 * 1000),
		);
		expect(
			(await as(token, "DELETE", "/v1/platform/admins/admin-reused"))
				.statusCode,
		).toBe(204);
		await freshAdmin(token, "admin-reused");

		expect(await entry(token, "admin-reused")).toMatchObject({
			lastSignInAt: null,
			activeSessions: 0,
		});
		expect(await sessionsOf(token, "admin-reused")).toEqual([]);
	});

	it("refuses to end another admin's session, which continues", async () => {
		const mine = await platformSignIn(ctx.app, ADMIN);
		const theirs = await platformSignIn(ctx.app, SECOND_ADMIN);
		const target = (await sessionsOf(theirs, "admin-second")).find(
			(session) => session.current,
		);

		const refused = await as(
			mine,
			"DELETE",
			`/v1/platform/admins/admin-second/sessions/${target?.id}`,
		);
		expect(refused.statusCode).toBe(403);
		expect(refused.json().error).toBe("not-your-session");
		expect((await as(theirs, "GET", "/v1/platform/admins")).statusCode).toBe(
			200,
		);
		// nor by naming yourself with their session
		expect(
			(
				await as(
					mine,
					"DELETE",
					`/v1/platform/admins/admin-test/sessions/${target?.id}`,
				)
			).statusCode,
		).toBe(404);
		expect((await as(theirs, "GET", "/v1/platform/admins")).statusCode).toBe(
			200,
		);
	});

	it("answers an unknown admin with 404", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		expect(
			(await as(token, "GET", "/v1/platform/admins/nobody/sessions"))
				.statusCode,
		).toBe(404);
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
