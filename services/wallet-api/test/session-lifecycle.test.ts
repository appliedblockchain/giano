/**
 * Wallet session lifecycle (openspec change session-lifecycle, G5): absolute and idle expiry,
 * the per-user cap, sign out everywhere, and bearer-only CORS. Scenarios follow
 * specs/wallet-sessions/spec.md. Time is moved by backdating rows, never by waiting.
 */
import { createHash, randomBytes } from "node:crypto";
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { createSessionService } from "../src/services/sessions.js";
import {
	startTestStack,
	stopTestStack,
	TENANT_A,
	TENANT_B,
	type TestContext,
} from "./setup.js";
import {
	createAuthenticator,
	makeRegistrationResponse,
} from "./webauthn-fixtures.js";

let ctx: TestContext;
let service: ReturnType<typeof createSessionService>;

beforeAll(async () => {
	ctx = await startTestStack();
	service = createSessionService(ctx.db, {
		ttlSeconds: ctx.config.SESSION_TTL_SECONDS,
		idleTimeoutSeconds: ctx.config.SESSION_IDLE_TIMEOUT_SECONDS,
		maxPerUser: ctx.config.SESSION_MAX_PER_USER,
	});
}, 120_000);

afterAll(async () => {
	if (ctx) await stopTestStack(ctx);
});

const UNAUTHORIZED = {
	error: "unauthorized",
	message: "invalid or expired session",
};

const sha256hex = (value: string) =>
	createHash("sha256").update(value).digest("hex");

type Registered = {
	token: string;
	walletAddress: string;
	userId: string;
	credentialDbId: string;
};

/** Registers a passkey on tenant A through the real ceremony and returns its session and ids. */
async function register(externalUserId: string): Promise<Registered> {
	const auth = createAuthenticator();
	const options = await ctx.app.inject({
		method: "POST",
		url: "/v1/webauthn/options",
		headers: { origin: TENANT_A.walletOrigin },
		payload: { externalUserId, kind: "registration" },
	});
	expect(options.statusCode).toBe(200);
	const res = await ctx.app.inject({
		method: "POST",
		url: "/v1/webauthn/registration/verify",
		headers: { origin: TENANT_A.walletOrigin },
		payload: {
			externalUserId,
			response: makeRegistrationResponse(auth, {
				challenge: (options.json() as { challenge: string }).challenge,
				origin: TENANT_A.walletOrigin,
				rpId: TENANT_A.rpId,
			}),
		},
	});
	expect(res.statusCode).toBe(200);
	const body = res.json() as {
		walletAddress: string;
		session: { token: string };
	};
	const { rows } = await ctx.db.execute<{
		user_id: string;
		credential_id: string;
	}>(
		sql`SELECT user_id, credential_id FROM sessions WHERE token_hash = ${sha256hex(body.session.token)}`,
	);
	return {
		token: body.session.token,
		walletAddress: body.walletAddress,
		userId: rows[0].user_id,
		credentialDbId: rows[0].credential_id,
	};
}

const me = (token: string) =>
	ctx.app.inject({
		method: "GET",
		url: "/v1/me",
		headers: { authorization: `Bearer ${token}` },
	});

const backdate = (token: string, column: "last_used_at", age: string) =>
	ctx.db.execute(
		sql`UPDATE sessions SET ${sql.raw(column)} = now() - ${age}::interval WHERE token_hash = ${sha256hex(token)}`,
	);

const sessionRow = async (token: string) => {
	const { rows } = await ctx.db.execute<{
		last_used_at: string;
		expires_at: string;
		revoked_at: string | null;
	}>(
		sql`SELECT last_used_at::text, expires_at::text, revoked_at::text FROM sessions WHERE token_hash = ${sha256hex(token)}`,
	);
	return rows[0];
};

/** Live sessions of one user, by the same definition the service uses. */
const liveCount = async (userId: string) => {
	const { rows } = await ctx.db.execute<{ n: number }>(
		sql`SELECT count(*)::int AS n FROM sessions
        WHERE user_id = ${userId} AND revoked_at IS NULL AND expires_at > now()
          AND last_used_at > now() - make_interval(secs => ${ctx.config.SESSION_IDLE_TIMEOUT_SECONDS})`,
	);
	return rows[0].n;
};

describe("issue", () => {
	it("stores only the token's hash", async () => {
		const { token } = await register("g5-issue");
		const { rows } = await ctx.db.execute<{ token_hash: string }>(
			sql`SELECT token_hash FROM sessions WHERE token_hash = ${sha256hex(token)} OR token_hash = ${token}`,
		);
		expect(rows).toEqual([{ token_hash: sha256hex(token) }]);
		expect(Buffer.from(token, "base64url")).toHaveLength(32);
	});

	it("refuses a session for a credential removed as an owner", async () => {
		const user = await register("g5-removed");
		await ctx.db.execute(
			sql`UPDATE credentials SET removed_at = now() WHERE id = ${user.credentialDbId}`,
		);
		await expect(
			service.create(user.userId, user.credentialDbId),
		).rejects.toThrow(/no longer an owner/);
	});
});

describe("absolute and idle expiry", () => {
	it("accepts a session used again within the idle window", async () => {
		const { token } = await register("g5-idle-ok");
		await backdate(token, "last_used_at", "50 minutes");
		expect((await me(token)).statusCode).toBe(200);
	});

	it("refuses a session idle for longer than the timeout, and the refusal does not revive it", async () => {
		const { token } = await register("g5-idle");
		await backdate(token, "last_used_at", "61 minutes");
		const before = await sessionRow(token);
		const res = await me(token);
		expect(res.statusCode).toBe(401);
		expect(res.json()).toEqual(UNAUTHORIZED);
		expect((await sessionRow(token)).last_used_at).toBe(before.last_used_at);
		expect((await me(token)).statusCode).toBe(401);
	});

	it("never extends the absolute expiry, however recently the session was used", async () => {
		const { token } = await register("g5-absolute");
		await backdate(token, "last_used_at", "2 minutes");
		const before = await sessionRow(token);
		expect((await me(token)).statusCode).toBe(200);
		const after = await sessionRow(token);
		expect(after.expires_at).toBe(before.expires_at);
		expect(after.last_used_at).not.toBe(before.last_used_at);

		await ctx.db.execute(
			sql`UPDATE sessions SET expires_at = now() - interval '1 second' WHERE token_hash = ${sha256hex(token)}`,
		);
		const res = await me(token);
		expect(res.statusCode).toBe(401);
		expect(res.json()).toEqual(UNAUTHORIZED);
	});

	it("writes the last use at most once a minute", async () => {
		const { token } = await register("g5-touch");
		const issued = (await sessionRow(token)).last_used_at;
		expect((await me(token)).statusCode).toBe(200);
		expect((await me(token)).statusCode).toBe(200);
		expect((await sessionRow(token)).last_used_at).toBe(issued);

		await backdate(token, "last_used_at", "61 seconds");
		const stale = (await sessionRow(token)).last_used_at;
		expect((await me(token)).statusCode).toBe(200);
		const touched = (await sessionRow(token)).last_used_at;
		expect(new Date(touched).getTime()).toBeGreaterThan(
			new Date(stale).getTime(),
		);
	});

	it("a request refused for a foreign origin or a suspended tenant does not refresh the session", async () => {
		const { token } = await register("g5-refused-touch");
		await backdate(token, "last_used_at", "61 seconds");
		const stale = (await sessionRow(token)).last_used_at;

		// another tenant's origin: refused, and the last use stays where it was
		const foreign = await ctx.app.inject({
			method: "GET",
			url: "/v1/me",
			headers: {
				authorization: `Bearer ${token}`,
				origin: TENANT_B.walletOrigin,
			},
		});
		expect(foreign.statusCode).toBe(401);
		expect((await sessionRow(token)).last_used_at).toBe(stale);

		// its own tenant suspended: refused too, and still not refreshed
		await ctx.db.execute(
			sql`UPDATE tenants SET status = 'suspended' WHERE slug = ${TENANT_A.slug}`,
		);
		try {
			expect((await me(token)).statusCode).toBe(401);
		} finally {
			await ctx.db.execute(
				sql`UPDATE tenants SET status = 'active' WHERE slug = ${TENANT_A.slug}`,
			);
		}
		expect((await sessionRow(token)).last_used_at).toBe(stale);

		// accepted again once the tenant is back: that use is recorded
		expect((await me(token)).statusCode).toBe(200);
		expect(
			new Date((await sessionRow(token)).last_used_at).getTime(),
		).toBeGreaterThan(new Date(stale).getTime());
	});

	it("answers every dead session with the same 401 body", async () => {
		const revoked = await register("g5-401-revoked");
		await ctx.app.inject({
			method: "POST",
			url: "/v1/sessions/logout",
			headers: { authorization: `Bearer ${revoked.token}` },
		});
		const expired = await register("g5-401-expired");
		await ctx.db.execute(
			sql`UPDATE sessions SET expires_at = now() - interval '1 second' WHERE token_hash = ${sha256hex(expired.token)}`,
		);
		const idle = await register("g5-401-idle");
		await backdate(idle.token, "last_used_at", "2 hours");
		const unknown = randomBytes(32).toString("base64url");

		for (const token of [revoked.token, expired.token, idle.token, unknown]) {
			const res = await me(token);
			expect(res.statusCode).toBe(401);
			expect(res.json()).toEqual(UNAUTHORIZED);
		}
	});
});

describe("configuration", () => {
	const ENV = {
		NODE_ENV: "test",
		GIANO_DEPLOYMENT_CLASS: "development",
		GIANO_ENVIRONMENT: "test",
		LOG_LEVEL: "error",
		DATABASE_URL: "postgres://u:p@localhost:5432/x",
		CHAIN_ID: "31337",
		RPC_URL: "http://localhost:8545",
		BUNDLER_URL: "http://localhost:4337",
		ENTRYPOINT_ADDRESS: `0x${"1".repeat(40)}`,
		FACTORY_ADDRESS: `0x${"2".repeat(40)}`,
	} as NodeJS.ProcessEnv;

	it("defaults to a one-hour idle timeout and ten live sessions per user", () => {
		const config = loadConfig(ENV);
		expect(config.SESSION_IDLE_TIMEOUT_SECONDS).toBe(3600);
		expect(config.SESSION_MAX_PER_USER).toBe(10);
	});

	it("refuses an idle timeout above the absolute lifetime or below five minutes, naming the variable", () => {
		expect(() =>
			loadConfig({
				...ENV,
				SESSION_TTL_SECONDS: "3600",
				SESSION_IDLE_TIMEOUT_SECONDS: "7200",
			}),
		).toThrow(
			/SESSION_IDLE_TIMEOUT_SECONDS: must not exceed SESSION_TTL_SECONDS/,
		);
		expect(() =>
			loadConfig({ ...ENV, SESSION_IDLE_TIMEOUT_SECONDS: "299" }),
		).toThrow(/SESSION_IDLE_TIMEOUT_SECONDS/);
		expect(() => loadConfig({ ...ENV, SESSION_MAX_PER_USER: "0" })).toThrow(
			/SESSION_MAX_PER_USER/,
		);
	});
});

describe("live sessions per user are capped", () => {
	/** Issues `count` sessions for the user, each last used one minute before the next. */
	async function fill(user: Registered, count: number): Promise<string[]> {
		const ids: string[] = [];
		for (let i = 0; i < count; i++) {
			await service.create(user.userId, user.credentialDbId);
		}
		const { rows } = await ctx.db.execute<{ id: string }>(
			sql`SELECT id FROM sessions WHERE user_id = ${user.userId} ORDER BY created_at, id`,
		);
		for (const [i, row] of rows.entries()) {
			await ctx.db.execute(
				sql`UPDATE sessions SET last_used_at = now() - make_interval(mins => ${rows.length - i}) WHERE id = ${row.id}`,
			);
			ids.push(row.id);
		}
		return ids;
	}

	it("a sign-in over the cap revokes the session used longest ago, and only that one", async () => {
		const user = await register("g5-cap");
		// the registration's own session plus nine more: ten live, the cap
		const ids = await fill(user, 9);
		expect(ids).toHaveLength(10);
		expect(await liveCount(user.userId)).toBe(10);

		const { token } = await service.create(user.userId, user.credentialDbId);
		expect((await me(token)).statusCode).toBe(200);
		expect(await liveCount(user.userId)).toBe(10);
		const { rows } = await ctx.db.execute<{ id: string }>(
			sql`SELECT id FROM sessions WHERE user_id = ${user.userId} AND revoked_at IS NOT NULL`,
		);
		// the registration's session was backdated furthest: it is the one used longest ago
		expect(rows.map((r) => r.id)).toEqual([ids[0]]);
	});

	it("does not count revoked, expired or idle sessions", async () => {
		const user = await register("g5-cap-dead");
		const ids = await fill(user, 9);
		await ctx.db.execute(
			sql`UPDATE sessions SET revoked_at = now() WHERE id = ${ids[1]}`,
		);
		await ctx.db.execute(
			sql`UPDATE sessions SET expires_at = now() - interval '1 second' WHERE id = ${ids[2]}`,
		);
		await ctx.db.execute(
			sql`UPDATE sessions SET last_used_at = now() - interval '2 hours' WHERE id = ${ids[3]}`,
		);
		await service.create(user.userId, user.credentialDbId);
		const { rows } = await ctx.db.execute<{ n: number }>(
			sql`SELECT count(*)::int AS n FROM sessions WHERE user_id = ${user.userId} AND revoked_at IS NOT NULL`,
		);
		expect(rows[0].n).toBe(1);
		expect(await liveCount(user.userId)).toBe(8);
	});

	it("concurrent sign-ins never leave the user above the cap", async () => {
		const user = await register("g5-cap-race");
		await fill(user, 7);
		const issued = await Promise.all(
			Array.from({ length: 6 }, () =>
				service.create(user.userId, user.credentialDbId),
			),
		);
		expect(issued).toHaveLength(6);
		expect(await liveCount(user.userId)).toBe(ctx.config.SESSION_MAX_PER_USER);
		// the newest sign-in is never the one trimmed: which of the concurrent ones locked last is not
		// knowable, so one more after them all is the session that must survive
		const newest = await service.create(user.userId, user.credentialDbId);
		expect((await me(newest.token)).statusCode).toBe(200);
		expect(await liveCount(user.userId)).toBe(ctx.config.SESSION_MAX_PER_USER);
	});
});

describe("sign out everywhere", () => {
	it("revokes every session of the user, the calling one included", async () => {
		const laptop = await register("g5-everywhere");
		const phone = await service.create(laptop.userId, laptop.credentialDbId);

		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/sessions/logout-all",
			headers: { authorization: `Bearer ${laptop.token}` },
		});
		expect(res.statusCode).toBe(200);
		expect(res.json()).toEqual({ ok: true, revoked: 2 });
		expect((await me(laptop.token)).statusCode).toBe(401);
		expect((await me(phone.token)).statusCode).toBe(401);
	});

	it("leaves other users alone, even one acting for the same wallet", async () => {
		const caller = await register("g5-everywhere-caller");
		const other = await register("g5-everywhere-other");
		// a second user's session bound to the caller's wallet, as a co-owner's would be
		const coOwnerToken = randomBytes(32).toString("base64url");
		await ctx.db.execute(
			sql`INSERT INTO sessions (user_id, credential_id, wallet_address, token_hash, expires_at)
          VALUES (${other.userId}, ${other.credentialDbId}, ${caller.walletAddress}, ${sha256hex(coOwnerToken)}, now() + interval '1 day')`,
		);

		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/sessions/logout-all",
			headers: { authorization: `Bearer ${caller.token}` },
		});
		expect(res.json()).toEqual({ ok: true, revoked: 1 });
		expect((await me(other.token)).statusCode).toBe(200);
		expect((await me(coOwnerToken)).statusCode).toBe(200);
	});

	it("needs a session", async () => {
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/sessions/logout-all",
		});
		expect(res.statusCode).toBe(401);
	});
});

describe("CORS carries no credentials", () => {
	it("a preflight from a wallet origin allows the bearer header without Allow-Credentials", async () => {
		const res = await ctx.app.inject({
			method: "OPTIONS",
			url: "/v1/sessions/logout-all",
			headers: {
				origin: TENANT_A.walletOrigin,
				"access-control-request-method": "POST",
				"access-control-request-headers": "authorization, content-type",
			},
		});
		expect(res.statusCode).toBe(204);
		expect(res.headers["access-control-allow-origin"]).toBe(
			TENANT_A.walletOrigin,
		);
		expect(String(res.headers["access-control-allow-headers"])).toMatch(
			/authorization/i,
		);
		expect(res.headers["access-control-allow-credentials"]).toBeUndefined();
	});

	it("an actual response carries no Allow-Credentials either", async () => {
		const { token } = await register("g5-cors");
		const res = await ctx.app.inject({
			method: "GET",
			url: "/v1/me",
			headers: {
				origin: TENANT_A.walletOrigin,
				authorization: `Bearer ${token}`,
			},
		});
		expect(res.statusCode).toBe(200);
		expect(res.headers["access-control-allow-origin"]).toBe(
			TENANT_A.walletOrigin,
		);
		expect(res.headers["access-control-allow-credentials"]).toBeUndefined();
	});
});
