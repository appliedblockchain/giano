import { expect, test } from "@playwright/test";
import { connectWallet, TENANTS } from "./helpers";
import { platformCall, platformSignIn } from "./platform-api";

/**
 * The platform tier against the real two-tenant stack (specs/PLATFORM-ADMIN-SPECS.md §14.2):
 * a tenant suspended at runtime stops resolving through the real proxies and comes back on
 * resume, and a tenant created at runtime resolves with no container restarted. The API-level
 * matrix lives in the wallet-api vitest suite; this proves the same thing end to end.
 *
 * Platform admin calls go server-to-server to wallet-api's loopback port, the way the console's proxy
 * will, so they carry no Origin — platform admin routes refuse any request that does.
 */

const call = platformCall;
const signIn = platformSignIn;

test.describe("admin tenant administration", () => {
	let token: string;
	const asAdmin = (method: string, path: string, body?: unknown) =>
		call(method, path, { body, headers: { authorization: `Bearer ${token}` } });

	test.beforeAll(async () => {
		token = await signIn();
	});

	test("a suspended tenant stops resolving through its own wallet origin and returns on resume", async ({
		page,
	}) => {
		expect(
			(
				await asAdmin(
					"POST",
					`/v1/platform/tenants/${TENANTS.byo.slug}/suspend`,
					{ reason: "e2e" },
				)
			).status,
		).toBe(200);
		try {
			// the BYO wallet's /api proxy, with the Origin a real browser on that origin sends
			await page.goto(TENANTS.byo.walletUrl);
			const refused = await page.evaluate(async () => {
				const res = await fetch("/api/v1/webauthn/options", {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({ externalUserId: "suspended-probe" }),
				});
				return res.status;
			});
			expect(refused).toBe(403);
			expect(
				(
					await call("GET", "/.well-known/webauthn", {
						headers: { host: "wallet-byo.localhost" },
					})
				).status,
			).toBe(404);

			// the other tenant is untouched throughout
			await connectWallet(page, TENANTS.stock);
		} finally {
			expect(
				(
					await asAdmin(
						"POST",
						`/v1/platform/tenants/${TENANTS.byo.slug}/resume`,
					)
				).status,
			).toBe(200);
		}
		await connectWallet(page, TENANTS.byo);
	});

	test("a tenant created at runtime resolves with no container restarted", async () => {
		// a deleted slug is never reusable and this stack's database may outlive a run, so each run takes a fresh one
		const slug = `runtime-${Date.now()}`;
		const walletOrigin = `http://wallet-${slug}.localhost`;
		const created = await asAdmin("POST", "/v1/platform/tenants", {
			slug,
			walletOrigin,
			rpName: "Runtime E2E",
			openRegistration: true,
		});
		expect(created.status).toBe(201);
		expect(created.json().tenant).toMatchObject({ slug, status: "active" });

		const wellKnown = await call("GET", "/.well-known/webauthn", {
			headers: { host: `wallet-${slug}.localhost` },
		});
		expect(wellKnown.status).toBe(200);
		const options = await call("POST", "/v1/webauthn/options", {
			body: { externalUserId: "runtime-user" },
			headers: { origin: walletOrigin },
		});
		expect(options.status).toBe(200);

		// and it leaves no trace: suspend and delete (the stack's ledger is synced by its watcher)
		expect(
			(
				await asAdmin("POST", `/v1/platform/tenants/${slug}/suspend`, {
					reason: "e2e cleanup",
				})
			).status,
		).toBe(200);
		expect(
			(await asAdmin("DELETE", `/v1/platform/tenants/${slug}`)).status,
		).toBe(204);
	});
});
