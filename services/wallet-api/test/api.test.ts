import { gianoSmartWalletAbi } from "@appliedblockchain/giano-contracts";
import { and, eq, sql } from "drizzle-orm";
import { encodeFunctionData } from "viem";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { tenants, users } from "../src/db/schema.js";
import { createChallengeService } from "../src/services/challenges.js";
import {
	loadTenantFixtures,
	parseTenantFixtures,
} from "../src/services/tenant-fixtures.js";
import {
	ADMIN_KEY,
	startTestStack,
	stopTestStack,
	TENANT_A,
	TENANT_B,
	TEST_ORIGIN,
	TEST_RP_ID,
	type TestContext,
} from "./setup.js";
import {
	createAuthenticator,
	FLAG_UP,
	makeAuthenticationResponse,
	makeRegistrationResponse,
	type TestAuthenticator,
} from "./webauthn-fixtures.js";

let ctx: TestContext;

beforeAll(async () => {
	ctx = await startTestStack();
}, 120_000);

afterAll(async () => {
	if (ctx) await stopTestStack(ctx);
});

type Tenant = typeof TENANT_A;

/** Ceremony calls carry the tenant's Origin header — that is what resolves the tenant. */
const getOptions = async (
	externalUserId: string,
	kind?: string,
	tenant: Tenant = TENANT_A,
	adminKey?: string,
) => {
	const res = await ctx.app.inject({
		method: "POST",
		url: "/v1/webauthn/options",
		headers: {
			origin: tenant.walletOrigin,
			...(adminKey ? { authorization: `Bearer ${adminKey}` } : {}),
		},
		payload: { externalUserId, ...(kind ? { kind } : {}) },
	});
	expect(res.statusCode).toBe(200);
	return res.json() as {
		kind: string;
		challenge: string;
		credentialIds: string[];
		userExists: boolean;
	};
};

const register = async (
	externalUserId: string,
	auth: TestAuthenticator,
	tenant: Tenant = TENANT_A,
	adminKey?: string,
) => {
	const options = await getOptions(
		externalUserId,
		"registration",
		tenant,
		adminKey,
	);
	const res = await ctx.app.inject({
		method: "POST",
		url: "/v1/webauthn/registration/verify",
		headers: { origin: tenant.walletOrigin },
		payload: {
			externalUserId,
			response: makeRegistrationResponse(auth, {
				challenge: options.challenge,
				origin: tenant.walletOrigin,
				rpId: tenant.rpId,
			}),
		},
	});
	expect(res.statusCode).toBe(200);
	return res.json() as {
		verified: boolean;
		walletAddress: string;
		credentialId: string;
		session: { token: string };
	};
};

/** Marks every passkey of a tenant user as removed, as the registry does once the chain confirms it. */
const removeCredentials = async (
	externalUserId: string,
	tenant: Tenant = TENANT_A,
) => {
	await ctx.db.execute(sql`
		UPDATE credentials SET removed_at = now()
		 WHERE user_id = (SELECT u.id FROM users u JOIN tenants t ON t.id = u.tenant_id
		                   WHERE t.slug = ${tenant.slug} AND u.external_id = ${externalUserId})`);
};

describe("health", () => {
	it("healthz and readyz are green", async () => {
		expect(
			(await ctx.app.inject({ method: "GET", url: "/healthz" })).statusCode,
		).toBe(200);
		const ready = await ctx.app.inject({ method: "GET", url: "/readyz" });
		expect(ready.statusCode).toBe(200);
		// `sponsorship: 'disabled'` is deliberate rather than absent: a deployment that does not
		// sponsor should say so, because silence would be indistinguishable from a broken signer.
		expect(ready.json()).toEqual({ status: "ready", sponsorship: "disabled" });
	});
});

describe("admin + well-known", () => {
	it("rejects ROR admin calls without the admin key", async () => {
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/admin/ror-origins",
			payload: { origin: "https://dapp.example.com" },
		});
		expect(res.statusCode).toBe(401);
	});

	it("manages ROR origins and serves them on /.well-known/webauthn by Host", async () => {
		const created = await ctx.app.inject({
			method: "POST",
			url: "/v1/admin/ror-origins",
			headers: { authorization: `Bearer ${ADMIN_KEY}` },
			payload: { origin: "https://dapp.example.com" },
		});
		expect(created.statusCode).toBe(201);

		// resolved by Host header → tenant A (rp_id 'localhost')
		const wellKnown = await ctx.app.inject({
			method: "GET",
			url: "/.well-known/webauthn",
			headers: { host: "localhost:4000" },
		});
		expect(wellKnown.statusCode).toBe(200);
		expect(wellKnown.json()).toEqual({ origins: ["https://dapp.example.com"] });

		const deleted = await ctx.app.inject({
			method: "DELETE",
			url: `/v1/admin/ror-origins/${(created.json() as { id: string }).id}`,
			headers: { authorization: `Bearer ${ADMIN_KEY}` },
		});
		expect(deleted.statusCode).toBe(204);
	});

	it("serves 404 for a Host that is no tenant rp_id", async () => {
		const res = await ctx.app.inject({
			method: "GET",
			url: "/.well-known/webauthn",
			headers: { host: "unknown.example.com" },
		});
		expect(res.statusCode).toBe(404);
	});
});

describe("registration ceremony", () => {
	it("registers a passkey, computes the wallet address and issues a session", async () => {
		const body = await register("user-1", createAuthenticator());
		expect(body.verified).toBe(true);
		expect(body.walletAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
		expect(body.session.token).toBeTruthy();

		// session gates /v1/me
		const me = await ctx.app.inject({
			method: "GET",
			url: "/v1/me",
			headers: { authorization: `Bearer ${body.session.token}` },
		});
		expect(me.statusCode).toBe(200);
		expect((me.json() as { externalUserId: string }).externalUserId).toBe(
			"user-1",
		);
	});

	it("rejects ceremony calls without a resolvable tenant Origin", async () => {
		const noOrigin = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/options",
			payload: { externalUserId: "x" },
		});
		expect(noOrigin.statusCode).toBe(403);
		expect((noOrigin.json() as { error: string }).error).toBe("unknown-tenant");

		const unknownOrigin = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/options",
			headers: { origin: "https://not-a-tenant.example.com" },
			payload: { externalUserId: "x" },
		});
		expect(unknownOrigin.statusCode).toBe(403);
	});

	it("rejects challenge replay", async () => {
		const auth = createAuthenticator();
		const options = await getOptions("user-replay", "registration");
		const payload = {
			externalUserId: "user-replay",
			response: makeRegistrationResponse(auth, {
				challenge: options.challenge,
				origin: TEST_ORIGIN,
				rpId: TEST_RP_ID,
			}),
		};
		const headers = { origin: TEST_ORIGIN };
		expect(
			(
				await ctx.app.inject({
					method: "POST",
					url: "/v1/webauthn/registration/verify",
					headers,
					payload,
				})
			).statusCode,
		).toBe(200);

		// same challenge again — different credential, same clientData challenge
		const replayed = {
			externalUserId: "user-replay-2",
			response: makeRegistrationResponse(createAuthenticator(), {
				challenge: options.challenge,
				origin: TEST_ORIGIN,
				rpId: TEST_RP_ID,
			}),
		};
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers,
			payload: replayed,
		});
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe("bad-challenge");
	});

	it("rejects expired challenges", async () => {
		const options = await getOptions("user-expired", "registration");
		await ctx.db.execute(
			sql`UPDATE challenges SET expires_at = now() - interval '1 minute' WHERE challenge = ${options.challenge}`,
		);
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers: { origin: TEST_ORIGIN },
			payload: {
				externalUserId: "user-expired",
				response: makeRegistrationResponse(createAuthenticator(), {
					challenge: options.challenge,
					origin: TEST_ORIGIN,
					rpId: TEST_RP_ID,
				}),
			},
		});
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe("bad-challenge");
	});

	it("rejects a response from the wrong origin", async () => {
		const options = await getOptions("user-origin", "registration");
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers: { origin: TEST_ORIGIN },
			payload: {
				externalUserId: "user-origin",
				response: makeRegistrationResponse(createAuthenticator(), {
					challenge: options.challenge,
					origin: "https://evil.test",
					rpId: TEST_RP_ID,
				}),
			},
		});
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe("verification-failed");
	});

	it("rejects a response bound to the wrong RP ID", async () => {
		const options = await getOptions("user-rpid", "registration");
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers: { origin: TEST_ORIGIN },
			payload: {
				externalUserId: "user-rpid",
				response: makeRegistrationResponse(createAuthenticator(), {
					challenge: options.challenge,
					origin: TEST_ORIGIN,
					rpId: "evil.test",
				}),
			},
		});
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe("verification-failed");
	});

	it("rejects a response without user verification (UP only)", async () => {
		const options = await getOptions("user-no-uv", "registration");
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers: { origin: TEST_ORIGIN },
			payload: {
				externalUserId: "user-no-uv",
				response: makeRegistrationResponse(createAuthenticator(), {
					challenge: options.challenge,
					origin: TEST_ORIGIN,
					rpId: TEST_RP_ID,
					flags: FLAG_UP,
				}),
			},
		});
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe("verification-failed");
		// Nothing was registered: the user still has no credential.
		expect((await getOptions("user-no-uv")).credentialIds).toEqual([]);
	});

	it("rejects a challenge bound to a different user (challenge-user-mismatch)", async () => {
		// 'mismatch-user' exists with no active passkey on closed tenant B, so a registration
		// challenge for them is user-bound
		await register(
			"mismatch-user",
			createAuthenticator(),
			TENANT_B,
			TENANT_B.adminKey,
		);
		await removeCredentials("mismatch-user", TENANT_B);
		const options = await getOptions(
			"mismatch-user",
			"registration",
			TENANT_B,
			TENANT_B.adminKey,
		);
		expect(options.userExists).toBe(true);
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers: { origin: TENANT_B.walletOrigin },
			payload: {
				externalUserId: "someone-else-entirely",
				response: makeRegistrationResponse(createAuthenticator(), {
					challenge: options.challenge,
					origin: TENANT_B.walletOrigin,
					rpId: TENANT_B.rpId,
				}),
			},
		});
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe(
			"challenge-user-mismatch",
		);
	});

	it("rejects a challenge issued for a new id when the body names an existing user", async () => {
		const victim = await register("victim-unbound", createAuthenticator());
		// 'attacker-fresh-id' does not exist, so this challenge has no bound user
		const options = await getOptions("attacker-fresh-id", "registration");
		expect(options.userExists).toBe(false);
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers: { origin: TEST_ORIGIN },
			payload: {
				externalUserId: "victim-unbound",
				response: makeRegistrationResponse(createAuthenticator(), {
					challenge: options.challenge,
					origin: TEST_ORIGIN,
					rpId: TEST_RP_ID,
				}),
			},
		});
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe(
			"challenge-user-mismatch",
		);
		// The victim still has only their own credential, and no user was created for the fresh id.
		expect((await getOptions("victim-unbound")).credentialIds).toEqual([
			victim.credentialId,
		]);
		expect((await getOptions("attacker-fresh-id")).userExists).toBe(false);
	});

	it("refuses a challenge issued for a new id once that user has registered", async () => {
		// Two challenges issued while 'race-user' did not exist: both are unbound.
		const first = await getOptions("race-user", "registration");
		const second = await getOptions("race-user", "registration");
		const verify = (challenge: string) =>
			ctx.app.inject({
				method: "POST",
				url: "/v1/webauthn/registration/verify",
				headers: { origin: TEST_ORIGIN },
				payload: {
					externalUserId: "race-user",
					response: makeRegistrationResponse(createAuthenticator(), {
						challenge,
						origin: TEST_ORIGIN,
						rpId: TEST_RP_ID,
					}),
				},
			});
		const created = await verify(first.challenge);
		expect(created.statusCode).toBe(200);
		const res = await verify(second.challenge);
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe(
			"challenge-user-mismatch",
		);
		expect((await getOptions("race-user")).credentialIds).toEqual([
			(created.json() as { credentialId: string }).credentialId,
		]);
	});

	it("refuses registration options for a user who already holds an active passkey", async () => {
		const victim = await register("victim-bound", createAuthenticator());
		// Tenant A has open registration: this call carries no credential of any kind.
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/options",
			headers: { origin: TEST_ORIGIN },
			payload: { externalUserId: "victim-bound", kind: "registration" },
		});
		expect(res.statusCode).toBe(409);
		expect((res.json() as { error: string }).error).toBe("already-registered");
		// 'auto' still resolves to sign-in for that user.
		const auto = await getOptions("victim-bound");
		expect(auto.kind).toBe("authentication");
		expect(auto.credentialIds).toEqual([victim.credentialId]);
	});

	it("on a closed tenant, refuses to add a passkey to a user who holds an active one, and lets a user with none register", async () => {
		const options = () =>
			getOptions(
				"re-register-user",
				"registration",
				TENANT_B,
				TENANT_B.adminKey,
			);
		await register(
			"re-register-user",
			createAuthenticator(),
			TENANT_B,
			TENANT_B.adminKey,
		);
		await removeCredentials("re-register-user", TENANT_B);
		// Both challenges are bound to the user, issued while they had no active passkey.
		const first = await options();
		const second = await options();
		const verify = (challenge: string) =>
			ctx.app.inject({
				method: "POST",
				url: "/v1/webauthn/registration/verify",
				headers: { origin: TENANT_B.walletOrigin },
				payload: {
					externalUserId: "re-register-user",
					response: makeRegistrationResponse(createAuthenticator(), {
						challenge,
						origin: TENANT_B.walletOrigin,
						rpId: TENANT_B.rpId,
					}),
				},
			});
		const created = await verify(first.challenge);
		expect(created.statusCode).toBe(200);
		const res = await verify(second.challenge);
		expect(res.statusCode).toBe(409);
		expect((res.json() as { error: string }).error).toBe("already-registered");
		expect(
			(
				await getOptions(
					"re-register-user",
					undefined,
					TENANT_B,
					TENANT_B.adminKey,
				)
			).credentialIds,
		).toEqual([(created.json() as { credentialId: string }).credentialId]);
	});

	it("registers only one of two concurrent registrations for the same user", async () => {
		const options = (kind?: string) =>
			getOptions("concurrent-user", kind, TENANT_B, TENANT_B.adminKey);
		await register(
			"concurrent-user",
			createAuthenticator(),
			TENANT_B,
			TENANT_B.adminKey,
		);
		await removeCredentials("concurrent-user", TENANT_B);
		const challenges = await Promise.all([
			options("registration"),
			options("registration"),
		]);
		const results = await Promise.all(
			challenges.map(({ challenge }) =>
				ctx.app.inject({
					method: "POST",
					url: "/v1/webauthn/registration/verify",
					headers: { origin: TENANT_B.walletOrigin },
					payload: {
						externalUserId: "concurrent-user",
						response: makeRegistrationResponse(createAuthenticator(), {
							challenge,
							origin: TENANT_B.walletOrigin,
							rpId: TENANT_B.rpId,
						}),
					},
				}),
			),
		);
		expect(results.map((r) => r.statusCode).sort()).toEqual([200, 409]);
		expect((await options()).credentialIds).toHaveLength(1);
	});

	it("on an open tenant, refuses registration for a user whose passkeys were all removed", async () => {
		await register("removed-open-user", createAuthenticator());
		await removeCredentials("removed-open-user");
		// Tenant A has open registration: neither an explicit request nor 'auto' gets a challenge.
		for (const kind of ["registration", "auto"]) {
			const res = await ctx.app.inject({
				method: "POST",
				url: "/v1/webauthn/options",
				headers: { origin: TEST_ORIGIN },
				payload: { externalUserId: "removed-open-user", kind },
			});
			expect(res.statusCode).toBe(409);
			expect((res.json() as { error: string }).error).toBe(
				"already-registered",
			);
		}
		// registration/verify refuses too, even with a challenge bound to the user that /options
		// would not issue (for example, one issued before the tenant opened registration).
		const tenantA = await ctx.db.query.tenants.findFirst({
			where: eq(tenants.slug, TENANT_A.slug),
		});
		if (!tenantA) throw new Error("tenant A is missing");
		const user = await ctx.db.query.users.findFirst({
			where: and(
				eq(users.tenantId, tenantA.id),
				eq(users.externalId, "removed-open-user"),
			),
		});
		if (!user) throw new Error("removed-open-user was not registered");
		const challenge = await createChallengeService(ctx.db, 300).issue(
			"registration",
			user.id,
			user.tenantId,
			"removed-open-user",
		);
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers: { origin: TEST_ORIGIN },
			payload: {
				externalUserId: "removed-open-user",
				response: makeRegistrationResponse(createAuthenticator(), {
					challenge,
					origin: TEST_ORIGIN,
					rpId: TEST_RP_ID,
				}),
			},
		});
		expect(res.statusCode).toBe(409);
		expect((res.json() as { error: string }).error).toBe("already-registered");
		const active = await ctx.db.execute(sql`
			SELECT 1 FROM credentials WHERE user_id = ${user.id} AND removed_at IS NULL`);
		expect(active.rows).toHaveLength(0);
	});

	it("requires the tenant's own admin key for options when open_registration is false", async () => {
		// tenant B runs with closed registration on the shared stack — no second app needed
		const anonymous = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/options",
			headers: { origin: TENANT_B.walletOrigin },
			payload: { externalUserId: "x" },
		});
		expect(anonymous.statusCode).toBe(401);

		const admin = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/options",
			headers: {
				origin: TENANT_B.walletOrigin,
				authorization: `Bearer ${TENANT_B.adminKey}`,
			},
			payload: { externalUserId: "x" },
		});
		expect(admin.statusCode).toBe(200);
	});
});

describe("authentication ceremony", () => {
	it("signs in with an existing passkey and issues a fresh session", async () => {
		const auth = createAuthenticator();
		const registered = await register("user-auth", auth);

		const options = await getOptions("user-auth");
		expect(options.kind).toBe("authentication");
		expect(options.credentialIds).toContain(
			auth.credentialId.toString("base64url"),
		);

		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/authentication/verify",
			headers: { origin: TEST_ORIGIN },
			payload: {
				response: makeAuthenticationResponse(auth, {
					challenge: options.challenge,
					origin: TEST_ORIGIN,
					rpId: TEST_RP_ID,
				}),
			},
		});
		expect(res.statusCode).toBe(200);
		const body = res.json() as {
			externalUserId: string;
			walletAddress: string;
			session: { token: string };
		};
		expect(body.externalUserId).toBe("user-auth");
		expect(body.walletAddress).toBe(registered.walletAddress);

		const logout = await ctx.app.inject({
			method: "POST",
			url: "/v1/sessions/logout",
			headers: { authorization: `Bearer ${body.session.token}` },
		});
		expect(logout.statusCode).toBe(200);
		const afterLogout = await ctx.app.inject({
			method: "GET",
			url: "/v1/me",
			headers: { authorization: `Bearer ${body.session.token}` },
		});
		expect(afterLogout.statusCode).toBe(401);
	});

	it("rejects an assertion without user verification (UP only) and issues no session", async () => {
		const auth = createAuthenticator();
		await register("user-auth-no-uv", auth);
		const options = await getOptions("user-auth-no-uv");

		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/authentication/verify",
			headers: { origin: TEST_ORIGIN },
			payload: {
				response: makeAuthenticationResponse(auth, {
					challenge: options.challenge,
					origin: TEST_ORIGIN,
					rpId: TEST_RP_ID,
					flags: FLAG_UP,
				}),
			},
		});
		expect(res.statusCode).toBe(400);
		const body = res.json() as { error: string; session?: unknown };
		expect(body.error).toBe("verification-failed");
		expect(body.session).toBeUndefined();
	});

	it("rejects an assertion whose challenge was never issued", async () => {
		const auth = createAuthenticator();
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/authentication/verify",
			headers: { origin: TEST_ORIGIN },
			payload: {
				response: makeAuthenticationResponse(auth, {
					challenge: "bm90LWEtcmVhbC1jaGFsbGVuZ2U",
					origin: TEST_ORIGIN,
					rpId: TEST_RP_ID,
				}),
			},
		});
		expect(res.statusCode).toBe(400);
	});
});

describe("userop relay", () => {
	let sessionToken: string;
	let walletAddress: string;
	const target = "0x3333333333333333333333333333333333333333";

	const makeOp = (nonce: number, overrides: Record<string, string> = {}) => ({
		sender: walletAddress,
		nonce: `0x${nonce.toString(16)}`,
		callData: encodeFunctionData({
			abi: gianoSmartWalletAbi,
			functionName: "execute",
			args: [target, 0n, "0x"],
		}),
		callGasLimit: "0x30000",
		verificationGasLimit: "0x30000",
		preVerificationGas: "0x10000",
		maxFeePerGas: "0x3b9aca00",
		maxPriorityFeePerGas: "0x3b9aca00",
		signature: "0x1234",
		...overrides,
	});

	beforeAll(async () => {
		const registered = await register("userop-user", createAuthenticator());
		sessionToken = registered.session.token;
		walletAddress = registered.walletAddress;
	});

	it("requires a session", async () => {
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			payload: { userOperation: makeOp(1) },
		});
		expect(res.statusCode).toBe(401);
	});

	it("relays a compliant op to the bundler with the SERVER EntryPoint", async () => {
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { userOperation: makeOp(1) },
		});
		expect(res.statusCode).toBe(200);
		const { userOperationHash } = res.json() as { userOperationHash: string };
		expect(userOperationHash).toMatch(/^0x[0-9a-f]{64}$/);

		const send = ctx.bundlerCalls.find(
			(c) => c.method === "eth_sendUserOperation",
		);
		expect(send).toBeTruthy();
		// EntryPoint param comes from server config, never the request
		expect(send!.params[1]).toBe("0x433709009B8330FDa32311DF1C2AFA402eD8D009");

		// status endpoint sees it under the server-computed hash
		const opRow = await ctx.app.inject({
			method: "GET",
			url: `/v1/userops/${userOperationHash}`,
			headers: { authorization: `Bearer ${sessionToken}` },
		});
		expect(opRow.statusCode).toBe(200);
		expect((opRow.json() as { status: string }).status).toBe("submitted");
	});

	it("is idempotent for duplicate submissions", async () => {
		const op = makeOp(2);
		const first = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { userOperation: op },
		});
		expect(first.statusCode).toBe(200);
		const second = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { userOperation: op },
		});
		expect(second.statusCode).toBe(200);
		expect((second.json() as { duplicate?: boolean }).duplicate).toBe(true);
	});

	it("rejects sender mismatch with a per-rule audit trail", async () => {
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: {
				userOperation: makeOp(3, {
					sender: "0x9999999999999999999999999999999999999999",
				}),
			},
		});
		expect(res.statusCode).toBe(403);
		const body = res.json() as {
			error: string;
			policy: { rule: string; passed: boolean }[];
		};
		expect(body.error).toBe("policy-rejected");
		expect(body.policy.find((r) => r.rule === "sender-binding")!.passed).toBe(
			false,
		);
		expect(body.policy.length).toBeGreaterThan(1);
	});

	it("rejects over-cap gas", async () => {
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { userOperation: makeOp(4, { callGasLimit: "0x4c4b4000" }) }, // 1.28B gas
		});
		expect(res.statusCode).toBe(403);
		expect((res.json() as { message: string }).message).toContain(
			"call-gas-cap",
		);
	});

	it("never accepts an entryPoint from the request body", async () => {
		const op = {
			...makeOp(5),
			account: {
				entryPoint: { address: "0x9999999999999999999999999999999999999999" },
			},
		};
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { userOperation: op },
		});
		expect(res.statusCode).toBe(200);
		const send = ctx.bundlerCalls
			.filter((c) => c.method === "eth_sendUserOperation")
			.at(-1)!;
		expect(send.params[1]).toBe("0x433709009B8330FDa32311DF1C2AFA402eD8D009");
	});

	it("serves receipts publicly (read-only)", async () => {
		const res = await ctx.app.inject({
			method: "GET",
			url: `/v1/userops/0x${"ab".repeat(32)}/receipt`,
		});
		expect(res.statusCode).toBe(200);
		expect(res.json()).toHaveProperty("receipt");
	});
});

/**
 * The JSON-RPC bundler facade (POST /v1/bundler/:chainId): what a wallet origin points its
 * bundler client at instead of a bundler. Same pipeline as the REST relay behind a second
 * door, so every assertion here is about the two doors being the same door.
 */
describe("bundler relay (JSON-RPC)", () => {
	const ENTRY_POINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
	const target = "0x4444444444444444444444444444444444444444";
	let sessionToken: string;
	let walletAddress: string;

	const makeOp = (nonce: number, overrides: Record<string, string> = {}) => ({
		sender: walletAddress,
		nonce: `0x${nonce.toString(16)}`,
		callData: encodeFunctionData({
			abi: gianoSmartWalletAbi,
			functionName: "execute",
			args: [target, 0n, "0x"],
		}),
		callGasLimit: "0x30000",
		verificationGasLimit: "0x30000",
		preVerificationGas: "0x10000",
		maxFeePerGas: "0x3b9aca00",
		maxPriorityFeePerGas: "0x3b9aca00",
		signature: "0x1234",
		...overrides,
	});

	type RpcResult = {
		jsonrpc: "2.0";
		id: number;
		result?: unknown;
		error?: { code: number; message: string; data?: Record<string, unknown> };
	};
	const rpc = async (
		method: string,
		params: unknown[] = [],
		url = "/v1/bundler/31337",
		token = sessionToken,
	) => {
		const res = await ctx.app.inject({
			method: "POST",
			url,
			headers: token ? { authorization: `Bearer ${token}` } : {},
			payload: { jsonrpc: "2.0", id: 7, method, params },
		});
		return { status: res.statusCode, body: res.json() as RpcResult };
	};

	beforeAll(async () => {
		const registered = await register(
			"bundler-relay-user",
			createAuthenticator(),
		);
		sessionToken = registered.session.token;
		walletAddress = registered.walletAddress;
	});

	it("requires a session", async () => {
		const { status } = await rpc("eth_chainId", [], "/v1/bundler/31337", "");
		expect(status).toBe(401);
	});

	it("answers eth_chainId and eth_supportedEntryPoints from configuration, without a bundler round trip", async () => {
		const before = ctx.bundlerCalls.length;
		expect((await rpc("eth_chainId")).body).toEqual({
			jsonrpc: "2.0",
			id: 7,
			result: "0x7a69",
		});
		expect((await rpc("eth_supportedEntryPoints")).body.result).toEqual([
			ENTRY_POINT,
		]);
		expect(ctx.bundlerCalls.length).toBe(before);
	});

	it("resolves the sole chain when the path names none (MC-53), and refuses an unserved one", async () => {
		expect((await rpc("eth_chainId", [], "/v1/bundler")).body.result).toBe(
			"0x7a69",
		);
		const { status, body } = await rpc("eth_chainId", [], "/v1/bundler/999");
		expect(status).toBe(400);
		expect(body).toMatchObject({ error: "unsupported-chain" });
	});

	it("forwards eth_estimateUserOperationGas for the session wallet, against the SERVER EntryPoint", async () => {
		const { status, body } = await rpc("eth_estimateUserOperationGas", [
			{ sender: walletAddress, nonce: "0x1", callData: "0x" },
			ENTRY_POINT,
		]);
		expect(status).toBe(200);
		expect(body.result).toMatchObject({ callGasLimit: "0x30000" });
		const estimate = ctx.bundlerCalls
			.filter((c) => c.method === "eth_estimateUserOperationGas")
			.at(-1)!;
		expect(estimate.params[1]).toBe(ENTRY_POINT);
		expect((estimate.params[0] as { sender: string }).sender).toBe(
			walletAddress,
		);
	});

	it("refuses to estimate for a wallet the session does not own", async () => {
		const before = ctx.bundlerCalls.length;
		const { body } = await rpc("eth_estimateUserOperationGas", [
			{
				sender: "0x9999999999999999999999999999999999999999",
				nonce: "0x1",
				callData: "0x",
			},
			ENTRY_POINT,
		]);
		expect(body.error).toMatchObject({
			code: -32020,
			data: { reason: "sender-binding" },
		});
		expect(ctx.bundlerCalls.length).toBe(before);
	});

	it("refuses a foreign EntryPoint and a state override", async () => {
		const foreign = await rpc("eth_estimateUserOperationGas", [
			{ sender: walletAddress, nonce: "0x1", callData: "0x" },
			"0x9999999999999999999999999999999999999999",
		]);
		expect(foreign.body.error?.code).toBe(-32010);
		const withOverride = await rpc("eth_estimateUserOperationGas", [
			{ sender: walletAddress, nonce: "0x1", callData: "0x" },
			ENTRY_POINT,
			{ [target]: { balance: "0x1" } },
		]);
		expect(withOverride.body.error?.code).toBe(-32602);
	});

	it("eth_sendUserOperation goes through the relay pipeline: server hash, audit row, bundler submission", async () => {
		const { status, body } = await rpc("eth_sendUserOperation", [
			makeOp(1),
			ENTRY_POINT,
		]);
		expect(status).toBe(200);
		expect(body.result).toMatch(/^0x[0-9a-f]{64}$/);

		const send = ctx.bundlerCalls
			.filter((c) => c.method === "eth_sendUserOperation")
			.at(-1)!;
		expect(send.params[1]).toBe(ENTRY_POINT);

		// the same audit trail the REST door writes, under the same server-computed hash
		const row = await ctx.app.inject({
			method: "GET",
			url: `/v1/userops/${body.result}`,
			headers: { authorization: `Bearer ${sessionToken}` },
		});
		expect(row.statusCode).toBe(200);
		expect((row.json() as { status: string }).status).toBe("submitted");
	});

	it("is idempotent across both doors: the REST relay sees the JSON-RPC submission as its own duplicate", async () => {
		const op = makeOp(2);
		const first = await rpc("eth_sendUserOperation", [op, ENTRY_POINT]);
		const again = await rpc("eth_sendUserOperation", [op, ENTRY_POINT]);
		expect(again.body.result).toBe(first.body.result);

		const rest = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${sessionToken}` },
			payload: { userOperation: op },
		});
		expect(rest.statusCode).toBe(200);
		expect(rest.json()).toEqual({
			userOperationHash: first.body.result,
			duplicate: true,
		});
	});

	it("applies the same policy as the REST relay, with the rule results in error.data", async () => {
		const { body } = await rpc("eth_sendUserOperation", [
			makeOp(3, { sender: "0x9999999999999999999999999999999999999999" }),
			ENTRY_POINT,
		]);
		expect(body.error?.code).toBe(-32020);
		expect(body.error?.message).toContain("sender-binding");
		const policy = body.error?.data?.policy as {
			rule: string;
			passed: boolean;
		}[];
		expect(policy.find((r) => r.rule === "sender-binding")!.passed).toBe(false);

		const overCap = await rpc("eth_sendUserOperation", [
			makeOp(4, { callGasLimit: "0x4c4b4000" }),
			ENTRY_POINT,
		]);
		expect(overCap.body.error?.message).toContain("call-gas-cap");
	});

	it("never submits against an EntryPoint named by the request", async () => {
		const before = ctx.bundlerCalls.filter(
			(c) => c.method === "eth_sendUserOperation",
		).length;
		const { body } = await rpc("eth_sendUserOperation", [
			makeOp(5),
			"0x9999999999999999999999999999999999999999",
		]);
		expect(body.error?.code).toBe(-32010);
		expect(
			ctx.bundlerCalls.filter((c) => c.method === "eth_sendUserOperation")
				.length,
		).toBe(before);
	});

	it("forwards receipt and by-hash lookups, and validates their parameters", async () => {
		const hash = `0x${"cd".repeat(32)}`;
		expect((await rpc("eth_getUserOperationReceipt", [hash])).body).toEqual({
			jsonrpc: "2.0",
			id: 7,
			result: null,
		});
		expect(ctx.bundlerCalls.at(-1)).toMatchObject({
			method: "eth_getUserOperationReceipt",
			params: [hash],
		});
		expect(
			(await rpc("eth_getUserOperationByHash", [hash])).body.result,
		).toBeNull();
		expect(
			(await rpc("eth_getUserOperationReceipt", ["not-a-hash"])).body.error
				?.code,
		).toBe(-32602);
	});

	it("relays nothing it was not built for", async () => {
		const { body } = await rpc("eth_sendRawTransaction", ["0x00"]);
		expect(body.error?.code).toBe(-32601);
		expect(
			(await rpc("pimlico_getUserOperationGasPrice")).body.error?.code,
		).toBe(-32601);
	});
});

/**
 * The chain RPC read relay (POST /v1/rpc/:chainId): tenant-bound by Origin, read-only by
 * allowlist, so a wallet origin needs no node URL and a keyed provider URL stays server-side.
 */
describe("rpc relay (JSON-RPC reads)", () => {
	type RpcResult = {
		jsonrpc: "2.0";
		id: number;
		result?: unknown;
		error?: { code: number; message: string };
	};
	// `null` = send no Origin at all (an explicit `undefined` would just select the default).
	const rpc = async (
		method: string,
		params: unknown[] = [],
		url = "/v1/rpc/31337",
		origin: string | null = TENANT_A.walletOrigin,
	) => {
		const res = await ctx.app.inject({
			method: "POST",
			url,
			headers: origin ? { origin } : {},
			payload: { jsonrpc: "2.0", id: 3, method, params },
		});
		return { status: res.statusCode, body: res.json() as RpcResult };
	};

	it("requires a registered tenant Origin — no session needed, reads happen before sign-in", async () => {
		expect((await rpc("eth_chainId", [], "/v1/rpc/31337", null)).status).toBe(
			403,
		);
		expect(
			(await rpc("eth_chainId", [], "/v1/rpc/31337", "http://evil.example"))
				.status,
		).toBe(403);
		expect((await rpc("eth_chainId")).body).toEqual({
			jsonrpc: "2.0",
			id: 3,
			result: "0x7a69",
		});
	});

	it("forwards read methods to the chain node verbatim", async () => {
		const call = await rpc("eth_call", [
			{ to: "0x2222222222222222222222222222222222222222", data: "0x1234" },
			"latest",
		]);
		expect(call.status).toBe(200);
		expect(call.body.result).toMatch(/^0x[0-9a-f]{64}$/); // the mock node's abi-encoded address answer
		expect(
			(
				await rpc("eth_getCode", [
					"0x2222222222222222222222222222222222222222",
					"latest",
				])
			).body.result,
		).toBe("0x");
	});

	it("refuses anything outside the read allowlist", async () => {
		for (const method of [
			"eth_sendRawTransaction",
			"eth_sendTransaction",
			"debug_traceCall",
			"anvil_setBalance",
			"eth_sendUserOperation",
		]) {
			expect((await rpc(method, [])).body.error?.code).toBe(-32601);
		}
	});

	it("bounds eth_getLogs to RPC_RELAY_MAX_LOG_BLOCKS", async () => {
		const logs = (filter: Record<string, unknown>) =>
			rpc("eth_getLogs", [
				{ address: "0x2222222222222222222222222222222222222222", ...filter },
			]);
		for (const filter of [
			{ fromBlock: "0x0", toBlock: `0x${(9_999).toString(16)}` }, // exactly the limit
			{ blockHash: `0x${"ab".repeat(32)}` },
		]) {
			const { body } = await logs(filter);
			expect(body.error, JSON.stringify(filter)).toBeUndefined();
		}
		for (const filter of [
			{ fromBlock: "earliest", toBlock: "latest" },
			{ fromBlock: "0x0" },
			{ fromBlock: "0x0", toBlock: `0x${(10_000).toString(16)}` },
		]) {
			const { body } = await logs(filter);
			expect(body.error, JSON.stringify(filter)).toMatchObject({
				code: -32602,
			});
			expect(body.error?.message).toContain("10000 blocks");
		}
	});

	it("resolves the sole chain when the path names none, and refuses an unserved one", async () => {
		expect((await rpc("eth_chainId", [], "/v1/rpc")).body.result).toBe(
			"0x7a69",
		);
		const { status, body } = await rpc("eth_chainId", [], "/v1/rpc/999");
		expect(status).toBe(400);
		expect(body).toMatchObject({ error: "unsupported-chain" });
	});
});

/**
 * The tenant-isolation negative matrix. Each case pins one way isolation could leak
 * (specs/DEVELOPER-GUIDE.md §1); none of them may pass without the fix it exists for.
 */
describe("tenant isolation", () => {
	const scrapeMetrics = async () => {
		const res = await ctx.app.inject({ method: "GET", url: "/metrics" });
		expect(res.statusCode).toBe(200);
		return res.body;
	};

	it("V1: the same externalUserId on two tenants yields two users and two wallets", async () => {
		const onA = await register(
			"shared-user-1",
			createAuthenticator(),
			TENANT_A,
		);
		const onB = await register(
			"shared-user-1",
			createAuthenticator(),
			TENANT_B,
			TENANT_B.adminKey,
		);

		const rows = (
			await ctx.db.execute(
				sql`SELECT count(*)::int AS count FROM users WHERE external_id = 'shared-user-1'`,
			)
		).rows as [{ count: number }];
		expect(rows[0].count).toBe(2); // pre-fix: onConflictDoUpdate silently merged them into one
		expect(onB.walletAddress).not.toBe(onA.walletAddress);
		expect(onB.credentialId).not.toBe(onA.credentialId);
	});

	it("V2: tenant A's credential replayed on tenant B is rejected by OUR tenant check (not rpIdHash)", async () => {
		const auth = createAuthenticator();
		await register("v2-victim", auth, TENANT_A);

		// build an assertion that would pass B's WebAuthn checks (B's origin and RP ID),
		// so the only thing standing is the server-side tenant scoping
		const options = await getOptions(
			"v2-attacker",
			"authentication",
			TENANT_B,
			TENANT_B.adminKey,
		);
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/authentication/verify",
			headers: { origin: TENANT_B.walletOrigin },
			payload: {
				response: makeAuthenticationResponse(auth, {
					challenge: options.challenge,
					origin: TENANT_B.walletOrigin,
					rpId: TENANT_B.rpId,
				}),
			},
		});
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe("unknown-credential");

		// the alertable counter proves the rejection came from the tenant guard
		const metrics = await scrapeMetrics();
		expect(metrics).toMatch(
			/giano_cross_tenant_rejections_total\{(?=[^}]*kind="credential")(?=[^}]*tenant="beta")[^}]*\} [1-9]/,
		);
	});

	it("V2b: another tenant holding the same credential id cannot block a legitimate sign-in", async () => {
		// credential ids are unique per tenant only, and the client chooses them under "none"
		// attestation. The attacker registers first, so a global lookup by id would find the
		// attacker's row before the victim's and refuse the victim's sign-in.
		const victim = createAuthenticator();
		const attacker = {
			...createAuthenticator(),
			credentialId: Buffer.from(victim.credentialId),
		};
		await register("v2b-attacker", attacker, TENANT_B, TENANT_B.adminKey);
		const registered = await register("v2b-victim", victim, TENANT_A);

		const options = await getOptions("v2b-victim", "authentication", TENANT_A);
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/authentication/verify",
			headers: { origin: TENANT_A.walletOrigin },
			payload: {
				response: makeAuthenticationResponse(victim, {
					challenge: options.challenge,
					origin: TENANT_A.walletOrigin,
					rpId: TENANT_A.rpId,
				}),
			},
		});
		expect(res.statusCode).toBe(200);
		const body = res.json() as {
			externalUserId: string;
			walletAddress: string;
		};
		expect(body.externalUserId).toBe("v2b-victim");
		expect(body.walletAddress).toBe(registered.walletAddress);
	});

	it("V3: a challenge issued on tenant A cannot be consumed on tenant B", async () => {
		const options = await getOptions("v3-user", "registration", TENANT_A);
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/registration/verify",
			headers: { origin: TENANT_B.walletOrigin },
			payload: {
				externalUserId: "v3-user",
				response: makeRegistrationResponse(createAuthenticator(), {
					challenge: options.challenge,
					origin: TENANT_B.walletOrigin,
					rpId: TENANT_B.rpId,
				}),
			},
		});
		expect(res.statusCode).toBe(400);
		expect((res.json() as { error: string }).error).toBe("bad-challenge");

		const metrics = await scrapeMetrics();
		expect(metrics).toMatch(
			/giano_cross_tenant_rejections_total\{(?=[^}]*kind="challenge")(?=[^}]*tenant="beta")[^}]*\} [1-9]/,
		);
	});

	it("V4: tenant A's admin key does not authorize tenant B's options, and discloses nothing", async () => {
		const res = await ctx.app.inject({
			method: "POST",
			url: "/v1/webauthn/options",
			headers: {
				origin: TENANT_B.walletOrigin,
				authorization: `Bearer ${TENANT_A.adminKey}`,
			},
			payload: { externalUserId: "shared-user-1" },
		});
		expect(res.statusCode).toBe(401);
		expect(res.body).not.toContain("credentialIds");
	});

	it("V5: tenant A's session token is rejected when presented from tenant B's origin", async () => {
		const registered = await register(
			"v5-user",
			createAuthenticator(),
			TENANT_A,
		);

		const meOnB = await ctx.app.inject({
			method: "GET",
			url: "/v1/me",
			headers: {
				authorization: `Bearer ${registered.session.token}`,
				origin: TENANT_B.walletOrigin,
			},
		});
		expect(meOnB.statusCode).toBe(401);

		// same token is fine on its own tenant (and with no Origin — server-to-server)
		const meOnA = await ctx.app.inject({
			method: "GET",
			url: "/v1/me",
			headers: {
				authorization: `Bearer ${registered.session.token}`,
				origin: TENANT_A.walletOrigin,
			},
		});
		expect(meOnA.statusCode).toBe(200);
	});

	it("V6: one tenant's admin key cannot delete another tenant's ROR origin", async () => {
		const created = await ctx.app.inject({
			method: "POST",
			url: "/v1/admin/ror-origins",
			headers: { authorization: `Bearer ${ADMIN_KEY}` },
			payload: { origin: "https://v6.example.com" },
		});
		expect(created.statusCode).toBe(201);
		const id = (created.json() as { id: string }).id;

		const foreignDelete = await ctx.app.inject({
			method: "DELETE",
			url: `/v1/admin/ror-origins/${id}`,
			headers: { authorization: `Bearer ${TENANT_B.adminKey}` },
		});
		expect(foreignDelete.statusCode).toBe(404); // indistinguishable from missing

		const ownDelete = await ctx.app.inject({
			method: "DELETE",
			url: `/v1/admin/ror-origins/${id}`,
			headers: { authorization: `Bearer ${ADMIN_KEY}` },
		});
		expect(ownDelete.statusCode).toBe(204);
	});

	it("V7: /.well-known/webauthn is Host-scoped — each tenant sees only its own origins", async () => {
		const seedRor = async (adminKey: string, origin: string) => {
			const res = await ctx.app.inject({
				method: "POST",
				url: "/v1/admin/ror-origins",
				headers: { authorization: `Bearer ${adminKey}` },
				payload: { origin },
			});
			expect(res.statusCode).toBe(201);
		};
		await seedRor(TENANT_A.adminKey, "https://ror-alpha.example.com");
		await seedRor(TENANT_B.adminKey, "https://ror-beta.example.com");

		const onA = await ctx.app.inject({
			method: "GET",
			url: "/.well-known/webauthn",
			headers: { host: "localhost:4000" },
		});
		const originsA = (onA.json() as { origins: string[] }).origins;
		expect(originsA).toContain("https://ror-alpha.example.com");
		expect(originsA).not.toContain("https://ror-beta.example.com");

		const onB = await ctx.app.inject({
			method: "GET",
			url: "/.well-known/webauthn",
			headers: { host: "wallet-b.localhost:4100" },
		});
		const originsB = (onB.json() as { origins: string[] }).origins;
		expect(originsB).toContain("https://ror-beta.example.com");
		expect(originsB).not.toContain("https://ror-alpha.example.com");
	});

	it("V9: a duplicate userop hash from another tenant never leaks `duplicate: true`", async () => {
		// the SAME authenticator (same P-256 key) on both tenants — the one legitimate way
		// to construct one wallet address, hence one userop hash, across two tenants
		const auth = createAuthenticator();
		const onA = await register("v9-user", auth, TENANT_A);
		const onB = await register("v9-user", auth, TENANT_B, TENANT_B.adminKey);
		expect(onB.walletAddress).toBe(onA.walletAddress); // address derivation is tenant-agnostic by construction

		const op = {
			sender: onA.walletAddress,
			nonce: "0x99",
			callData: encodeFunctionData({
				abi: gianoSmartWalletAbi,
				functionName: "execute",
				args: ["0x3333333333333333333333333333333333333333", 0n, "0x"],
			}),
			callGasLimit: "0x30000",
			verificationGasLimit: "0x30000",
			preVerificationGas: "0x10000",
			maxFeePerGas: "0x3b9aca00",
			maxPriorityFeePerGas: "0x3b9aca00",
			signature: "0x1234",
		};

		const first = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${onA.session.token}` },
			payload: { userOperation: op },
		});
		expect(first.statusCode).toBe(200);

		// byte-identical op via tenant B's session: same hash, different tenant → generic 409
		const fromB = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${onB.session.token}` },
			payload: { userOperation: op },
		});
		expect(fromB.statusCode).toBe(409);
		expect(fromB.body).not.toContain('duplicate": true');

		// while the original submitter still gets the idempotent answer
		const fromAAgain = await ctx.app.inject({
			method: "POST",
			url: "/v1/userops",
			headers: { authorization: `Bearer ${onA.session.token}` },
			payload: { userOperation: op },
		});
		expect(fromAAgain.statusCode).toBe(200);
		expect((fromAAgain.json() as { duplicate?: boolean }).duplicate).toBe(true);
	});

	it("V11 (write path): a fixture naming an existing tenant never rewrites its rp_id", async () => {
		const mutated = parseTenantFixtures(
			JSON.stringify([
				{
					slug: TENANT_A.slug,
					walletOrigin: "http://other.localhost:5000",
					rpName: "Mutated",
					openRegistration: true,
				},
			]),
		);
		expect(await loadTenantFixtures(ctx.db, mutated)).toEqual({
			created: [],
			existing: [TENANT_A.slug],
		});
		const [row] = (
			await ctx.db.execute(
				sql`SELECT rp_id, rp_name FROM tenants WHERE slug = ${TENANT_A.slug}`,
			)
		).rows;
		expect(row).toEqual({ rp_id: TENANT_A.rpId, rp_name: TENANT_A.rpName });
	});
});
