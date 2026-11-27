import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { chainRelayPolicy, chainRelayPolicyHistory } from "../src/db/schema.js";
import {
	createChainPolicyService,
	resolveChainPolicy,
	SEED_ACTOR,
	seedChainPolicy,
} from "../src/services/chain-policy.js";
import {
	PLATFORM_ENV,
	platformSignIn,
	startTestStack,
	stopTestStack,
	type TestContext,
} from "./setup.js";

/**
 * Each chain's relay policy in the database (openspec chain-relay-policy-console): the seed, the
 * field-by-field resolution, the platform API and its history. The relay applying the stored policy
 * is in api.test.ts ("userop relay").
 */

const PAYMASTER = "0xb2C7081be89D88f1da020530Ebd5c14b8871615a";

describe("seedChainPolicy (design D3)", () => {
	it("seeds a known chain with its fee caps, any target and only its own Giano paymaster", () => {
		expect(
			seedChainPolicy({ chainId: 8453, sponsorshipPaymaster: PAYMASTER }),
		).toEqual({
			maxCallGas: "5000000",
			maxVerificationGas: "5000000",
			maxPreVerificationGas: "10000000",
			maxPaymasterVerificationGas: "1000000",
			maxPaymasterPostOpGas: "1000000",
			maxFeePerGas: "10000000000",
			maxPriorityFeePerGas: "1000000000",
			allowedTargets: "any",
			allowedPaymasters: [PAYMASTER.toLowerCase()],
		});
	});

	it("leaves undecided what it cannot know: fee caps of an unknown chain, a paymaster it does not have", () => {
		const seed = seedChainPolicy({ chainId: 777777 });
		expect(seed).not.toHaveProperty("maxFeePerGas");
		expect(seed).not.toHaveProperty("maxPriorityFeePerGas");
		expect(seed).not.toHaveProperty("allowedPaymasters");
		expect(seed.allowedTargets).toBe("any");
	});
});

describe("resolveChainPolicy (design D2, D4)", () => {
	const stored = seedChainPolicy({
		chainId: 8453,
		sponsorshipPaymaster: PAYMASTER,
	});

	it("applies the stored policy, and reports each field as stored", () => {
		const resolved = resolveChainPolicy({
			chainId: 8453,
			stored,
			overrides: {},
			production: true,
		});
		expect(resolved.problems).toEqual([]);
		expect(resolved.policy).toMatchObject({
			maxFeePerGas: 10_000_000_000n,
			allowedTargets: [],
			allowedPaymasters: [PAYMASTER.toLowerCase()],
		});
		expect(resolved.fields.allowedTargets).toEqual({
			value: "any",
			from: { kind: "stored" },
		});
	});

	it("lets an override win over the stored value, naming its source", () => {
		const resolved = resolveChainPolicy({
			chainId: 8453,
			stored,
			overrides: {
				maxFeePerGas: { value: 123n, source: "GIANO_CHAINS" },
				allowedPaymasters: { value: "any", source: "GIANO_CHAINS" },
			},
			production: true,
		});
		expect(resolved.policy.maxFeePerGas).toBe(123n);
		expect(resolved.policy.allowedPaymasters).toEqual([]);
		expect(resolved.fields.maxFeePerGas).toEqual({
			value: "123",
			from: { kind: "override", source: "GIANO_CHAINS" },
		});
	});

	it("falls back outside production for an undecided field, with no problem", () => {
		const resolved = resolveChainPolicy({
			chainId: 777777,
			stored: seedChainPolicy({ chainId: 777777 }),
			overrides: {},
			production: false,
		});
		expect(resolved.problems).toEqual([]);
		expect(resolved.policy.maxFeePerGas).toBe(500_000_000_000n);
		expect(resolved.policy.allowedPaymasters).toEqual([]);
		expect(resolved.fields.maxFeePerGas.from).toEqual({ kind: "fallback" });
	});

	it("refuses the chain in production for every undecided field, naming it and where to set it", () => {
		const resolved = resolveChainPolicy({
			chainId: 777777,
			stored: seedChainPolicy({ chainId: 777777 }),
			overrides: {},
			production: true,
		});
		expect(resolved.problems).toHaveLength(3);
		expect(resolved.problems[0]).toMatch(
			/^chain 777777: maxFeePerGas is not set, so the chain's operations are refused\. Set it in the console \(Relay policy\)/,
		);
		expect(resolved.problems.join("\n")).toMatch(/maxPriorityFeePerGas/);
		expect(resolved.problems.join("\n")).toMatch(/allowedPaymasters/);
		expect(resolved.fields.allowedPaymasters).toEqual({
			value: null,
			from: { kind: "undecided" },
		});
	});

	it("an override closes a production gap", () => {
		const resolved = resolveChainPolicy({
			chainId: 777777,
			stored: seedChainPolicy({ chainId: 777777 }),
			overrides: {
				maxFeePerGas: { value: 1n, source: "USEROP_MAX_FEE_PER_GAS" },
				maxPriorityFeePerGas: {
					value: 1n,
					source: "USEROP_MAX_PRIORITY_FEE_PER_GAS",
				},
				allowedPaymasters: { value: "any", source: "GIANO_CHAINS" },
			},
			production: true,
		});
		expect(resolved.problems).toEqual([]);
	});

	it("refuses a stored policy that does not parse in every deployment class, with one problem", () => {
		for (const production of [false, true]) {
			const resolved = resolveChainPolicy({
				chainId: 8453,
				stored: { ...stored, maxCallGas: 5, allowedTargets: [] },
				overrides: {},
				production,
			});
			expect(resolved.problems).toHaveLength(1);
			expect(resolved.problems[0]).toMatch(
				/^chain 8453's stored relay policy is invalid, so its operations are refused: maxCallGas: .*; allowedTargets: /,
			);
		}
	});

	it("always allows the chain's own current paymaster, even when the stored list predates it", () => {
		const moved = "0x00000000000000000000000000000000000000aa";
		const resolved = resolveChainPolicy({
			chainId: 8453,
			stored,
			overrides: {},
			production: true,
			ownPaymaster: moved,
		});
		expect(resolved.problems).toEqual([]);
		expect(resolved.policy.allowedPaymasters).toEqual([
			PAYMASTER.toLowerCase(),
			moved,
		]);
		// an open list stays open
		expect(
			resolveChainPolicy({
				chainId: 8453,
				stored: { ...stored, allowedPaymasters: "any" },
				overrides: {},
				production: true,
				ownPaymaster: moved,
			}).policy.allowedPaymasters,
		).toEqual([]);
	});

	it("leaves an overridden paymaster list as the deployment set it, and does not change it", () => {
		const moved = "0x00000000000000000000000000000000000000aa";
		const overridden = [PAYMASTER.toLowerCase()];
		const resolved = resolveChainPolicy({
			chainId: 8453,
			stored,
			overrides: {
				allowedPaymasters: {
					value: overridden,
					source: "USEROP_ALLOWED_PAYMASTERS",
				},
			},
			production: true,
			ownPaymaster: moved,
		});
		expect(resolved.policy.allowedPaymasters).toEqual([
			PAYMASTER.toLowerCase(),
		]);
		expect(overridden).toEqual([PAYMASTER.toLowerCase()]);
	});

	it("refuses a chain with no stored row, saying how to get one", () => {
		const resolved = resolveChainPolicy({
			chainId: 8453,
			stored: undefined,
			overrides: {},
			production: false,
		});
		expect(resolved.problems).toEqual([
			"chain 8453 has no stored relay policy. wallet-api seeds one when it starts; restart it, or set the policy in the console (Relay policy)",
		]);
	});
});

describe("the stored policy and the platform API", () => {
	let ctx: TestContext;
	let token: string;

	type ChainView = {
		chainId: number;
		version: number;
		stored: Record<string, unknown> | null;
		updatedBy: string | null;
		fields: Record<
			string,
			{
				effective: string | string[] | null;
				source: string;
				overriddenBy: string | null;
				stored: string | string[] | null;
			}
		>;
		problems: string[];
	};

	const list = async () => {
		const res = await ctx.app.inject({
			method: "GET",
			url: "/v1/platform/chain-policies",
			headers: { authorization: `Bearer ${token}` },
		});
		expect(res.statusCode).toBe(200);
		return (res.json() as { chains: ChainView[] }).chains;
	};
	const put = (body: unknown, version?: string, chainId = 31337) =>
		ctx.app.inject({
			method: "PUT",
			url: `/v1/platform/chain-policies/${chainId}`,
			headers: {
				authorization: `Bearer ${token}`,
				...(version === undefined ? {} : { "if-match": version }),
			},
			payload: body as object,
		});

	beforeAll(async () => {
		// The single-chain stack overrides the paymaster allowlist from the env, so the API reports
		// one overridden field.
		ctx = await startTestStack({
			...PLATFORM_ENV,
			USEROP_ALLOWED_PAYMASTERS: PAYMASTER,
		});
		token = await platformSignIn(ctx.app);
	});

	afterAll(async () => {
		if (ctx) await stopTestStack(ctx);
	});

	it("seeded every served chain at boot, and recorded it", async () => {
		const [row] = await ctx.db
			.select()
			.from(chainRelayPolicy)
			.where(eq(chainRelayPolicy.chainId, 31337));
		expect(row).toMatchObject({ version: 1, updatedBy: SEED_ACTOR });
		expect(row.policy).toEqual(seedChainPolicy({ chainId: 31337 }));
		const history = await ctx.db
			.select()
			.from(chainRelayPolicyHistory)
			.where(eq(chainRelayPolicyHistory.chainId, 31337));
		expect(history).toHaveLength(1);
		expect(history[0]).toMatchObject({ action: "seed", actor: SEED_ACTOR });
	});

	it("never overwrites a stored row when it seeds again", async () => {
		await ctx.db
			.update(chainRelayPolicy)
			.set({ policy: { allowedTargets: "any", maxCallGas: "7" } })
			.where(eq(chainRelayPolicy.chainId, 31337));
		const log = { info: vi.fn(), error: vi.fn() };
		try {
			const seeded = await createChainPolicyService({
				db: ctx.db,
				chains: ctx.config.CHAINS,
				production: false,
			}).seed(log);
			expect(seeded).toEqual([]);
			const [row] = await ctx.db
				.select()
				.from(chainRelayPolicy)
				.where(eq(chainRelayPolicy.chainId, 31337));
			expect(row.policy).toEqual({ allowedTargets: "any", maxCallGas: "7" });
		} finally {
			await ctx.db
				.update(chainRelayPolicy)
				.set({ policy: seedChainPolicy({ chainId: 31337 }) })
				.where(eq(chainRelayPolicy.chainId, 31337));
		}
	});

	it("logs a chain's problems at error level when it seeds", async () => {
		const log = { info: vi.fn(), error: vi.fn() };
		await createChainPolicyService({
			db: ctx.db,
			chains: ctx.config.CHAINS,
			production: true,
		}).seed(log);
		// the test chain has no known fee caps: undecided in production
		expect(log.error).toHaveBeenCalledWith(
			expect.objectContaining({
				chainId: 31337,
				problem: expect.stringMatching(/maxFeePerGas is not set/),
			}),
			expect.any(String),
		);
	});

	it("lists every served chain with stored, overridden, fallback and effective values", async () => {
		const [chain] = await list();
		expect(chain).toMatchObject({ chainId: 31337, version: 1, problems: [] });
		expect(chain.fields.maxCallGas).toEqual({
			effective: "5000000",
			source: "stored",
			overriddenBy: null,
			stored: "5000000",
		});
		expect(chain.fields.allowedPaymasters).toEqual({
			effective: [PAYMASTER.toLowerCase()],
			source: "override",
			overriddenBy: "USEROP_ALLOWED_PAYMASTERS",
			stored: null,
		});
		// a development stack: an undecided fee cap falls back, and says so
		expect(chain.fields.maxFeePerGas).toMatchObject({
			effective: "500000000000",
			source: "fallback",
		});
	});

	it("still lists every chain when a stored row is valid JSON but not an object", async () => {
		await ctx.db
			.update(chainRelayPolicy)
			.set({ policy: [] })
			.where(eq(chainRelayPolicy.chainId, 31337));
		try {
			const [chain] = await list();
			expect(chain.stored).toBeNull();
			expect(chain.problems).toEqual([
				expect.stringMatching(/stored relay policy is invalid/),
			]);
		} finally {
			await ctx.db
				.update(chainRelayPolicy)
				.set({ policy: seedChainPolicy({ chainId: 31337 }) })
				.where(eq(chainRelayPolicy.chainId, 31337));
		}
	});

	it("replaces the stored policy with the current version, and records who did it", async () => {
		const policy = {
			...seedChainPolicy({ chainId: 31337 }),
			maxFeePerGas: "2000000000",
			maxPriorityFeePerGas: "100000000",
			allowedTargets: ["0x00000000000000000000000000000000000000AA"],
		};
		const res = await put(policy, '"1"');
		expect(res.statusCode).toBe(200);
		expect(res.headers.etag).toBe('"2"');
		const view = res.json() as ChainView;
		expect(view.version).toBe(2);
		expect(view.updatedBy).toMatch(/^platform-admin:admin-test:/);
		expect(view.fields.maxFeePerGas).toMatchObject({
			effective: "2000000000",
			source: "stored",
		});
		// addresses are stored lowercase
		expect(view.fields.allowedTargets.effective).toEqual([
			"0x00000000000000000000000000000000000000aa",
		]);

		const history = await ctx.app.inject({
			method: "GET",
			url: "/v1/platform/chain-policies/31337/history",
			headers: { authorization: `Bearer ${token}` },
		});
		const { entries } = history.json() as {
			entries: {
				action: string;
				actor: string;
				platformAdminSessionId: string | null;
				before: unknown;
				after: unknown;
			}[];
		};
		expect(entries.map((entry) => entry.action)).toEqual(["update", "seed"]);
		expect(entries[0].actor).toMatch(/^platform-admin:admin-test:/);
		expect(entries[0].platformAdminSessionId).not.toBeNull();
		expect(entries[0].before).toEqual(seedChainPolicy({ chainId: 31337 }));
	});

	it("refuses a stale version with 412, and a missing If-Match with 428", async () => {
		const policy = seedChainPolicy({ chainId: 31337 });
		const stale = await put(policy, '"1"');
		expect(stale.statusCode).toBe(412);
		expect(stale.json()).toMatchObject({
			error: "version-mismatch",
			version: 2,
		});
		expect((stale.json() as { message: string }).message).toMatch(
			/someone else changed it/,
		);
		expect((await put(policy)).statusCode).toBe(428);
	});

	it("refuses an empty allowlist, a bad cap and an unknown field with 400 naming each", async () => {
		const res = await put(
			{ allowedTargets: [], maxCallGas: "0", maxCallgas: "1" },
			'"2"',
		);
		expect(res.statusCode).toBe(400);
		const body = res.json() as {
			error: string;
			issues: { path: string; message: string }[];
		};
		expect(body.error).toBe("validation");
		const text = JSON.stringify(body.issues);
		expect(text).toMatch(/allowedTargets/);
		expect(text).toMatch(/maxCallGas/);
		expect(text).toMatch(/maxCallgas/);
		// nothing was written
		expect((await list())[0].version).toBe(2);
	});

	it("refuses a chain wallet-api does not serve with 404", async () => {
		const res = await put({}, '"0"', 777777);
		expect(res.statusCode).toBe(404);
		expect(res.json()).toMatchObject({ error: "unknown-chain" });
		const history = await ctx.app.inject({
			method: "GET",
			url: "/v1/platform/chain-policies/777777/history",
			headers: { authorization: `Bearer ${token}` },
		});
		expect(history.statusCode).toBe(404);
	});

	it("pages through history entries that share a timestamp without skipping any", async () => {
		const chainId = 424242; // a chain of its own, so the served chain's history is untouched
		const at = new Date("2026-01-01T00:00:00.000Z");
		await ctx.db.insert(chainRelayPolicyHistory).values(
			[1, 2, 3].map((n) => ({
				chainId,
				action: "update" as const,
				actor: `test:${n}`,
				after: { maxCallGas: String(n) },
				createdAt: at,
			})),
		);
		const service = createChainPolicyService({
			db: ctx.db,
			chains: ctx.config.CHAINS,
			production: false,
		});
		const seen: string[] = [];
		let before: string | undefined;
		for (let page = 0; page < 5; page++) {
			const { entries, next } = await service.history(chainId, before, 1);
			seen.push(...entries.map((entry) => entry.actor));
			if (!next) break;
			before = next;
		}
		expect(seen.sort()).toEqual(["test:1", "test:2", "test:3"]);
	});

	it("needs a platform admin session", async () => {
		const res = await ctx.app.inject({
			method: "GET",
			url: "/v1/platform/chain-policies",
		});
		expect(res.statusCode).toBe(401);
	});
});
