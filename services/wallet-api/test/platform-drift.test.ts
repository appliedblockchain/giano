import { and, eq } from "drizzle-orm";
import type { PublicClient } from "viem";
import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	vi,
} from "vitest";
import { paymasterState, paymasterTenants, tenants } from "../src/db/schema.js";
import {
	type ChainDrift,
	computeDrift,
	createDriftStore,
	ledgerBlock,
	tenantDrift,
} from "../src/services/drift.js";
import {
	createPaymasterWatcher,
	createSerialRunner,
	driftThenReconcile,
} from "../src/services/paymaster-watcher.js";
import {
	ADMIN,
	FAKE_WITHDRAW_ADDRESS,
	PLATFORM_ENV,
	platformSignIn,
	type SponsorshipTestContext,
	startSponsorshipStack,
	stopTestStack,
	TENANT_A,
	TENANT_B,
} from "./setup.js";

/**
 * Drift between wallet-api's records and a paymaster (openspec tenant-chain-drift, D14): the rules
 * first, as a pure function, then GET /v1/platform/drift over a real database and a faked chain.
 */

const OTHER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as const;

const chain = (
	overrides: Partial<Parameters<typeof tenantDrift>[0]["onChain"]> = {},
) => ({
	registered: true,
	enabled: true,
	withdrawAddress: FAKE_WITHDRAW_ADDRESS,
	balanceWei: 100n,
	deficitWei: 0n,
	...overrides,
});
const ledger = {
	balanceWei: 100n,
	deficitWei: 0n,
	withdrawAddress: FAKE_WITHDRAW_ADDRESS.toLowerCase(),
	lastSyncedBlock: 50n,
};
const active = { slug: "acme", status: "active" };

describe("tenantDrift", () => {
	it("finds none where the registry, the ledger and the chain agree", () => {
		expect(
			tenantDrift({
				tenantId: "t",
				onChain: chain(),
				registry: active,
				ledger,
				atLedgerBlock: { block: 50n, chain: chain() },
			}),
		).toEqual([]);
	});

	it("reports a suspended tenant still enabled on chain, naming both states", () => {
		expect(
			tenantDrift({
				tenantId: "t",
				onChain: chain(),
				registry: { slug: "acme", status: "suspended" },
				ledger,
				atLedgerBlock: { block: 50n, chain: chain() },
			}),
		).toEqual([
			{
				kind: "enabled-state",
				tenantId: "t",
				slug: "acme",
				registryStatus: "suspended",
				enabledOnChain: true,
			},
		]);
	});

	it("reports an active tenant disabled on chain, and a deleted one enabled", () => {
		const kinds = (status: string, enabled: boolean) =>
			tenantDrift({
				tenantId: "t",
				onChain: chain({ enabled }),
				registry: { slug: "acme", status },
				ledger,
				atLedgerBlock: { block: 50n, chain: chain() },
			}).map((entry) => entry.kind);
		expect(kinds("active", false)).toEqual(["enabled-state"]);
		expect(kinds("deleted", true)).toEqual(["enabled-state"]);
		expect(kinds("deleted", false)).toEqual([]);
	});

	it("reports a tenant on the roster with no registry row", () => {
		expect(
			tenantDrift({
				tenantId: "t",
				onChain: chain({ balanceWei: 7n }),
				registry: undefined,
				ledger: undefined,
				atLedgerBlock: undefined,
			}),
		).toEqual([
			{
				kind: "unknown-tenant",
				tenantId: "t",
				enabledOnChain: true,
				balanceWei: "7",
			},
		]);
	});

	it("never reports a tenant not yet registered on the chain: a step not yet taken", () => {
		expect(
			tenantDrift({
				tenantId: "t",
				onChain: chain({ registered: false, enabled: false }),
				registry: active,
				ledger: undefined,
				atLedgerBlock: undefined,
			}),
		).toEqual([]);
	});

	it("does not report a watcher that is behind: the chain changed after the ledger's block", () => {
		expect(
			tenantDrift({
				tenantId: "t",
				// at the head: funded since, and a new withdrawal address
				onChain: chain({ balanceWei: 900n, withdrawAddress: OTHER }),
				registry: active,
				ledger,
				// at the block the ledger describes, it agrees
				atLedgerBlock: { block: 50n, chain: chain() },
			}),
		).toEqual([]);
	});

	it("reports a ledger balance, deficit or withdrawal address the chain did not have at that block", () => {
		const drift = tenantDrift({
			tenantId: "t",
			onChain: chain(),
			registry: active,
			ledger,
			atLedgerBlock: {
				block: 50n,
				chain: chain({
					balanceWei: 90n,
					deficitWei: 5n,
					withdrawAddress: OTHER,
				}),
			},
		});
		expect(drift).toEqual([
			{
				kind: "ledger-balance",
				tenantId: "t",
				slug: "acme",
				atBlock: "50",
				ledger: { balanceWei: "100", deficitWei: "0" },
				chain: { balanceWei: "90", deficitWei: "5" },
			},
			{
				kind: "withdraw-address",
				tenantId: "t",
				slug: "acme",
				atBlock: "50",
				ledger: FAKE_WITHDRAW_ADDRESS.toLowerCase(),
				chain: OTHER,
			},
		]);
	});
});

describe("a tenant with no ledger row", () => {
	it("is drift when the chain holds a balance or a deficit for it, and nothing when it holds none", () => {
		expect(
			tenantDrift({
				tenantId: "t",
				onChain: chain({ balanceWei: 500n }),
				registry: active,
				ledger: undefined,
				atLedgerBlock: undefined,
			}),
		).toEqual([
			{
				kind: "no-ledger",
				tenantId: "t",
				slug: "acme",
				chain: { balanceWei: "500", deficitWei: "0" },
			},
		]);
		expect(
			tenantDrift({
				tenantId: "t",
				onChain: chain({ balanceWei: 0n }),
				registry: active,
				ledger: undefined,
				atLedgerBlock: undefined,
			}),
		).toEqual([]);
	});
});

describe("ledgerBlock", () => {
	it("is the later of the watcher's cursor and the row's own block, and none for a row never synced", () => {
		expect(ledgerBlock(90n, 50n)).toBe(90n);
		expect(ledgerBlock(90n, 120n)).toBe(120n);
		expect(ledgerBlock(null, 50n)).toBe(50n);
		expect(ledgerBlock(90n, null)).toBeUndefined();
	});
});

describe("the drift store", () => {
	const drift = (chainId: number, ageMs: number): ChainDrift => ({
		chainId,
		checkedAt: new Date(Date.now() - ageMs),
		entries: [],
		unchecked: [],
	});

	it("serves a watcher result only while fresh, and forgets it when told", async () => {
		const store = createDriftStore();
		store.set(drift(1, 10_000));
		expect(store.get(1, 60_000)).toBeDefined();
		expect(store.get(1, 5_000)).toBeUndefined();
		store.clear(1);
		expect(store.get(1, 60_000)).toBeUndefined();
	});

	it("computes again for an old result, shares a computation in flight, and reuses it briefly", async () => {
		const store = createDriftStore();
		store.set(drift(1, 10 * 60_000));
		const compute = vi.fn(async () => drift(1, 0));
		const [a, b] = await Promise.all([
			store.fresh(1, 120_000, compute),
			store.fresh(1, 120_000, compute),
		]);
		expect(compute).toHaveBeenCalledTimes(1);
		expect(a).toBe(b);
		await store.fresh(1, 120_000, compute);
		expect(compute).toHaveBeenCalledTimes(1);
	});
});

describe("the watcher's passes", () => {
	it("runs drift before the reconcile, and forgets the last drift when its pass fails", async () => {
		const order: string[] = [];
		const lost = vi.fn();
		await driftThenReconcile(
			{
				driftOnce: async () => {
					order.push("drift");
					throw new Error("roster unreadable");
				},
				reconcileOnce: async () => {
					order.push("reconcile");
					return { breach: false, slackWei: 0n, divergenceWei: 0n };
				},
			},
			{ warn: () => {} },
			lost,
		);
		expect(order).toEqual(["drift", "reconcile"]);
		expect(lost).toHaveBeenCalledTimes(1);
	});

	it("runs the poll and the reconcile one at a time, and does not queue a kind twice", async () => {
		const serial = createSerialRunner();
		const events: string[] = [];
		let release: () => void = () => {};
		const slow = new Promise<void>((resolve) => {
			release = resolve;
		});
		const poll = serial.run("poll", async () => {
			events.push("poll start");
			await slow;
			events.push("poll end");
		});
		const reconcile = serial.run("reconcile", async () => {
			events.push("reconcile");
		});
		const reconcileAgain = serial.run("reconcile", async () => {
			events.push("reconcile again");
		});
		release();
		await Promise.all([poll, reconcile, reconcileAgain]);
		expect(events).toEqual(["poll start", "poll end", "reconcile"]);
	});
});

describe("GET /v1/platform/drift", () => {
	let ctx: SponsorshipTestContext;
	let idA: string;
	let idB: string;
	const bytes16 = (uuid: string) => `0x${uuid.replace(/-/g, "")}`;

	beforeAll(async () => {
		ctx = await startSponsorshipStack(PLATFORM_ENV);
		const rows = await ctx.db
			.select({ id: tenants.id, slug: tenants.slug })
			.from(tenants);
		idA = rows.find((row) => row.slug === TENANT_A.slug)!.id;
		idB = rows.find((row) => row.slug === TENANT_B.slug)!.id;
		// both registered and funded on chain; the watcher has synced both to block 90
		for (const id of [idA, idB]) {
			ctx.paymasterState.registered.add(bytes16(id));
			ctx.paymasterState.tenantBalances.set(bytes16(id), 1_000n);
		}
		await ctx.db.insert(paymasterState).values({
			chainId: 31337,
			paymasterAddress: "0x15a2075f2407427c5dd0bde9d1966c48bd70e2f2",
			lastSyncedBlock: 90n,
		});
		await ctx.db.insert(paymasterTenants).values(
			[idA, idB].map((id) => ({
				tenantId: id,
				chainId: 31337,
				paymasterAddress: "0x15a2075f2407427c5dd0bde9d1966c48bd70e2f2",
				balanceWei: "1000",
				deficitWei: "0",
				withdrawAddress: FAKE_WITHDRAW_ADDRESS.toLowerCase(),
				lastSyncedBlock: 90n,
			})),
		);
	});

	afterAll(async () => {
		await stopTestStack(ctx);
	});

	// Each test changes the records: none may be answered from an earlier test's result.
	beforeEach(() => ctx.app.drift.clear(31337));

	const get = (token?: string) =>
		ctx.app.inject({
			method: "GET",
			url: "/v1/platform/drift",
			headers: token ? { authorization: `Bearer ${token}` } : {},
		});

	it("refuses a request without a platform admin session", async () => {
		expect((await get()).statusCode).toBe(401);
	});

	it("returns an empty list per sponsoring chain when every record agrees", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const response = await get(token);
		expect(response.statusCode).toBe(200);
		const { chains } = response.json();
		expect(chains).toHaveLength(1);
		expect(chains[0]).toMatchObject({
			chainId: 31337,
			entries: [],
			unchecked: [],
		});
		expect(Date.parse(chains[0].checkedAt)).toBeGreaterThan(
			Date.now() - 60_000,
		);
	});

	it("reports a suspended tenant still enabled, and a tenant the registry does not know", async () => {
		const stranger = "0x00000000000000000000000000000abc";
		ctx.paymasterState.registered.add(stranger);
		await ctx.db
			.update(tenants)
			.set({ status: "suspended" })
			.where(eq(tenants.id, idB));
		try {
			const token = await platformSignIn(ctx.app, ADMIN);
			const { chains } = (await get(token)).json();
			expect(chains[0].entries).toEqual(
				expect.arrayContaining([
					expect.objectContaining({
						kind: "enabled-state",
						slug: TENANT_B.slug,
						registryStatus: "suspended",
						enabledOnChain: true,
					}),
					expect.objectContaining({
						kind: "unknown-tenant",
						tenantId: "00000000-0000-0000-0000-000000000abc",
					}),
				]),
			);
			expect(chains[0].entries).toHaveLength(2);
		} finally {
			ctx.paymasterState.registered.delete(stranger);
			await ctx.db
				.update(tenants)
				.set({ status: "active" })
				.where(eq(tenants.id, idB));
		}
	});

	it("serves the watcher's last pass while it is fresh, and computes again once it is not", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const computed = await computeDrift({
			db: ctx.db,
			chainId: 31337,
			paymaster: {
				roster: async () => [],
				tenantAt: async () => {
					throw new Error("not read");
				},
			},
		});
		const tenSecondsAgo = new Date(Date.now() - 10_000);
		ctx.app.drift.set({ ...computed, checkedAt: tenSecondsAgo });
		expect((await get(token)).json().chains[0].checkedAt).toBe(
			tenSecondsAgo.toISOString(),
		);

		// a watcher that stopped a day ago is not served as current
		ctx.app.drift.set({
			...computed,
			checkedAt: new Date(Date.now() - 24 * 3600 * 1000),
		});
		const [current] = (await get(token)).json().chains;
		expect(Date.parse(current.checkedAt)).toBeGreaterThan(Date.now() - 60_000);
		ctx.app.drift.clear(31337);
	});

	it("answers for each chain on its own: one that cannot be read is an error for that chain", async () => {
		const token = await platformSignIn(ctx.app, ADMIN);
		const chain = ctx.app.chains.get(31337);
		const roster = vi
			.spyOn(chain.paymaster!, "roster")
			.mockRejectedValue(
				new Error("HTTP request failed. URL: http://node/v2/key"),
			);
		try {
			const response = await get(token);
			expect(response.statusCode).toBe(200);
			expect(response.json().chains).toEqual([
				{
					chainId: 31337,
					error: "drift-unavailable",
					message:
						"the paymaster or wallet-api's records could not be read to compare",
				},
			]);
			expect(response.body).not.toMatch(/http:\/\/node/);
		} finally {
			roster.mockRestore();
		}
	});

	it("compares each row at the later of the cursor and its own block", async () => {
		const asked: bigint[] = [];
		const roster = async () =>
			[idA, idB].map((id) => ({
				tenantId: bytes16(id) as `0x${string}`,
				registered: true,
				enabled: true,
				withdrawAddress: FAKE_WITHDRAW_ADDRESS,
				balanceWei: 1_000n,
				deficitWei: 0n,
			}));
		// A's row was written by a reconcile at 120, past the cursor (90); B's row is at 50, behind it.
		await ctx.db
			.update(paymasterTenants)
			.set({ lastSyncedBlock: 120n })
			.where(eq(paymasterTenants.tenantId, idA));
		await ctx.db
			.update(paymasterTenants)
			.set({ lastSyncedBlock: 50n })
			.where(eq(paymasterTenants.tenantId, idB));
		try {
			const drift = await computeDrift({
				db: ctx.db,
				chainId: 31337,
				paymaster: {
					roster,
					tenantAt: async (tenantId, block) => {
						asked.push(block);
						return {
							registered: true,
							enabled: true,
							withdrawAddress: FAKE_WITHDRAW_ADDRESS,
							// the chain at any other block disagrees, so a wrong block would show
							balanceWei:
								(tenantId === bytes16(idA) && block === 120n) ||
								(tenantId === bytes16(idB) && block === 90n)
									? 1_000n
									: 7n,
							deficitWei: 0n,
						};
					},
				},
			});
			expect(drift.entries).toEqual([]);
			expect([...asked].sort((a, b) => (a < b ? -1 : 1))).toEqual([90n, 120n]);
		} finally {
			await ctx.db
				.update(paymasterTenants)
				.set({ lastSyncedBlock: 90n })
				.where(eq(paymasterTenants.chainId, 31337));
		}
	});

	it("leaves a row the watcher has never synced uncompared, rather than report its zero balance", async () => {
		await ctx.db
			.update(paymasterTenants)
			.set({ lastSyncedBlock: null, balanceWei: "0" })
			.where(eq(paymasterTenants.tenantId, idA));
		try {
			const token = await platformSignIn(ctx.app, ADMIN);
			const [chainDrift] = (await get(token)).json().chains;
			expect(chainDrift.entries).toEqual([]);
			expect(chainDrift.unchecked).toEqual([idA]);
		} finally {
			await ctx.db
				.update(paymasterTenants)
				.set({ lastSyncedBlock: 90n, balanceWei: "1000" })
				.where(eq(paymasterTenants.tenantId, idA));
		}
	});

	it("reports a registry tenant the chain funded but the ledger has no row for", async () => {
		await ctx.db
			.delete(paymasterTenants)
			.where(eq(paymasterTenants.tenantId, idA));
		try {
			const token = await platformSignIn(ctx.app, ADMIN);
			const [chainDrift] = (await get(token)).json().chains;
			expect(chainDrift.entries).toEqual([
				{
					kind: "no-ledger",
					tenantId: idA,
					slug: TENANT_A.slug,
					chain: { balanceWei: "1000", deficitWei: "0" },
				},
			]);
		} finally {
			await ctx.db.insert(paymasterTenants).values({
				tenantId: idA,
				chainId: 31337,
				paymasterAddress: "0x15a2075f2407427c5dd0bde9d1966c48bd70e2f2",
				balanceWei: "1000",
				deficitWei: "0",
				withdrawAddress: FAKE_WITHDRAW_ADDRESS.toLowerCase(),
				lastSyncedBlock: 90n,
			});
		}
	});

	it("ingests a withdrawal address change, but not one older than what a reconcile wrote", async () => {
		const NEWER = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
		// A reconcile wrote A's row at 200; the cursor is still at 90 (a catch-up after an outage).
		await ctx.db
			.update(paymasterTenants)
			.set({ lastSyncedBlock: 200n })
			.where(eq(paymasterTenants.tenantId, idA));
		const change = (block: bigint, newAddress: string) => ({
			address: "0x15a2075f2407427c5dd0bde9d1966c48bd70e2f2",
			blockNumber: block,
			logIndex: 0,
			args: {
				tenantId: bytes16(idA),
				oldAddress: FAKE_WITHDRAW_ADDRESS,
				newAddress,
			},
		});
		const client = {
			getBlockNumber: async () => 300n,
			getLogs: async ({ event }: { event: { name: string } }) =>
				event.name === "TenantWithdrawAddressChanged"
					? [change(150n, OTHER), change(250n, NEWER)].filter(
							// the first poll sees only the older change
							(entry) => entry.blockNumber <= polledTo,
						)
					: [],
		} as unknown as PublicClient;
		let polledTo = 160n;
		const watcher = createPaymasterWatcher({
			db: ctx.db,
			pool: undefined as never,
			client,
			paymaster: {
				address: "0x15a2075f2407427c5dd0bde9d1966c48bd70e2f2",
			} as never,
			ledger: { expireStale: async () => {} } as never,
			chainId: 31337,
			pollMs: 1_000,
			lockRetryMs: 1_000,
			confirmations: 0,
			reconcileIntervalMs: 1_000,
			tenantSlug: async () => undefined,
		});
		const addressOf = async () =>
			(
				await ctx.db
					.select({ address: paymasterTenants.withdrawAddress })
					.from(paymasterTenants)
					.where(
						and(
							eq(paymasterTenants.tenantId, idA),
							eq(paymasterTenants.chainId, 31337),
						),
					)
			)[0].address;
		try {
			await watcher.pollOnce();
			expect(await addressOf()).toBe(FAKE_WITHDRAW_ADDRESS.toLowerCase());
			polledTo = 300n;
			await ctx.db
				.update(paymasterState)
				.set({ lastSyncedBlock: 90n })
				.where(eq(paymasterState.chainId, 31337));
			await watcher.pollOnce();
			expect(await addressOf()).toBe(NEWER.toLowerCase());
		} finally {
			await ctx.db
				.update(paymasterTenants)
				.set({
					lastSyncedBlock: 90n,
					withdrawAddress: FAKE_WITHDRAW_ADDRESS.toLowerCase(),
				})
				.where(eq(paymasterTenants.tenantId, idA));
			await ctx.db
				.update(paymasterState)
				.set({ lastSyncedBlock: 90n })
				.where(eq(paymasterState.chainId, 31337));
		}
	});

	it("says which tenants it could not compare, rather than guessing, through the endpoint too", async () => {
		const chain = ctx.app.chains.get(31337);
		const tenantAt = vi
			.spyOn(chain.paymaster!, "tenantAt")
			.mockRejectedValue(new Error("missing trie node"));
		try {
			const token = await platformSignIn(ctx.app, ADMIN);
			const [chainDrift] = (await get(token)).json().chains;
			expect(chainDrift.entries).toEqual([]);
			expect(chainDrift.unchecked.sort()).toEqual([idA, idB].sort());
		} finally {
			tenantAt.mockRestore();
		}
		const drift = await computeDrift({
			db: ctx.db,
			chainId: 31337,
			paymaster: {
				roster: async () =>
					[idA].map((id) => ({
						tenantId: bytes16(id) as `0x${string}`,
						registered: true,
						enabled: true,
						withdrawAddress: FAKE_WITHDRAW_ADDRESS,
						balanceWei: 1_000n,
						deficitWei: 0n,
					})),
				tenantAt: async () => {
					throw new Error("missing trie node");
				},
			},
		});
		expect(drift.entries).toEqual([]);
		expect(drift.unchecked).toEqual([idA]);
	});
});
