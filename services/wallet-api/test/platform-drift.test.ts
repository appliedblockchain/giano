import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { paymasterState, paymasterTenants, tenants } from "../src/db/schema.js";
import { computeDrift, tenantDrift } from "../src/services/drift.js";
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
				ledger: undefined,
				atLedgerBlock: undefined,
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
				ledger: undefined,
				atLedgerBlock: undefined,
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

	it("serves the watcher's last pass where this replica runs it", async () => {
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
		ctx.app.drift.set({
			...computed,
			checkedAt: new Date("2026-11-03T12:00:00Z"),
		});
		const { chains } = (await get(token)).json();
		expect(chains[0].checkedAt).toBe("2026-11-03T12:00:00.000Z");
	});

	it("says which tenants it could not compare, rather than guessing", async () => {
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
