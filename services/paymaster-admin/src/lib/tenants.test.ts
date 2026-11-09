import type { TenantView } from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import type { TenantSummary } from "./platform-api";
import {
	compareLedger,
	filterTenants,
	historyChanges,
	joinTenants,
	mergeFirstPage,
	needsAttention,
	nextStep,
	onChainBlocks,
	tenantTotals,
} from "./tenants";

const STOCK = "11111111-1111-4111-8111-111111111111";
const BYO = "22222222-2222-4222-8222-222222222222";
const ORPHAN = "33333333-3333-4333-8333-333333333333";

function registry(
	id: string,
	slug: string,
	overrides: Partial<TenantSummary> = {},
): TenantSummary {
	return {
		id,
		slug,
		status: "active",
		version: 1,
		walletOrigin: `https://${slug}.wallet.test`,
		rpId: `${slug}.wallet.test`,
		rpName: `${slug} wallet`,
		expectedOrigins: [],
		allowedDappOrigins: [],
		corsOrigins: [],
		openRegistration: false,
		policy: {},
		branding: {},
		createdAt: "2026-10-01T00:00:00.000Z",
		updatedAt: "2026-10-01T00:00:00.000Z",
		statusChangedAt: null,
		users: 0,
		...overrides,
	};
}

function onChain(
	uuid: string,
	overrides: Partial<TenantView> = {},
): TenantView {
	return {
		id: `0x${uuid.replace(/-/g, "")}`,
		uuid: uuid.toUpperCase(),
		registered: true,
		enabled: true,
		hasFeeOverride: false,
		withdrawAddress: `0x${"aa".repeat(20)}`,
		balance: 10n,
		deficit: 0n,
		feeWeiOverride: 0n,
		effectiveFeeWei: 1n,
		status: "active",
		...overrides,
	};
}

describe("joinTenants", () => {
	it("joins on id whatever its case, newest registry row first, then roster-only ids", () => {
		const rows = joinTenants(
			[
				registry(STOCK, "stock", { createdAt: "2026-09-01T00:00:00.000Z" }),
				registry(BYO, "byo", { createdAt: "2026-10-01T00:00:00.000Z" }),
			],
			[onChain(STOCK), onChain(ORPHAN, { enabled: false })],
		);
		expect(
			rows.map((row) => [row.registry?.slug ?? row.id, row.state]),
		).toEqual([
			["byo", "not-registered"],
			["stock", "enabled"],
			[ORPHAN, "disabled"],
		]);
	});

	it("says unknown, not unregistered, before the paymaster is read", () => {
		expect(joinTenants([registry(STOCK, "stock")], undefined)[0].state).toBe(
			"unknown",
		);
	});
});

describe("nextStep and needsAttention", () => {
	const [byo, stock, orphan] = joinTenants(
		[
			registry(BYO, "byo", { createdAt: "2026-10-02T00:00:00.000Z" }),
			registry(STOCK, "stock"),
		],
		[onChain(STOCK, { deficit: 5n }), onChain(ORPHAN)],
	);

	it("asks an active unregistered tenant to register, and one in deficit to be funded", () => {
		expect(nextStep(byo)).toBe("register");
		expect(nextStep(stock)).toBe("fund");
		expect(nextStep(orphan)).toBeUndefined();
	});

	it("suggests nothing for a suspended tenant", () => {
		const [suspended] = joinTenants(
			[registry(BYO, "byo", { status: "suspended" })],
			[],
		);
		expect(nextStep(suspended)).toBeUndefined();
	});

	it("flags a deficit, a missing registration, a roster-only id and a suspended tenant still enabled", () => {
		expect(needsAttention(byo, true)).toBe(true);
		expect(needsAttention(stock, true)).toBe(true);
		expect(needsAttention(orphan, true)).toBe(true);
		const [suspendedEnabled] = joinTenants(
			[registry(STOCK, "stock", { status: "suspended" })],
			[onChain(STOCK)],
		);
		expect(needsAttention(suspendedEnabled, true)).toBe(true);
		const [healthy] = joinTenants([registry(STOCK, "stock")], [onChain(STOCK)]);
		expect(needsAttention(healthy, true)).toBe(false);
	});

	it("does not flag a missing registry row while there is no registry to have one", () => {
		const [healthy, inDeficit] = joinTenants(undefined, [
			onChain(ORPHAN),
			onChain(STOCK, { deficit: 5n }),
		]);
		expect(needsAttention(healthy, false)).toBe(false);
		expect(needsAttention(inDeficit, false)).toBe(true);
	});
});

describe("filterTenants", () => {
	const rows = joinTenants(
		[
			registry(STOCK, "stock"),
			registry(BYO, "byo", { status: "suspended", rpName: "Bring your own" }),
			registry(ORPHAN, "gone", { status: "deleted" }),
		],
		[onChain(STOCK)],
	);
	const slugs = (filtered: ReturnType<typeof filterTenants>) =>
		filtered.map((row) => row.registry?.slug);

	it("hides deleted tenants unless asked", () => {
		expect(
			slugs(
				filterTenants(rows, {
					query: "",
					filter: "all",
					includeDeleted: false,
					registryKnown: true,
				}),
			),
		).toEqual(["stock", "byo"]);
		expect(
			filterTenants(rows, {
				query: "",
				filter: "all",
				includeDeleted: true,
				registryKnown: true,
			}),
		).toHaveLength(3);
	});

	it("searches slug, name, origin and id, and filters by state", () => {
		const all = {
			filter: "all",
			includeDeleted: false,
			registryKnown: true,
		} as const;
		expect(slugs(filterTenants(rows, { ...all, query: "bring" }))).toEqual([
			"byo",
		]);
		expect(
			slugs(filterTenants(rows, { ...all, query: "stock.wallet" })),
		).toEqual(["stock"]);
		expect(
			slugs(filterTenants(rows, { ...all, query: STOCK.slice(0, 8) })),
		).toEqual(["stock"]);
		expect(
			slugs(
				filterTenants(rows, {
					query: "",
					filter: "suspended",
					includeDeleted: false,
					registryKnown: true,
				}),
			),
		).toEqual(["byo"]);
	});
});

describe("onChainBlocks", () => {
	it("offers a deleted tenant no Register, Fund or Enable, and a suspended one no Enable", () => {
		expect(Object.keys(onChainBlocks("deleted")).sort()).toEqual([
			"enable",
			"fund",
			"register",
		]);
		expect(Object.keys(onChainBlocks("suspended"))).toEqual(["enable"]);
		expect(onChainBlocks("active")).toEqual({});
		expect(onChainBlocks(undefined)).toEqual({});
	});
});

describe("mergeFirstPage", () => {
	const e = (id: string) => ({ id });
	const ids = (entries: { id: string }[]) => entries.map((entry) => entry.id);

	it("keeps older pages the operator loaded, and puts what is new on top", () => {
		const loaded = [e("5"), e("4"), e("3"), e("2"), e("1")];
		const merged = mergeFirstPage(loaded, [e("6"), e("5"), e("4")]);
		expect(ids(merged.entries)).toEqual(["6", "5", "4", "3", "2", "1"]);
		expect(merged.keepCursor).toBe(true);
	});

	it("takes the page whole when nothing is loaded, or when it does not reach what is", () => {
		expect(mergeFirstPage([], [e("2"), e("1")])).toEqual({
			entries: [e("2"), e("1")],
			keepCursor: false,
		});
		const gap = mergeFirstPage([e("2"), e("1")], [e("9"), e("8")]);
		expect(ids(gap.entries)).toEqual(["9", "8"]);
		expect(gap.keepCursor).toBe(false);
	});
});

describe("tenantTotals", () => {
	it("totals the roster, counting on-chain tenants with no registry row", () => {
		const rows = joinTenants(
			[registry(STOCK, "stock"), registry(BYO, "byo")],
			[
				onChain(STOCK, { balance: 7n, deficit: 2n }),
				onChain(ORPHAN, { balance: 3n }),
			],
		);
		expect(tenantTotals(rows)).toEqual({
			held: 10n,
			onChain: 2,
			deficit: 2n,
			unregistered: 1,
		});
	});
});

describe("historyChanges", () => {
	it("lists only the fields that changed, not the bookkeeping", () => {
		expect(
			historyChanges(
				{ rpName: "Old", version: 1, updatedAt: "a", corsOrigins: ["x"] },
				{ rpName: "New", version: 2, updatedAt: "b", corsOrigins: ["x"] },
			),
		).toEqual([{ field: "rpName", before: "Old", after: "New" }]);
	});

	it("lists every field of a create", () => {
		expect(historyChanges(null, { slug: "acme", rpName: "Acme" })).toEqual([
			{ field: "slug", before: undefined, after: "acme" },
			{ field: "rpName", before: undefined, after: "Acme" },
		]);
	});
});

describe("compareLedger", () => {
	const ledger = {
		chainId: 1,
		balanceWei: "10",
		deficitWei: "0",
		lastSyncedBlock: "90",
	};

	it("agrees when balance and deficit match", () => {
		expect(compareLedger(ledger, { balance: 10n, deficit: 0n }, 100n)).toEqual({
			kind: "agrees",
		});
	});

	it("states both figures and the ledger's lag when they differ", () => {
		expect(compareLedger(ledger, { balance: 7n, deficit: 0n }, 100n)).toEqual({
			kind: "differs",
			ledgerBalance: 10n,
			ledgerDeficit: 0n,
			lag: 10n,
		});
		expect(
			compareLedger(
				{ ...ledger, lastSyncedBlock: null },
				{ balance: 7n, deficit: 0n },
				100n,
			),
		).toMatchObject({ kind: "differs", lag: undefined });
	});

	it("says when the ledger has no row for a tenant the chain has", () => {
		expect(compareLedger(undefined, { balance: 1n, deficit: 0n }, 1n)).toEqual({
			kind: "no-ledger",
		});
	});
});
