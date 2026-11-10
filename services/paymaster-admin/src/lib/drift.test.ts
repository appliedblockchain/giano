import { describe, expect, it } from "vitest";
import { ago, driftChecks, shouldCompareLedger } from "./drift";
import type { ChainDrift } from "./platform-api";

const money = (wei: bigint) => `${wei} wei`;
const drift = (overrides: Partial<ChainDrift> = {}): ChainDrift => ({
	chainId: 31337,
	checkedAt: "2026-11-03T12:00:00Z",
	entries: [],
	unchecked: [],
	...overrides,
});
const byId = (checks: ReturnType<typeof driftChecks>) =>
	Object.fromEntries(checks.map((check) => [check.id, check]));

describe("driftChecks", () => {
	it("passes all three where wallet-api found no drift", () => {
		expect(
			driftChecks(drift(), money).map((check) => [check.id, check.level]),
		).toEqual([
			["registry-rows", "ok"],
			["drift-enabled", "ok"],
			["ledger", "ok"],
		]);
	});

	it("names each kind of drift, with both sides, and links the tenants it can", () => {
		const checks = byId(
			driftChecks(
				drift({
					entries: [
						{
							kind: "unknown-tenant",
							tenantId: "00000000-0000-0000-0000-000000000abc",
							enabledOnChain: true,
							balanceWei: "5",
						},
						{
							kind: "enabled-state",
							tenantId: "t1",
							slug: "acme",
							registryStatus: "suspended",
							enabledOnChain: true,
						},
						{
							kind: "ledger-balance",
							tenantId: "t2",
							slug: "byo",
							atBlock: "90",
							ledger: { balanceWei: "100", deficitWei: "0" },
							chain: { balanceWei: "90", deficitWei: "0" },
						},
						{
							kind: "withdraw-address",
							tenantId: "t2",
							slug: "byo",
							atBlock: "90",
							ledger: "0xaaa",
							chain: "0xbbb",
						},
					],
				}),
				money,
			),
		);
		expect(checks["registry-rows"]).toMatchObject({ level: "warn" });
		expect(checks["registry-rows"].detail).toContain(
			"00000000-0000-0000-0000-000000000abc (enabled, 5 wei)",
		);
		expect(checks["drift-enabled"]).toMatchObject({
			level: "warn",
			detail: "acme is suspended in the registry and enabled on chain",
			links: [{ to: "/tenants/acme", label: "acme" }],
		});
		expect(checks.ledger.detail).toBe(
			"byo: ledger 100 wei, chain 90 wei at block 90; byo: ledger withdraws to 0xaaa, the chain to 0xbbb at block 90",
		);
	});

	it("says when tenants could not be compared, instead of calling the ledger clean", () => {
		const ledger = byId(
			driftChecks(drift({ unchecked: ["t9"] }), money),
		).ledger;
		expect(ledger.level).toBe("warn");
		expect(ledger.label).toBe(
			"wallet-api's ledger could not be compared for every tenant",
		);
	});
});

describe("a tenant the ledger has no row for", () => {
	it("is a ledger difference, naming what the chain holds", () => {
		const [, , ledger] = driftChecks(
			drift({
				entries: [
					{
						kind: "no-ledger",
						tenantId: "t1",
						slug: "acme",
						chain: { balanceWei: "500", deficitWei: "0" },
					},
				],
			}),
			money,
		);
		expect(ledger.level).toBe("warn");
		expect(ledger.detail).toContain(
			"acme: no ledger row, the chain holds 500 wei",
		);
	});
});

describe("ago", () => {
	it("says how old a result is, so yesterday's does not read as today's", () => {
		const now = Date.parse("2026-11-10T12:00:00Z");
		expect(ago("2026-11-10T11:59:50Z", now)).toBe("just now");
		expect(ago("2026-11-10T11:57:00Z", now)).toBe("3 minutes ago");
		expect(ago("2026-11-09T12:00:00Z", now)).toBe("24 hours ago");
		expect(ago("2026-11-01T12:00:00Z", now)).toBe("9 days ago");
	});
});

describe("shouldCompareLedger", () => {
	it("starts the console's own comparison once wallet-api turns out to serve no drift", () => {
		// the tab opens while the drift read is pending: not this tab's job yet
		expect(
			shouldCompareLedger({
				enabled: false,
				count: 3,
				compared: false,
				emptyBefore: false,
			}),
		).toBe(false);
		// the drift read answers 404: it is, and nothing has been compared
		expect(
			shouldCompareLedger({
				enabled: true,
				count: 3,
				compared: false,
				emptyBefore: false,
			}),
		).toBe(true);
		// compared already: only when asked again
		expect(
			shouldCompareLedger({
				enabled: true,
				count: 3,
				compared: true,
				emptyBefore: false,
			}),
		).toBe(false);
		// the last comparison had nothing to compare, and tenants have arrived
		expect(
			shouldCompareLedger({
				enabled: true,
				count: 3,
				compared: true,
				emptyBefore: true,
			}),
		).toBe(true);
		expect(
			shouldCompareLedger({
				enabled: true,
				count: 0,
				compared: false,
				emptyBefore: false,
			}),
		).toBe(false);
	});
});
