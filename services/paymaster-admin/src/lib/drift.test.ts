import { describe, expect, it } from "vitest";
import { driftChecks } from "./drift";
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
