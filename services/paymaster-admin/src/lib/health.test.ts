import type { HealthCheck } from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import {
	CHAIN_THRESHOLDS,
	chainChecks,
	chainThresholds,
	checkLink,
	executorStanding,
	groupChecks,
	pendingText,
	signerCheck,
	withReads,
} from "./health";
import type { ChainStatus } from "./platform-api";

const check = (id: string): HealthCheck => ({
	id,
	level: "ok",
	label: id,
	detail: "",
});

describe("groupChecks", () => {
	it("puts each SDK check in its group, and anything unknown with the chain", () => {
		const groups = groupChecks(
			[
				"solvency",
				"stake",
				"tenants-funded",
				"signers",
				"role-UPGRADER_ROLE",
				"timelocked-roles",
				"timelock-delays",
				"implementation",
				"paused",
				"something-new",
			].map(check),
		);
		expect(groups.funds.map((entry) => entry.id)).toEqual([
			"solvency",
			"stake",
			"tenants-funded",
		]);
		expect(groups.keys.map((entry) => entry.id)).toEqual([
			"signers",
			"role-UPGRADER_ROLE",
			"timelocked-roles",
			"timelock-delays",
			"implementation",
		]);
		expect(groups.registry.map((entry) => entry.id)).toEqual([
			"paused",
			"something-new",
		]);
	});
});

describe("checkLink", () => {
	it("links each check to where it is fixed", () => {
		expect(checkLink("role-ROLE_ADMIN")).toEqual({
			to: "/roles",
			label: "Roles",
		});
		expect(checkLink("tenant-deficits")).toEqual({
			to: "/tenants",
			label: "Tenants",
		});
		expect(checkLink("timelocked-roles")).toEqual({
			to: "/roles",
			label: "Roles",
		});
		expect(checkLink("timelock-delays")).toEqual({
			to: "/timelock",
			label: "Timelock",
		});
		expect(checkLink("implementation")).toEqual({
			to: "/paymaster",
			label: "Paymaster",
		});
		expect(checkLink("drift-enabled")).toEqual({
			to: "/tenants",
			label: "Tenants",
		});
		expect(checkLink("stake")).toEqual({
			to: "/paymaster",
			label: "Paymaster",
		});
	});
});

describe("withReads", () => {
	const READ = {
		implementationRead: true,
		implementationError: undefined,
		timelockConfigured: true,
		timelockRead: true,
		timelockError: undefined,
	};
	// What assessHealth reports with no timelock and no implementation: the no-timelock warning and
	// its "exactly one holder" checks.
	const noTimelock = {
		level: "fail" as const,
		checks: [
			check("solvency"),
			{ ...check("role-ROLE_ADMIN"), level: "fail" as const },
			{ ...check("timelock"), level: "warn" as const },
		],
	};

	it("leaves a fully read report as it is", () => {
		const report = { level: "ok" as const, checks: [check("solvency")] };
		expect(withReads(report, READ)).toEqual({ ...report, pending: [] });
	});

	it("holds the implementation and an unread timelock as pending, not as a pass or as no timelock", () => {
		const health = withReads(noTimelock, {
			...READ,
			implementationRead: false,
			timelockRead: false,
		});
		expect(health.pending.map((entry) => entry.id)).toEqual([
			"implementation",
			"timelock",
		]);
		expect(health.checks.map((entry) => entry.id)).toEqual(["solvency"]);
		expect(health.level).toBe("ok");
		expect(pendingText(health.pending)).toBe(
			"the implementation and the timelock",
		);
	});

	it("warns about a failed read instead of leaving the check out", () => {
		const health = withReads(noTimelock, {
			...READ,
			implementationRead: false,
			implementationError: "slot read failed",
			timelockRead: false,
			timelockError: "getConfig failed",
		});
		expect(health.pending).toEqual([]);
		expect(
			health.checks.map((entry) => [entry.id, entry.level, entry.detail]),
		).toEqual([
			["solvency", "ok", ""],
			["implementation", "warn", "slot read failed"],
			["timelock-read", "warn", "getConfig failed"],
		]);
		expect(health.level).toBe("warn");
	});

	it("warns when a later read of the timelock fails, as the delays compared may be old", () => {
		const health = withReads(
			{ level: "ok", checks: [check("timelock-delays")] },
			{ ...READ, timelockStaleError: "getConfig failed" },
		);
		expect(health.checks.map((entry) => [entry.id, entry.level])).toEqual([
			["timelock-delays", "ok"],
			["timelock-read", "warn"],
		]);
		expect(health.level).toBe("warn");
	});

	it("keeps the no-timelock checks when no timelock is configured", () => {
		const health = withReads(noTimelock, {
			...READ,
			timelockConfigured: false,
			timelockRead: false,
		});
		expect(health.checks).toEqual(noTimelock.checks);
		expect(health.level).toBe("fail");
	});
});

const healthy: ChainStatus = {
	chainId: 84532,
	name: "Base Sepolia",
	registryStatus: "ready",
	verification: { checkedAt: "2026-11-03T12:00:00Z", failures: [] },
	lastProbe: { at: "2026-11-03T12:00:00Z", ok: true },
	node: { reachable: true, headBlock: "1000", headAgeSeconds: 2 },
	bundler: { reachable: true, entryPointSupported: true },
	paymaster: {
		address: "0x4Bf0c2F63C4fA20D88B8126298fFFC64710Ece96",
		depositWei: "1",
		treasuryWei: "0",
		stakeWei: "1",
		invariantSlackWei: "0",
		lastSyncedBlock: "990",
		watcherLagBlocks: 10,
		checkedAt: "2026-11-03T12:00:00Z",
	},
};
const levels = (chain: ChainStatus) =>
	Object.fromEntries(
		chainChecks(chain).map((check) => [
			check.id.replace(`chain-${chain.chainId}-`, ""),
			check.level,
		]),
	);

describe("chainChecks", () => {
	it("passes a chain that is served, current, submitting and synced", () => {
		expect(levels(healthy)).toEqual({
			status: "ok",
			node: "ok",
			bundler: "ok",
			watcher: "ok",
		});
	});

	it("applies the head-age and watcher-lag thresholds", () => {
		const at = (headAgeSeconds: number, watcherLagBlocks: number) =>
			levels({
				...healthy,
				node: { ...healthy.node, headAgeSeconds },
				paymaster: healthy.paymaster && {
					...healthy.paymaster,
					watcherLagBlocks,
				},
			});
		expect(at(61, 51)).toMatchObject({ node: "warn", watcher: "warn" });
		expect(at(301, 1_001)).toMatchObject({ node: "fail", watcher: "fail" });
		expect(at(60, 50)).toMatchObject({ node: "ok", watcher: "ok" });
	});

	it("shows a local devnet's head age without judging it: it mines on demand", () => {
		const idle = (chainId: number) =>
			levels({
				...healthy,
				chainId,
				node: { ...healthy.node, headAgeSeconds: 90_000 },
			}).node;
		expect(idle(31338)).toBe("ok");
		expect(idle(84532)).toBe("fail");
	});

	it("fails what cannot work: a dead node, a bundler on another EntryPoint, an unserved chain", () => {
		expect(
			levels({
				...healthy,
				registryStatus: "unavailable",
				node: { reachable: false, headBlock: null, headAgeSeconds: null },
				bundler: { reachable: true, entryPointSupported: false },
			}),
		).toMatchObject({ status: "fail", node: "fail", bundler: "fail" });
		expect(
			levels({
				...healthy,
				bundler: { reachable: true, entryPointSupported: null },
			}).bundler,
		).toBe("warn");
	});

	it("names a failed verification, and leaves the watcher out where the chain does not sponsor", () => {
		const checks = chainChecks({
			...healthy,
			paymaster: null,
			verification: {
				checkedAt: "2026-11-03T12:00:00Z",
				failures: [{ kind: "factory-not-canonical" }, { kind: "unreachable" }],
			},
		});
		expect(
			checks.find((check) => check.id.endsWith("verification")),
		).toMatchObject({
			level: "fail",
			detail: "factory-not-canonical",
		});
		expect(checks.some((check) => check.id.endsWith("watcher"))).toBe(false);
	});
});

describe("signerCheck", () => {
	it("fails an unavailable signer, and says nothing where sponsorship is off", () => {
		expect(signerCheck("unavailable")?.level).toBe("fail");
		expect(signerCheck("ok")?.level).toBe("ok");
		expect(signerCheck("disabled")).toBeUndefined();
	});
});

describe("chainThresholds", () => {
	it("warns at wallet-api's own ledger lag limit, and the console's default without one", () => {
		expect(chainThresholds(undefined)).toEqual(CHAIN_THRESHOLDS);
		const status = { signer: "ok" as const, chains: [] };
		expect(chainThresholds(status).watcherLagWarnBlocks).toBe(50);
		expect(
			chainThresholds({ ...status, maxLedgerLagBlocks: 200 })
				.watcherLagWarnBlocks,
		).toBe(200);
		// a limit past the failing lag moves the failing lag with it
		expect(
			chainThresholds({ ...status, maxLedgerLagBlocks: 5_000 })
				.watcherLagFailBlocks,
		).toBe(5_000);
	});
});

describe("executorStanding", () => {
	const lane = (
		balanceWei: string,
		nonces: [number, number] = [5, 5],
		busy = false,
	) => ({
		address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
		balanceWei,
		busy,
		latestNonce: nonces[0],
		pendingNonce: nonces[1],
	});
	// 1 gwei: 0.0004 ETH a submission
	const gwei = "1000000000";

	it("judges by the submissions a balance pays for at the gas price: under 10 fails, under 100 warns", () => {
		expect(executorStanding(lane("0"), gwei)).toMatchObject({
			level: "fail",
			submissions: 0,
		});
		expect(executorStanding(lane("3600000000000000"), gwei)).toMatchObject({
			level: "fail",
			submissions: 9,
		});
		expect(executorStanding(lane("4000000000000000"), gwei).level).toBe("warn");
		expect(executorStanding(lane("40000000000000000"), gwei)).toMatchObject({
			level: "ok",
			submissions: 100,
		});
	});

	it("fails an empty executor even when the gas price is unknown", () => {
		expect(executorStanding(lane("0"), null)).toMatchObject({
			level: "fail",
			submissions: null,
		});
		expect(executorStanding(lane("1"), null).level).toBe("ok");
	});

	it("warns on a transaction the bundler is not working on: pending while the lane is idle, or more than one ahead", () => {
		const funded = "1000000000000000000";
		expect(
			executorStanding(lane(funded, [5, 6], true), gwei).stuck,
		).toBeUndefined();
		expect(executorStanding(lane(funded, [5, 6], false), gwei)).toMatchObject({
			level: "warn",
			stuck: "mempool",
		});
		expect(executorStanding(lane(funded, [5, 7], true), gwei).stuck).toBe(
			"mempool",
		);
	});

	it("warns on a lane the bundler has held past its replacements and cancellation", () => {
		const now = Date.parse("2026-11-10T12:00:00Z");
		const busy = (minutesAgo: number) => ({
			...lane("1000000000000000000", [5, 6], true),
			busySince: new Date(now - minutesAgo * 60_000).toISOString(),
		});
		// 270 s is what giano-bundler reports for 3 replacements at a 30 s resubmit timeout
		const options = { stuckAfterSeconds: 270, now };
		expect(executorStanding(busy(2), gwei, options).stuck).toBeUndefined();
		expect(executorStanding(busy(90), gwei, options)).toMatchObject({
			level: "warn",
			stuck: "held",
			heldSeconds: 5400,
		});
		// without the bundler's limit (an older wallet-api) the hold time alone says nothing
		expect(executorStanding(busy(90), gwei).stuck).toBeUndefined();
		// the bundler's own count wins over this browser's clock: here it is 10 minutes slow
		expect(
			executorStanding({ ...busy(-10), heldSeconds: 5_400 }, gwei, options),
		).toMatchObject({ stuck: "held", heldSeconds: 5_400 });
		expect(
			executorStanding({ ...busy(90), heldSeconds: 60 }, gwei, options).stuck,
		).toBeUndefined();
	});
});

describe("executor checks on a chain", () => {
	it("blames the node or the time budget, not the bundler, when the executors could not be read", () => {
		const [check] = chainChecks(
			{
				...healthy,
				bundler: {
					reachable: true,
					entryPointSupported: true,
					executors: null,
					executorsUnknown: "unavailable",
				},
			},
			(wei) => `${wei} wei`,
		).filter((entry) => entry.id.includes("executors"));
		expect(check.detail).toContain("did not report them in time");
		expect(check.remedy).toContain("node first");
	});

	it("lists each executor, and warns once where the bundler does not report them", () => {
		const money = (wei: bigint) => `${wei} wei`;
		const withLanes = chainChecks(
			{
				...healthy,
				bundler: {
					reachable: true,
					entryPointSupported: true,
					gasPriceWei: "1000000000",
					executors: [
						{
							address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
							balanceWei: "0",
							busy: false,
							latestNonce: 0,
							pendingNonce: 0,
						},
					],
				},
			},
			money,
		).filter((check) => check.id.includes("executor"));
		expect(withLanes).toEqual([
			expect.objectContaining({
				id: "chain-84532-executor-0x90f79bf6eb2c4f870365e785982e1f101e93b906",
				level: "fail",
				label: "bundler executor 1",
				detail:
					"0x90F79bf6EB2c4f870365E785982E1f101E93b906: 0 wei, nothing to pay gas with; idle",
			}),
		]);
		expect(withLanes[0].remedy).toContain("Fund this address on Base Sepolia");

		const unknown = chainChecks(
			{
				...healthy,
				bundler: {
					reachable: true,
					entryPointSupported: true,
					executors: null,
				},
			},
			money,
		).filter((check) => check.id.includes("executor"));
		expect(unknown).toEqual([
			expect.objectContaining({ id: "chain-84532-executors", level: "warn" }),
		]);
	});
});
