import type { HealthCheck } from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import { checkLink, groupChecks, pendingText, withReads } from "./health";

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
