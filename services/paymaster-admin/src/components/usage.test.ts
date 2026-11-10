import { describe, expect, it } from "vitest";
import type { UsageFigures } from "../lib/platform-api";
import { refusalSplit, USAGE_READ_EVERY_MS, usageDue } from "./usage";

const figures = (refusedBy: UsageFigures["decisions"]["refusedBy"]) =>
	({
		decisions: { allowed: 0, refused: 0, refusedBy, byReason: {} },
		settled: 0,
		reverted: 0,
		gasWei: "0",
		feeWei: "0",
		overheadWei: "0",
	}) satisfies UsageFigures;

describe("refusalSplit", () => {
	it("names whose each refusal is to fix, leaving out the empty ones", () => {
		expect(
			refusalSplit(figures({ rules: 3, funds: 0, platform: 1, other: 0 })),
		).toEqual([
			["the tenant's rules", 3],
			["the platform", 1],
		]);
		expect(
			refusalSplit(figures({ rules: 0, funds: 0, platform: 0, other: 0 })),
		).toEqual([]);
	});
});

describe("usageDue", () => {
	it("reads on the first refresh, on another chain, and then at most once a minute", () => {
		const now = 1_800_000_000_000;
		expect(usageDue(undefined, 1, now)).toBe(true);
		const last = { chainId: 1, at: now - 10_000 };
		expect(usageDue(last, 1, now)).toBe(false);
		expect(usageDue(last, 2, now)).toBe(true);
		expect(
			usageDue({ chainId: 1, at: now - USAGE_READ_EVERY_MS }, 1, now),
		).toBe(true);
	});
});
