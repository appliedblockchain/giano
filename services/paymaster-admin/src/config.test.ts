import { describe, expect, it } from "vitest";
import {
	toAddresses,
	toExplorerUrl,
	toRefreshSeconds,
	toTimelockDelays,
} from "./config";

const SAFE = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

describe("toExplorerUrl", () => {
	it("accepts https, and http on localhost, without a trailing slash", () => {
		expect(toExplorerUrl("https://sepolia.basescan.org/", "d")).toBe(
			"https://sepolia.basescan.org",
		);
		expect(toExplorerUrl("http://localhost:4000", "d")).toBe(
			"http://localhost:4000",
		);
		expect(toExplorerUrl("", "d")).toBeUndefined();
	});

	it("refuses plain http elsewhere, and anything that is not a URL", () => {
		expect(() => toExplorerUrl("http://basescan.org", "deployment 1")).toThrow(
			"deployment 1 has an explorerUrl that is not https",
		);
		expect(() => toExplorerUrl("javascript:alert(1)", "d")).toThrow(
			/not https/,
		);
		expect(() => toExplorerUrl("basescan.org", "d")).toThrow(/not a URL/);
	});
});

describe("toExplorerUrl with a query or a fragment", () => {
	it("refuses both, since links are appended to the URL", () => {
		for (const raw of [
			"https://basescan.org?lang=en",
			"https://basescan.org/#top",
			"https://basescan.org/?",
		])
			expect(() => toExplorerUrl(raw, "d")).toThrow(/query or a fragment/);
	});
});

describe("toRefreshSeconds", () => {
	it("defaults when absent or empty", () => {
		expect(toRefreshSeconds(undefined, "d")).toBe(15);
		expect(toRefreshSeconds("", "d")).toBe(15);
	});

	it("accepts 0, and whole seconds from 1 to a day, as a number or a string", () => {
		expect(toRefreshSeconds(0, "d")).toBe(0);
		expect(toRefreshSeconds("1", "d")).toBe(1);
		expect(toRefreshSeconds(86_400, "d")).toBe(86_400);
	});

	it("refuses what would poll too fast, overflow the timer, or switch polling off unasked", () => {
		for (const raw of [0.001, 86_401, 2_147_484, -1, "15s", " ", " 15", null])
			expect(() => toRefreshSeconds(raw, "deployment 1")).toThrow(
				"deployment 1 has a refreshSeconds that is not 0 or a whole number of seconds from 1 to 86400",
			);
	});
});

describe("toAddresses", () => {
	it("keys known addresses by lowercase address", () => {
		expect(
			toAddresses({ [SAFE]: { label: "Safe", kind: "safe" } }, "d"),
		).toEqual({
			[SAFE.toLowerCase()]: { label: "Safe", kind: "safe" },
		});
		expect(toAddresses(undefined, "d")).toEqual({});
	});

	it("refuses a bad address, a missing label or an unknown kind", () => {
		expect(() => toAddresses({ "0x123": { label: "x" } }, "d")).toThrow(
			/not an address/,
		);
		expect(() => toAddresses({ [SAFE]: {} }, "d")).toThrow(/without a label/);
		expect(() =>
			toAddresses({ [SAFE]: { label: "x", kind: "eoa" } }, "d"),
		).toThrow(/only kind is "safe"/);
	});
});

describe("toTimelockDelays", () => {
	// base-sepolia's profile (deploy/chains/base-sepolia.json).
	const PUBLISHED = {
		minDelay: 300,
		upgradeToAndCall: 3600,
		grantRole: 3600,
		revokeRole: 3600,
		renounceRole: 3600,
		setTenantWithdrawAddress: 1800,
		setDefaultFee: 1200,
		setTenantFee: 600,
	};

	it("keeps the published delays, in seconds, and treats none as unset", () => {
		expect(toTimelockDelays(PUBLISHED, "d")).toEqual(PUBLISHED);
		expect(toTimelockDelays(undefined, "d")).toBeUndefined();
		expect(toTimelockDelays({}, "d")).toBeUndefined();
	});

	it("refuses a partial list, naming every delay it leaves out", () => {
		expect(() =>
			toTimelockDelays({ minDelay: 300, upgradeToAndCall: 3600 }, "d"),
		).toThrow(
			/without grantRole, revokeRole, renounceRole, setTenantWithdrawAddress, setDefaultFee, setTenantFee/,
		);
	});

	it("refuses a name the timelock has no delay for, and a delay that is not whole seconds", () => {
		expect(() =>
			toTimelockDelays({ ...PUBLISHED, upgrade: 3600 }, "d"),
		).toThrow(/"upgrade"; the names are minDelay, upgradeToAndCall/);
		expect(() =>
			toTimelockDelays({ ...PUBLISHED, minDelay: "2d" }, "d"),
		).toThrow(/minDelay delay that is not a whole number of seconds/);
		expect(() => toTimelockDelays({ ...PUBLISHED, minDelay: -1 }, "d")).toThrow(
			/not a whole number/,
		);
	});
});
