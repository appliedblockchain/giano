import { describe, expect, it } from "vitest";
import { toAddresses, toExplorerUrl, toTimelockDelays } from "./config";

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
	it("keeps the published delays, in seconds, and treats none as unset", () => {
		expect(
			toTimelockDelays({ minDelay: 300, upgradeToAndCall: 3600 }, "d"),
		).toEqual({ minDelay: 300, upgradeToAndCall: 3600 });
		expect(toTimelockDelays(undefined, "d")).toBeUndefined();
		expect(toTimelockDelays({}, "d")).toBeUndefined();
	});

	it("refuses a name the timelock has no delay for, and a delay that is not whole seconds", () => {
		expect(() => toTimelockDelays({ upgrade: 3600 }, "d")).toThrow(
			/"upgrade"; the names are minDelay, upgradeToAndCall/,
		);
		expect(() => toTimelockDelays({ minDelay: "2d" }, "d")).toThrow(
			/minDelay delay that is not a whole number of seconds/,
		);
		expect(() => toTimelockDelays({ minDelay: -1 }, "d")).toThrow(
			/not a whole number/,
		);
	});
});
