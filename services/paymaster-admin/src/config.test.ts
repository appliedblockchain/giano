import { describe, expect, it } from "vitest";
import { toAddresses, toExplorerUrl, toRefreshSeconds } from "./config";

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
