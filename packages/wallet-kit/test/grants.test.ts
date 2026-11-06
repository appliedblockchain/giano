import { describe, expect, it } from "vitest";
import { createConnectionGrants } from "../src/grants";

function memoryStorage(initial: Record<string, string> = {}) {
	const data = new Map(Object.entries(initial));
	return {
		getItem: (key: string) => data.get(key) ?? null,
		setItem: (key: string, value: string) => {
			data.set(key, value);
		},
	};
}

describe("connection grants (WK-34)", () => {
	it("grants nothing until an origin is granted, and only that origin", () => {
		const grants = createConnectionGrants(memoryStorage());
		expect(grants.has("https://app.test")).toBe(false);
		grants.grant("https://app.test");
		expect(grants.has("https://app.test")).toBe(true);
		expect(grants.has("https://other.test")).toBe(false);
	});

	it("survives the popup closing: a new store on the same storage sees the grant", () => {
		const storage = memoryStorage();
		createConnectionGrants(storage).grant("https://app.test");
		expect(createConnectionGrants(storage).has("https://app.test")).toBe(true);
	});

	it("revokes one origin and keeps the others", () => {
		const storage = memoryStorage();
		const grants = createConnectionGrants(storage);
		grants.grant("https://app.test");
		grants.grant("https://other.test");
		grants.revoke("https://app.test");
		const reopened = createConnectionGrants(storage);
		expect(reopened.has("https://app.test")).toBe(false);
		expect(reopened.has("https://other.test")).toBe(true);
	});

	it.each([
		["not JSON", "{"],
		["not an array", '{"https://app.test":true}'],
	])("treats an unreadable entry (%s) as no grant", (_label, raw) => {
		const grants = createConnectionGrants(
			memoryStorage({ "giano:connection-grants": raw }),
		);
		expect(grants.has("https://app.test")).toBe(false);
	});

	it("keeps the grant in memory when storage refuses the write", () => {
		const grants = createConnectionGrants({
			getItem: () => null,
			setItem: () => {
				throw new Error("QuotaExceededError");
			},
		});
		grants.grant("https://app.test");
		expect(grants.has("https://app.test")).toBe(true);
	});

	it("throws on revoke when storage refuses the write, and stops granting in this popup", () => {
		const storage = memoryStorage({
			"giano:connection-grants": JSON.stringify(["https://app.test"]),
		});
		const grants = createConnectionGrants({
			getItem: storage.getItem,
			setItem: () => {
				throw new Error("QuotaExceededError");
			},
		});
		expect(() => grants.revoke("https://app.test")).toThrow(
			"QuotaExceededError",
		);
		expect(grants.has("https://app.test")).toBe(false);
	});

	it("writes a revoke to storage even after a failed grant write switched to memory", () => {
		const storage = memoryStorage({
			"giano:connection-grants": JSON.stringify(["https://app.test"]),
		});
		let refuse = true;
		const grants = createConnectionGrants({
			getItem: storage.getItem,
			setItem: (key, value) => {
				if (refuse) throw new Error("QuotaExceededError");
				storage.setItem(key, value);
			},
		});
		grants.grant("https://other.test"); // fails: this popup now uses memory
		refuse = false;
		grants.revoke("https://app.test");
		expect(createConnectionGrants(storage).has("https://app.test")).toBe(false);
	});

	it("works with no storage at all", () => {
		const grants = createConnectionGrants(null);
		grants.grant("https://app.test");
		expect(grants.has("https://app.test")).toBe(true);
		grants.revoke("https://app.test");
		expect(grants.has("https://app.test")).toBe(false);
	});
});
