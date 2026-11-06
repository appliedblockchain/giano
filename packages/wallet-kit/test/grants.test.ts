import { afterEach, describe, expect, it } from "vitest";
import { createConnectionGrants } from "../src/grants";

const KEY = "giano:connection-grant:https://app.test";

function memoryStorage(initial: Record<string, string> = {}) {
	const data = new Map(Object.entries(initial));
	return {
		data,
		getItem: (key: string) => data.get(key) ?? null,
		setItem: (key: string, value: string) => {
			data.set(key, value);
		},
		removeItem: (key: string) => {
			data.delete(key);
		},
	};
}

const refuse = () => {
	throw new Error("QuotaExceededError");
};

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

	it("touches only the origin's own key: no read before a write, so popups cannot overwrite each other", () => {
		const storage = memoryStorage();
		const calls: string[] = [];
		const spy = {
			getItem: (key: string) => {
				calls.push(`get ${key}`);
				return storage.getItem(key);
			},
			setItem: (key: string, value: string) => {
				calls.push(`set ${key}`);
				storage.setItem(key, value);
			},
			removeItem: (key: string) => {
				calls.push(`remove ${key}`);
				storage.removeItem(key);
			},
		};
		createConnectionGrants(spy).grant("https://app.test");
		createConnectionGrants(spy).revoke("https://app.test");
		expect(calls).toEqual([`set ${KEY}`, `remove ${KEY}`]);
	});

	it("treats unreadable storage as no grant", () => {
		const grants = createConnectionGrants({
			...memoryStorage({ [KEY]: "x" }),
			getItem: () => {
				throw new Error("SecurityError");
			},
		});
		expect(grants.has("https://app.test")).toBe(false);
	});

	it("keeps the grant in memory when storage refuses the write", () => {
		const grants = createConnectionGrants({
			...memoryStorage(),
			setItem: refuse,
		});
		grants.grant("https://app.test");
		expect(grants.has("https://app.test")).toBe(true);
	});

	it("throws on revoke when storage refuses the write, and stops granting in this popup", () => {
		const storage = memoryStorage({ [KEY]: "x" });
		const grants = createConnectionGrants({ ...storage, removeItem: refuse });
		expect(() => grants.revoke("https://app.test")).toThrow(
			"QuotaExceededError",
		);
		expect(grants.has("https://app.test")).toBe(false);
		expect(storage.data.has(KEY)).toBe(true);
	});

	it("drops a grant kept in memory when the revoke reaches storage", () => {
		const storage = memoryStorage();
		const grants = createConnectionGrants({ ...storage, setItem: refuse });
		grants.grant("https://app.test"); // kept in memory only
		grants.revoke("https://app.test");
		expect(grants.has("https://app.test")).toBe(false);
	});

	describe("the default storage", () => {
		const original = Object.getOwnPropertyDescriptor(
			globalThis,
			"localStorage",
		);
		afterEach(() => {
			if (original) Object.defineProperty(globalThis, "localStorage", original);
			else Reflect.deleteProperty(globalThis, "localStorage");
			globalThis.localStorage?.clear();
		});

		it("uses the wallet origin's localStorage", () => {
			createConnectionGrants().grant("https://app.test");
			expect(globalThis.localStorage.getItem(KEY)).not.toBeNull();
		});

		it("fails a revoke when the localStorage getter throws, and grants nothing", () => {
			globalThis.localStorage.setItem(KEY, "x"); // granted before site data was blocked
			Object.defineProperty(globalThis, "localStorage", {
				configurable: true,
				get: () => {
					throw new Error("SecurityError");
				},
			});
			const grants = createConnectionGrants();
			expect(grants.has("https://app.test")).toBe(false);
			expect(() => grants.revoke("https://app.test")).toThrow("SecurityError");
			grants.grant("https://other.test"); // kept in memory for this popup
			expect(grants.has("https://other.test")).toBe(true);
		});
	});

	it("works with no storage at all", () => {
		const grants = createConnectionGrants(null);
		grants.grant("https://app.test");
		expect(grants.has("https://app.test")).toBe(true);
		grants.revoke("https://app.test");
		expect(grants.has("https://app.test")).toBe(false);
	});
});
