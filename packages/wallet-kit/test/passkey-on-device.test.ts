import { afterEach, describe, expect, it } from "vitest";
import {
	hasPasskeyOnDevice,
	markPasskeyOnDevice,
	passkeyName,
} from "../src/passkey-on-device";

describe("what the device remembers about its passkeys", () => {
	afterEach(() => {
		localStorage.removeItem("giano:passkey-on-device");
	});

	it("knows of no passkey until one is marked", () => {
		expect(hasPasskeyOnDevice()).toBe(false);
		markPasskeyOnDevice();
		expect(hasPasskeyOnDevice()).toBe(true);
	});

	it("treats blocked storage as holding none, and marking as a no-op", () => {
		const original = Object.getOwnPropertyDescriptor(
			globalThis,
			"localStorage",
		);
		Object.defineProperty(globalThis, "localStorage", {
			configurable: true,
			get: () => {
				throw new DOMException("blocked", "SecurityError");
			},
		});
		try {
			expect(() => markPasskeyOnDevice()).not.toThrow();
			expect(hasPasskeyOnDevice()).toBe(false);
		} finally {
			if (original) Object.defineProperty(globalThis, "localStorage", original);
		}
	});
});

describe("passkeyName", () => {
	it("names a passkey after the wallet it joins, shortened", () => {
		expect(
			passkeyName("Giano", "0xA34a51cFF899812e9B208Ad37f14A919f35F9227"),
		).toBe("Giano · 0xA34a…9227");
	});

	it("names a first passkey after the day it was made, when its wallet is not known yet", () => {
		expect(
			passkeyName("Giano", undefined, new Date("2026-11-25T18:02:00Z")),
		).toBe("Giano · 2026-11-25");
	});

	it("ignores something that is not an address", () => {
		expect(
			passkeyName("Giano", "not-an-address", new Date("2026-11-25T00:00:00Z")),
		).toBe("Giano · 2026-11-25");
	});
});
