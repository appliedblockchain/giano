import { describe, expect, it } from "vitest";
import {
	fromBase64Url,
	toBase64Url,
} from "../src/provider-injection/wallet-api/serialization";

describe("base64url", () => {
	it.each([0, 1, 2, 3, 4, 5, 32, 65])(
		"round-trips %i bytes without padding",
		(length) => {
			const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + 251) % 256);
			const encoded = toBase64Url(bytes);
			expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
			expect(Array.from(fromBase64Url(encoded))).toEqual(Array.from(bytes));
		},
	);

	it("uses the URL-safe alphabet", () => {
		expect(toBase64Url(Uint8Array.of(0xfb, 0xff))).toBe("-_8");
	});
});
