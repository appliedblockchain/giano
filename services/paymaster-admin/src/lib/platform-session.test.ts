import { describe, expect, it } from "vitest";
import { refusalOutcome, tokenToRevoke } from "./platform-session";

describe("refusalOutcome", () => {
	it("ends the session on a 401 for the token in use", () => {
		expect(refusalOutcome("gps_new", "gps_new")).toBe("end");
		// a 401 that names no token is the session in use
		expect(refusalOutcome(undefined, "gps_new")).toBe("end");
	});

	it("goes again with the new token on a 401 for one Stay signed in replaced, and never ends the new session", () => {
		expect(refusalOutcome("gps_old", "gps_new")).toBe("retry");
	});

	it("ignores a 401 once no session is in use: a poll still in flight after Sign out says nothing", () => {
		expect(refusalOutcome("gps_old", undefined)).toBe("ignore");
		expect(refusalOutcome(undefined, undefined)).toBe("ignore");
	});
});

describe("tokenToRevoke", () => {
	it("revokes the token a renewal replaced, never the new one, and nothing on a first sign-in", () => {
		expect(tokenToRevoke("gps_old", "gps_new")).toBe("gps_old");
		expect(tokenToRevoke("gps_new", "gps_new")).toBeUndefined();
		expect(tokenToRevoke(undefined, "gps_new")).toBeUndefined();
	});
});
