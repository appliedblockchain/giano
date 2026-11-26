import { describe, expect, it } from "vitest";
import { claimCodeFromUrl, pairingUrl } from "../src/pairing";

describe("the pairing link (PS-2)", () => {
	it("carries the claim code in the fragment of the wallet origin", () => {
		expect(pairingUrl("https://wallet.example.com", "AB3D9KFM")).toBe(
			"https://wallet.example.com/#claim=AB3D9KFM",
		);
		expect(pairingUrl("https://wallet.example.com/", "AB3D9KFM")).toBe(
			"https://wallet.example.com/#claim=AB3D9KFM",
		);
	});

	it("reads the code back from the link", () => {
		expect(
			claimCodeFromUrl(pairingUrl("http://wallet.localhost", "AB3D9KFM")),
		).toBe("AB3D9KFM");
		expect(claimCodeFromUrl("http://wallet.localhost/#claim=AB3D-9KFM")).toBe(
			"AB3D-9KFM",
		);
	});

	it("reads nothing from a URL without a code, or with one that is not a claim code", () => {
		expect(claimCodeFromUrl("http://wallet.localhost/")).toBeNull();
		expect(
			claimCodeFromUrl("http://wallet.localhost/?claim=AB3D9KFM"),
		).toBeNull();
		expect(
			claimCodeFromUrl("http://wallet.localhost/#claim=%3Cscript%3E"),
		).toBeNull();
		expect(claimCodeFromUrl("not a url")).toBeNull();
	});
});
