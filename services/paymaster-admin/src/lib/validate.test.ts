import { describe, expect, it } from "vitest";
import {
	parseAddress,
	parseAmount,
	parsePenaltyBps,
	parseWholeNumber,
} from "./validate";

const ETH = { symbol: "ETH", decimals: 18 };
const CHECKSUMMED = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";

describe("parseAddress", () => {
	it("says nothing about an empty field", () => {
		expect(parseAddress("  ")).toEqual({});
	});

	it("accepts a checksummed or lowercase address, trimmed, and returns it checksummed", () => {
		expect(parseAddress(` ${CHECKSUMMED} `)).toEqual({ value: CHECKSUMMED });
		expect(parseAddress(CHECKSUMMED.toLowerCase())).toEqual({
			value: CHECKSUMMED,
		});
	});

	it("counts the hex characters of an address that is too short", () => {
		expect(parseAddress(CHECKSUMMED.slice(0, 41)).error).toBe(
			"This address has 39 hex characters instead of 40.",
		);
	});

	it("refuses a mixed-case address whose checksum does not match", () => {
		const typo = `${CHECKSUMMED.slice(0, 3)}A${CHECKSUMMED.slice(4)}`;
		expect(parseAddress(typo).error).toMatch(/checksum/);
	});

	it("refuses text that is not hex or has no 0x", () => {
		expect(parseAddress(CHECKSUMMED.slice(2)).error).toMatch(/0x/);
		expect(parseAddress(`0x${"g".repeat(40)}`).error).toMatch(/hex/);
	});
});

describe("parseAmount", () => {
	it("returns the amount in wei", () => {
		expect(parseAmount("1.5", { currency: ETH })).toEqual({
			value: 1_500_000_000_000_000_000n,
		});
		expect(parseAmount(".25", { currency: ETH })).toEqual({
			value: 250_000_000_000_000_000n,
		});
	});

	it("refuses zero, signs, units and too many decimals", () => {
		expect(parseAmount("0", { currency: ETH }).error).toMatch(/more than 0/);
		expect(parseAmount("-1", { currency: ETH }).error).toMatch(/amount in ETH/);
		expect(parseAmount("1 ETH", { currency: ETH }).error).toBeDefined();
		expect(
			parseAmount("0.1234567", { currency: { symbol: "USD", decimals: 6 } })
				.error,
		).toBe("USD has 6 decimal places; this has 7.");
	});

	it("refuses more than the maximum, naming it in the chain's currency", () => {
		const max = 1_000_000_000_000_000_000n;
		expect(
			parseAmount("1.01", {
				currency: { symbol: "POL", decimals: 18 },
				max,
				maxLabel: "the treasury",
			}).error,
		).toBe("That is more than the treasury (1 POL).");
		expect(parseAmount("1", { currency: ETH, max })).toEqual({ value: max });
	});
});

describe("parseWholeNumber", () => {
	it("accepts a non-negative whole number, including 0", () => {
		expect(parseWholeNumber("0")).toEqual({ value: 0n });
		expect(parseWholeNumber("86400")).toEqual({ value: 86_400n });
	});

	it("refuses decimals, signs and units", () => {
		expect(parseWholeNumber("1.5").error).toBeDefined();
		expect(parseWholeNumber("-1").error).toBeDefined();
		expect(parseWholeNumber("10s", { unit: "seconds" }).error).toBe(
			"Type a whole number of seconds, with no sign, decimals or units.",
		);
	});

	it("caps a penalty at 5000 basis points", () => {
		expect(parsePenaltyBps("5000")).toEqual({ value: 5000n });
		expect(parsePenaltyBps("5001").error).toBe(
			"The most this can be is 5000 basis points.",
		);
	});
});
