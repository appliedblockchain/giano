import { bytesToHex, stringToBytes } from "viem";
import { describe, expect, it } from "vitest";
import { describePersonalMessage } from "../src/personal-message";

const hexOf = (text: string) => bytesToHex(stringToBytes(text));

describe("describePersonalMessage", () => {
	it("shows plain text as text", () => {
		expect(describePersonalMessage("giano e2e")).toEqual({
			body: "giano e2e",
			rawHex: false,
		});
	});

	it("keeps tab and line breaks as text", () => {
		expect(describePersonalMessage("a\tb\r\nc")).toEqual({
			body: "a\tb\r\nc",
			rawHex: false,
		});
	});

	it("decodes hex of text to the text", () => {
		expect(describePersonalMessage("0x6869")).toEqual({
			body: "hi",
			rawHex: false,
		});
	});

	it("shows a 32-byte hash as hex", () => {
		const hash = `0x${"ab".repeat(32)}`;
		expect(describePersonalMessage(hash)).toEqual({ body: hash, rawHex: true });
	});

	it("shows invalid UTF-8 as hex", () => {
		expect(describePersonalMessage("0x68ff69")).toEqual({
			body: "0x68ff69",
			rawHex: true,
		});
	});

	it("shows a leading BOM as hex", () => {
		expect(describePersonalMessage("0xefbbbf6869")).toEqual({
			body: "0xefbbbf6869",
			rawHex: true,
		});
	});

	it.each([
		["bidi override", "pay ‮evil"],
		["zero-width space", "pay​me"],
		["combining grapheme joiner (U+034F)", "pay͏me"],
	])("shows text with a %s as hex", (_, text) => {
		expect(describePersonalMessage(text)).toEqual({
			body: hexOf(text),
			rawHex: true,
		});
		expect(describePersonalMessage(hexOf(text))).toEqual({
			body: hexOf(text),
			rawHex: true,
		});
	});

	it("shows odd-length hex as the text it is signed as", () => {
		expect(describePersonalMessage("0x123")).toEqual({
			body: "0x123",
			rawHex: false,
		});
	});
});
