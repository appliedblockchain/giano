/**
 * releasesOf against hand-made fingerprints: code that several releases left unchanged is every one
 * of those releases'.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { type Hex, keccak256 } from "viem";
import type { ReleaseFingerprint } from "../release-code";
import { releasesOf } from "../release-code";

const code: Hex = `0x${"6080".repeat(16)}`;
const entry = (release: string): ReleaseFingerprint => ({
	contract: "ERC1967Proxy",
	release,
	size: (code.length - 2) / 2,
	immutables: [],
	fingerprint: keccak256(code),
});

test("code a newer release left unchanged is every such release's, oldest first", () => {
	const fingerprints = [entry("v2"), entry("v3")];
	assert.deepEqual(
		releasesOf("ERC1967Proxy", code, undefined, fingerprints).map(
			(match) => match.release,
		),
		["v2", "v3"],
	);
	assert.deepEqual(
		releasesOf("PrivateERC20", code, undefined, fingerprints),
		[],
	);
});
