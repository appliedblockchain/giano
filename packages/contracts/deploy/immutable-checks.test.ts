import assert from "node:assert/strict";
import { test } from "node:test";
import { RELEASE_FINGERPRINTS } from "../release-fingerprints";
import { IMMUTABLE_CHECKS } from "./immutable-checks";

test("every immutable a release embeds has a registered check", () => {
	const missing = new Set<string>();
	for (const { contract, release, immutables } of RELEASE_FINGERPRINTS) {
		for (const { name } of immutables)
			if (!IMMUTABLE_CHECKS[contract]?.[name])
				missing.add(`${contract} (${release}): ${name}`);
	}
	assert.deepEqual(
		[...missing],
		[],
		"a release embeds an immutable that release fingerprints mask but nothing checks; add it to deploy/immutable-checks.ts together with its check",
	);
});

test("every registered check names an immutable some release embeds", () => {
	const embedded = new Set(
		RELEASE_FINGERPRINTS.flatMap(({ contract, immutables }) =>
			immutables.map(({ name }) => `${contract}:${name}`),
		),
	);
	const stale = Object.entries(IMMUTABLE_CHECKS).flatMap(([contract, checks]) =>
		Object.keys(checks ?? {})
			.map((name) => `${contract}:${name}`)
			.filter((key) => !embedded.has(key)),
	);
	assert.deepEqual(stale, []);
});
