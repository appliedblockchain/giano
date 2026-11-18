/**
 * The fixture artifacts' versions (deploy/fixtures.ts): a chain keeps the code it was deployed with,
 * so an earlier version of a fixture's code still matches after the artifact is regenerated.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { type Hex, keccak256 } from "viem";
import {
	artifactMatch,
	type FixtureArtifact,
	fixtureFingerprints,
	fixtureMatch,
	loadFixture,
	previousVersions,
} from "./fixtures";

const OLDEST: Hex = "0x6001";
const OLDER: Hex = "0x600260";
const CURRENT: Hex = "0x60036000";

const version = (code: Hex) => ({
	fingerprint: keccak256(code),
	size: (code.length - 2) / 2,
});

const artifact = (code: Hex, previous: Hex[]): FixtureArtifact => ({
	...loadFixture("GianoTestPrivateErc20"),
	runtimeCode: code,
	...version(code),
	previous: previous.map(version),
});

test("code of the current or an earlier version matches, with that version's fingerprint", () => {
	const fixture = artifact(CURRENT, [OLDER, OLDEST]);
	assert.equal(artifactMatch(fixture, CURRENT), keccak256(CURRENT));
	assert.equal(artifactMatch(fixture, OLDER), keccak256(OLDER));
	assert.equal(artifactMatch(fixture, OLDEST), keccak256(OLDEST));
	assert.equal(artifactMatch(fixture, "0x6004"), undefined);
	assert.equal(artifactMatch(artifact(CURRENT, []), OLDER), undefined);
});

test("a regeneration that changes the code keeps the replaced version, newest first", () => {
	assert.deepEqual(previousVersions(undefined, keccak256(CURRENT)), []);
	// The code did not change: the list stays as it is.
	const same = artifact(CURRENT, [OLDER]);
	assert.deepEqual(previousVersions(same, keccak256(CURRENT)), [
		version(OLDER),
	]);
	// It changed: the replaced code becomes the newest earlier version.
	assert.deepEqual(
		previousVersions(artifact(OLDER, [OLDEST]), keccak256(CURRENT)),
		[version(OLDER), version(OLDEST)],
	);
	// Back to an earlier version's code: it is current again, so it leaves the list.
	assert.deepEqual(
		previousVersions(artifact(OLDER, [OLDEST]), keccak256(OLDEST)),
		[version(OLDER)],
	);
	// An artifact written before `previous` existed.
	const { previous: _none, ...legacy } = artifact(OLDER, []);
	assert.deepEqual(
		previousVersions(legacy as FixtureArtifact, keccak256(CURRENT)),
		[version(OLDER)],
	);
});

test("the committed artifact: every version is a fingerprint gen:addresses accepts", () => {
	const committed = loadFixture("GianoTestPrivateErc20");
	assert.ok(
		committed.previous.length > 0,
		"the artifact lists earlier versions",
	);
	const accepted = fixtureFingerprints().map(({ fingerprint }) => fingerprint);
	for (const { fingerprint } of [committed, ...committed.previous])
		assert.ok(accepted.includes(fingerprint), fingerprint);
	assert.deepEqual(
		fixtureMatch("GianoTestPrivateErc20", committed.runtimeCode),
		{
			release: "fixture",
			fingerprint: committed.fingerprint,
		},
	);
});
