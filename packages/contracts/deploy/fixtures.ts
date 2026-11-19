/**
 * Test fixtures deployed from a committed artifact instead of a release (fixtures/README.md).
 *
 * The private test token GianoTestPrivateErc20 exists only for the demo's private token section
 * (openspec silent-data-network, design D7). A release is what every chain of a class is adopted at,
 * forever; a demo fixture must not wait for one, nor make one. So the token's creation code is
 * committed under fixtures/, generated from a Foundry build (`pnpm gen:fixtures`, CI fails on
 * drift), and the deploy CLI deploys it from there, as it deploys CreateX from vendor/createx.
 *
 * A deployment record names such a contract's release as `fixture` and carries the artifact's
 * fingerprint, which `gen:addresses` checks like a release fingerprint.
 *
 * A chain keeps the code it was deployed with, and the token's address depends only on its label. So
 * the artifact also lists the fingerprints of its earlier versions (`previous`), and a chain that holds
 * an earlier version still matches: `gen:addresses` and a re-run of `testing` accept it. A new chain
 * gets the current code.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { type Hex, keccak256 } from "viem";

export const FIXTURES_DIR = path.resolve(import.meta.dirname, "..", "fixtures");

/** The `release` a deployment record names for a contract deployed from a fixture artifact. */
export const FIXTURE_RELEASE = "fixture";

/** Every contract deployed from a fixture artifact: its source unit and its artifact under fixtures/. */
export const FIXTURE_CONTRACTS = {
	GianoTestPrivateErc20: {
		source: "src/testing/GianoTestPrivateErc20.sol",
		file: "private-test-erc20.json",
	},
} as const;

export type FixtureContractName = keyof typeof FIXTURE_CONTRACTS;

/** fixtures/<file>.json, written by scripts/generate-fixtures.ts. */
export type FixtureArtifact = {
	$comment: string;
	contract: FixtureContractName;
	/** The source unit Foundry compiled it from. */
	source: string;
	/** The solc version Foundry used (foundry.toml pins it). */
	solc: string;
	creationCode: Hex;
	/** What `eth_getCode` returns once it is deployed. */
	runtimeCode: Hex;
	/** Runtime code size in bytes. */
	size: number;
	/** keccak256 of the runtime code. The fixtures have no immutables, so nothing is masked. */
	fingerprint: Hex;
	/** The earlier versions of this artifact, newest first, kept by `pnpm gen:fixtures`. */
	previous: FixtureCode[];
};

/** One version of a fixture's runtime code: its fingerprint and its size in bytes. */
export type FixtureCode = { fingerprint: Hex; size: number };

export function isFixtureContract(
	contract: string,
): contract is FixtureContractName {
	return Object.hasOwn(FIXTURE_CONTRACTS, contract);
}

const loaded = new Map<FixtureContractName, FixtureArtifact>();

export function loadFixture(contract: FixtureContractName): FixtureArtifact {
	let artifact = loaded.get(contract);
	if (!artifact) {
		const { file } = FIXTURE_CONTRACTS[contract];
		artifact = JSON.parse(
			fs.readFileSync(path.join(FIXTURES_DIR, file), "utf8"),
		) as FixtureArtifact;
		if (artifact.contract !== contract)
			throw new Error(
				`fixtures/${file} holds ${artifact.contract}, not ${contract}`,
			);
		loaded.set(contract, artifact);
	}
	return artifact;
}

/** Every version of `artifact`'s code: the current one first, then its `previous` ones. */
export function fixtureVersions(
	artifact: Pick<FixtureArtifact, "fingerprint" | "size" | "previous">,
): FixtureCode[] {
	return [
		{ fingerprint: artifact.fingerprint, size: artifact.size },
		// An artifact written before `previous` existed has none.
		...(artifact.previous ?? []),
	];
}

/**
 * The `previous` list of an artifact whose code now has `fingerprint`, given the artifact it replaces
 * (`old`). When the code changed, the old code becomes the newest earlier version. A version is listed
 * once, and never as both current and earlier.
 */
export function previousVersions(
	old: Pick<FixtureArtifact, "fingerprint" | "size" | "previous"> | undefined,
	fingerprint: Hex,
): FixtureCode[] {
	if (!old) return [];
	const versions = fixtureVersions(old);
	const seen = new Set<string>([fingerprint.toLowerCase()]);
	return versions.filter((version) => {
		const key = version.fingerprint.toLowerCase();
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}

/** Every fixture's fingerprints, every version, in the shape gen:addresses checks release fingerprints in. */
export function fixtureFingerprints(): {
	contract: FixtureContractName;
	release: string;
	fingerprint: Hex;
}[] {
	return (Object.keys(FIXTURE_CONTRACTS) as FixtureContractName[]).flatMap(
		(contract) =>
			fixtureVersions(loadFixture(contract)).map(({ fingerprint }) => ({
				contract,
				release: FIXTURE_RELEASE,
				fingerprint,
			})),
	);
}

/** The matching version's fingerprint when `runtimeCode` is one of `artifact`'s versions; else undefined. */
export function artifactMatch(
	artifact: FixtureArtifact,
	runtimeCode: Hex,
): Hex | undefined {
	const size = (runtimeCode.length - 2) / 2;
	const versions = fixtureVersions(artifact).filter((v) => v.size === size);
	if (versions.length === 0) return undefined;
	const hash = keccak256(runtimeCode);
	return versions.find(
		(v) => v.fingerprint.toLowerCase() === hash.toLowerCase(),
	)?.fingerprint;
}

/**
 * The fixture's fingerprint when `runtimeCode` (from `eth_getCode`) is its code, current or earlier;
 * else undefined.
 */
export function fixtureMatch(
	contract: FixtureContractName,
	runtimeCode: Hex,
): { release: string; fingerprint: Hex } | undefined {
	const fingerprint = artifactMatch(loadFixture(contract), runtimeCode);
	return fingerprint ? { release: FIXTURE_RELEASE, fingerprint } : undefined;
}
