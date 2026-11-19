/** scripts/generate-addresses.ts: the registry is built from verified records, wherever they put a contract. */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { RELEASE_FINGERPRINTS } from "../release-code";
import {
	generateRegistry,
	type KnownFingerprint,
} from "../scripts/generate-addresses";
import { FIXTURE_RELEASE, loadFixture } from "./fixtures";
import type { DeploymentRecord } from "./records";

const fingerprint = (contract: string) => {
	const entry = RELEASE_FINGERPRINTS.find(
		(r) => r.contract === contract && r.release === "v2",
	);
	assert.ok(entry);
	return entry.fingerprint;
};

const contract = (address: string, kind: string, deterministic = true) => ({
	address: address as `0x${string}`,
	label: kind,
	release: "v2",
	codehash: "0x00" as `0x${string}`,
	fingerprint: fingerprint(kind),
	deterministic,
});

/** A mainnet record whose paymaster proxy sits at an overridden, non-deterministic address. */
const record = (): DeploymentRecord => ({
	chainId: 8453,
	network: "mainnet",
	deployer: "0x1000000000000000000000000000000000000001",
	contracts: {
		walletImplementation: contract(
			"0x1111111111111111111111111111111111111111",
			"GianoSmartWallet",
		),
		factory: contract(
			"0x2222222222222222222222222222222222222222",
			"GianoSmartWalletFactory",
		),
		paymasterImplementation: contract(
			"0x3333333333333333333333333333333333333333",
			"GianoPaymaster",
		),
		paymasterProxy: contract(
			"0x4444444444444444444444444444444444444444",
			"ERC1967Proxy",
			false,
		),
	},
	upgrades: [],
	deviations: [
		{
			contract: "paymasterProxy",
			reason: "override",
			expected: "0x5555555555555555555555555555555555555555",
			actual: "0x4444444444444444444444444444444444444444",
			at: "2026-11-03T00:00:00.000Z",
			confirmed: true,
		},
	],
});

function generate(
	input: DeploymentRecord,
	overrides: Record<string, Record<string, string>> = {},
	/** Undefined: the generator's own, every release's and every fixture artifact's. */
	fingerprints?: readonly KnownFingerprint[],
) {
	const dir = mkdtempSync(join(tmpdir(), "giano-registry-"));
	try {
		writeFileSync(join(dir, `${input.chainId}.json`), JSON.stringify(input));
		return generateRegistry(
			dir,
			{
				default: { entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009" },
				...overrides,
			},
			fingerprints,
		);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

test("an overridden address with release code enters the registry", () => {
	const { text, chains } = generate(record());
	assert.equal(chains, 1);
	assert.match(
		text,
		/8453: \{[^}]*sponsorshipPaymaster: '0x4444444444444444444444444444444444444444'/,
	);
	assert.match(text, /factory: '0x2222222222222222222222222222222222222222'/);
});

test("a recorded contract whose code matches no release fails, naming the chain, contract and hash", () => {
	const foreign = record();
	const proxy = foreign.contracts.paymasterProxy;
	assert.ok(proxy);
	// A real fingerprint, but of another contract: the proxy's code is checked as a proxy.
	proxy.fingerprint = fingerprint("GianoPaymaster");
	assert.throws(
		() => generate(foreign),
		new RegExp(
			`chain 8453: paymasterProxy at 0x4444444444444444444444444444444444444444 has fingerprint ${proxy.fingerprint}, which matches no release's ERC1967Proxy`,
		),
	);
});

test("a release that leaves a contract unchanged can be recorded under either release", () => {
	// A v3 that ships v2's factory unchanged: one fingerprint, two releases.
	const v3 = RELEASE_FINGERPRINTS.filter((r) => r.release === "v2").map(
		(r) => ({ ...r, release: "v3" }),
	);
	const fingerprints = [...RELEASE_FINGERPRINTS, ...v3];
	const newer = record();
	for (const deployed of Object.values(newer.contracts))
		if (deployed) deployed.release = "v3";
	assert.equal(generate(newer, {}, fingerprints).chains, 1);
	assert.equal(generate(record(), {}, fingerprints).chains, 1);
	const older = record();
	if (older.contracts.factory) older.contracts.factory.release = "v1";
	assert.throws(
		() => generate(older, {}, fingerprints),
		/factory .* is recorded as v1 but its fingerprint is v2, v3's/,
	);
});

test("a record without a fingerprint fails rather than trusting the address", () => {
	const unverified = record();
	delete unverified.contracts.factory?.fingerprint;
	assert.throws(() => generate(unverified), /factory .* has no fingerprint/);
});

test("the factory and the wallet implementation are required", () => {
	const missing = record();
	delete missing.contracts.factory;
	assert.throws(() => generate(missing), /chain 8453: factory missing/);
});

test("local chains never enter the registry", () => {
	const { chains } = generate({ ...record(), chainId: 31337 });
	assert.equal(chains, 0);
});

test("address-overrides.json cannot set a Giano contract", () => {
	assert.throws(
		() =>
			generate(record(), {
				8453: { factory: "0x9999999999999999999999999999999999999999" },
			}),
		/address-overrides.json sets factory for chain 8453/,
	);
});

test("the served testnets may carry the test ERC-20 but never the permissive paymaster; a mainnet neither", () => {
	const token = contract(
		"0x7777777777777777777777777777777777777777",
		"PrivateERC20",
	);
	const permissive = contract(
		"0x6666666666666666666666666666666666666666",
		"PermissivePaymaster",
	);
	// Base Sepolia: on the production list (served) but a testnet.
	const served = { ...record(), chainId: 84532, network: "testnet" as const };
	served.contracts.testErc20 = token;
	assert.doesNotThrow(() => generate(served));
	served.contracts.testPaymaster = permissive;
	assert.throws(
		() => generate(served),
		/chain 84532 is a production chain but carries testPaymaster/,
	);
	// Base mainnet: no test ERC-20 either.
	const mainnet = record();
	mainnet.contracts.testErc20 = token;
	assert.throws(
		() => generate(mainnet),
		/chain 8453 is a mainnet but carries testErc20/,
	);
});

test("a chain recorded as mainnet is a production chain for R-29, listed or not", () => {
	const mainnet = { ...record(), chainId: 4242 };
	mainnet.contracts.testPaymaster = contract(
		"0x6666666666666666666666666666666666666666",
		"PermissivePaymaster",
	);
	assert.throws(() => generate(mainnet), /chain 4242 is a production chain/);
	assert.doesNotThrow(() => generate({ ...mainnet, network: "testnet" }));
});

/** The private test token as `testing` records it: from its committed artifact, not a release. */
const privateToken = (
	fingerprint = loadFixture("GianoTestPrivateErc20").fingerprint,
) => ({
	address: "0x7777777777777777777777777777777777777777" as `0x${string}`,
	label: "giano.test.private-erc20",
	release: FIXTURE_RELEASE,
	codehash: "0x00" as `0x${string}`,
	fingerprint,
	deterministic: true,
});

test("the paymaster proxy's deployment block enters the registry as a number, and only when recorded", () => {
	const withBlock = record();
	withBlock.contracts.paymasterProxy = {
		...(withBlock.contracts.paymasterProxy as NonNullable<
			DeploymentRecord["contracts"]["paymasterProxy"]
		>),
		blockNumber: 1_234_567,
	};
	assert.match(
		generate(withBlock).text,
		/8453: \{[^}]*sponsorshipPaymasterDeployBlock: 1234567,/,
	);
	assert.doesNotMatch(
		generate(record()).text,
		/8453: \{[^}]*sponsorshipPaymasterDeployBlock/,
	);
	withBlock.contracts.paymasterProxy = {
		...(withBlock.contracts.paymasterProxy as NonNullable<
			DeploymentRecord["contracts"]["paymasterProxy"]
		>),
		blockNumber: -1,
	};
	assert.throws(
		() => generate(withBlock),
		/chain 8453: invalid paymasterProxy blockNumber -1/,
	);
});

test("a testnet that carries the private test token lists it in its registry entry", () => {
	const testnet = { ...record(), chainId: 19877, network: "testnet" as const };
	testnet.contracts.privateTestErc20 = privateToken();
	const { text } = generate(testnet);
	assert.match(
		text,
		/19877: \{[^}]*privateTestErc20: '0x7777777777777777777777777777777777777777'/,
	);
});

test("a served Silent Data testnet may carry the private test token but never the permissive paymaster (R-29)", () => {
	for (const chainId of [19874, 19877]) {
		const testnet = { ...record(), chainId, network: "testnet" as const };
		testnet.contracts.privateTestErc20 = privateToken();
		assert.doesNotThrow(() => generate(testnet));
		testnet.contracts.testPaymaster = contract(
			"0x6666666666666666666666666666666666666666",
			"PermissivePaymaster",
		);
		assert.throws(
			() => generate(testnet),
			new RegExp(
				`chain ${chainId} is a production chain but carries testPaymaster`,
			),
		);
	}
});

test("the private test token's code is checked against its committed artifact", () => {
	const testnet = { ...record(), chainId: 19877, network: "testnet" as const };
	// Code that is not the artifact's.
	testnet.contracts.privateTestErc20 = privateToken(`0x${"ab".repeat(32)}`);
	assert.throws(
		() => generate(testnet),
		/privateTestErc20 at 0x7777777777777777777777777777777777777777 .* matches no release's GianoTestPrivateErc20 \(release-fingerprints.ts\) nor its fixture artifact/,
	);
	// An earlier version of the artifact: the chain keeps the code it was deployed with.
	const [earlier] = loadFixture("GianoTestPrivateErc20").previous;
	testnet.contracts.privateTestErc20 = privateToken(earlier.fingerprint);
	assert.match(
		generate(testnet).text,
		/19877: \{[^}]*privateTestErc20: '0x7777777777777777777777777777777777777777'/,
	);
	// The artifact's code recorded under a release: the record must name `fixture`.
	testnet.contracts.privateTestErc20 = { ...privateToken(), release: "v3" };
	assert.throws(
		() => generate(testnet),
		/privateTestErc20 at 0x7777777777777777777777777777777777777777 is recorded as v3 but its fingerprint is fixture's/,
	);
});

test("a production chain has no private test token entry: a record that carries one fails", () => {
	const { text } = generate(record());
	assert.doesNotMatch(text, /privateTestErc20:/);
	const mainnet = record();
	mainnet.contracts.privateTestErc20 = privateToken();
	assert.throws(
		() => generate(mainnet),
		/chain 8453 is a production chain but carries privateTestErc20=0x7777777777777777777777777777777777777777/,
	);
});
