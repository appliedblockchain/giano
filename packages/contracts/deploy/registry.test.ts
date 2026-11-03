/** scripts/generate-addresses.ts: the registry is built from verified records, wherever they put a contract. */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { RELEASE_FINGERPRINTS } from "../release-code";
import { generateRegistry } from "../scripts/generate-addresses";
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
) {
	const dir = mkdtempSync(join(tmpdir(), "giano-registry-"));
	try {
		writeFileSync(join(dir, `${input.chainId}.json`), JSON.stringify(input));
		return generateRegistry(dir, {
			default: { entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009" },
			...overrides,
		});
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

test("a chain recorded as mainnet is a production chain for R-29, listed or not", () => {
	const mainnet = { ...record(), chainId: 4242 };
	mainnet.contracts.testPaymaster = contract(
		"0x6666666666666666666666666666666666666666",
		"PermissivePaymaster",
	);
	assert.throws(() => generate(mainnet), /chain 4242 is a production chain/);
	assert.doesNotThrow(() => generate({ ...mainnet, network: "testnet" }));
});
