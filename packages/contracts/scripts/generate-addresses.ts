/**
 * Generates addresses.ts (the committed per-chain address registry) from the deployment records the
 * deploy CLI writes (deployments/<chainId>.json) plus address-overrides.json.
 *
 * A chain's addresses are whatever its record says: the class's deterministic ones, or a profile's
 * overrides. None is compared with a fixed address. What is checked is the code: every recorded
 * contract must carry the fingerprint of a release of that contract (release-fingerprints.ts), which
 * the deploy tooling computed from the chain itself when it recorded it.
 *
 *   pnpm gen:addresses  (CI re-runs it and fails on drift)
 *
 * Exported for tests: generateRegistry(dir, overrides) returns the file's text instead of writing it.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import {
	CONTRACT_OF,
	isProductionChain,
	type LabelKey,
	LOCAL_CHAIN_IDS,
	type NetworkClass,
} from "../deploy/config";
import { DEPLOYMENTS_DIR, type DeploymentRecord } from "../deploy/records";
import { RELEASE_FINGERPRINTS } from "../release-code";

const pkgRoot = path.resolve(import.meta.dirname, "..");
const overridesPath = path.join(pkgRoot, "address-overrides.json");
const outPath = path.join(pkgRoot, "addresses.ts");

/** Deployment-record key → registry field. Optional fields may be absent on production chains. */
const RECORD_TO_FIELD: Record<LabelKey, { field: string; optional: boolean }> =
	{
		factory: { field: "factory", optional: false },
		walletImplementation: { field: "implementation", optional: false },
		paymasterProxy: { field: "sponsorshipPaymaster", optional: true },
		paymasterImplementation: {
			field: "sponsorshipPaymasterImplementation",
			optional: true,
		},
		testPaymaster: { field: "testPaymaster", optional: true },
		testErc20: { field: "testErc20", optional: true },
	};

type Overrides = Record<string, Record<string, string>>;

/**
 * The registry fields address-overrides.json may set: third-party contracts only. A Giano contract's
 * address comes from its record alone, whose fingerprint the deploy tooling read from the chain; one
 * at a non-deterministic address goes through a profile override (deploy/chains/<profile>.json),
 * which the tooling verifies and records.
 */
const OVERRIDABLE_FIELDS = ["entryPoint"];

function isAddress(value: unknown): value is string {
	return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

export function generateRegistry(
	dir: string = DEPLOYMENTS_DIR,
	overrides: Overrides = JSON.parse(fs.readFileSync(overridesPath, "utf8")),
): { text: string; chains: number } {
	overrides = { ...overrides };
	delete overrides.$comment;

	const chains: Record<number, Record<string, string>> = {};
	const networks: Record<number, NetworkClass | undefined> = {};
	const files = fs.existsSync(dir) ? fs.readdirSync(dir).sort() : [];
	for (const entry of files) {
		const match = /^(\d+)\.json$/.exec(entry);
		if (!match) continue;
		const chainId = Number(match[1]);
		if ((LOCAL_CHAIN_IDS as readonly number[]).includes(chainId)) continue; // local chains are never committed
		const record = JSON.parse(
			fs.readFileSync(path.join(dir, entry), "utf8"),
		) as DeploymentRecord;
		if (record.chainId !== chainId)
			throw new Error(`${entry} records chain ${record.chainId}`);

		const out: Record<string, string> = {};
		for (const [key, { field, optional }] of Object.entries(
			RECORD_TO_FIELD,
		) as [LabelKey, { field: string; optional: boolean }][]) {
			const deployed = record.contracts[key];
			if (!deployed) {
				if (!optional)
					throw new Error(`chain ${chainId}: ${key} missing from ${entry}`);
				continue;
			}
			if (!isAddress(deployed.address))
				throw new Error(
					`chain ${chainId}: invalid ${key} address ${deployed.address}`,
				);
			// MC-19/MC-27: an address proves nothing about the code; the recorded fingerprint must be a
			// release's, for this contract and the release the record names.
			const contract = CONTRACT_OF[key];
			const release = RELEASE_FINGERPRINTS.find(
				(r) =>
					r.contract === contract &&
					r.fingerprint.toLowerCase() === deployed.fingerprint?.toLowerCase(),
			);
			if (!release)
				throw new Error(
					`chain ${chainId}: ${key} at ${deployed.address} has ${deployed.fingerprint ? `fingerprint ${deployed.fingerprint}` : `no fingerprint (code hash ${deployed.codehash})`}, which matches no release's ${contract} (release-fingerprints.ts)`,
				);
			if (release.release !== deployed.release)
				throw new Error(
					`chain ${chainId}: ${key} at ${deployed.address} is recorded as ${deployed.release} but its fingerprint is ${release.release}'s`,
				);
			out[field] = deployed.address;
		}
		chains[chainId] = out;
		networks[chainId] = record.network;
	}

	const defaults = overrides.default ?? {};
	for (const chainId of Object.keys(chains)) {
		const merged = { ...defaults, ...(overrides[chainId] ?? {}) };
		for (const [field, address] of Object.entries(merged)) {
			if (!OVERRIDABLE_FIELDS.includes(field))
				throw new Error(
					`address-overrides.json sets ${field} for chain ${chainId}: only ${OVERRIDABLE_FIELDS.join(", ")} may be set there. A Giano contract's address comes from its deployment record; to use one at a non-deterministic address, override it in the chain profile (deploy/chains/<profile>.json addresses) and deploy, which verifies and records it.`,
				);
			if (!isAddress(address))
				throw new Error(
					`Invalid override address for chain ${chainId}.${field}: ${address}`,
				);
			chains[Number(chainId)][field] = address;
		}
	}

	const fieldOrder = [
		"entryPoint",
		"factory",
		"implementation",
		"sponsorshipPaymaster",
		"sponsorshipPaymasterImplementation",
		"testPaymaster",
		"testErc20",
	];
	const chainBlocks = Object.entries(chains)
		.sort(([a], [b]) => Number(a) - Number(b))
		.map(([chainId, record]) => {
			const lines = fieldOrder
				.filter((field) => record[field])
				.map((field) => `    ${field}: '${record[field]}',`)
				.join("\n");
			return `  ${chainId}: {\n${lines}\n  },`;
		})
		.join("\n");

	// R-29 layer 2: a testing artifact on a production chain (the fixed list, or any chain recorded
	// as mainnet) is a build failure, not a warning.
	for (const [id, record] of Object.entries(chains)) {
		const chainId = Number(id);
		if (!isProductionChain(chainId, networks[chainId])) continue;
		for (const field of ["testPaymaster", "testErc20"]) {
			if (record[field]) {
				throw new Error(
					`chain ${chainId} is a production chain but carries ${field}=${record[field]}. ` +
						"Testing contracts must never be deployed to a production chain.",
				);
			}
		}
	}

	const output = `// AUTO-GENERATED by scripts/generate-addresses.ts — do not edit by hand.
// Source of truth: deployments/<chainId>.json (written by the deploy CLI) + address-overrides.json.
// Regenerate with: pnpm gen:addresses (CI fails on drift).

import { ENTRY_POINT_ADDRESS } from './entrypoint';

/** Canonical ERC-4337 EntryPoint v0.9. */
export const ENTRYPOINT_V09_ADDRESS: typeof ENTRY_POINT_ADDRESS = ENTRY_POINT_ADDRESS;

export type GianoDeployment = {
  /** ERC-4337 EntryPoint the wallets are bound to. */
  entryPoint: \`0x\${string}\`;
  /** GianoSmartWalletFactory. */
  factory: \`0x\${string}\`;
  /** GianoSmartWallet implementation behind the factory's proxies. */
  implementation: \`0x\${string}\`;
  /**
   * Production sponsorship paymaster (the UUPS proxy). This is the address tenants send funding
   * to, so it must stay stable: changing it means every tenant re-learns where to fund, and any
   * payment already in flight to the old address is lost.
   */
  sponsorshipPaymaster?: \`0x\${string}\`;
  /** Implementation behind {@link sponsorshipPaymaster}. Changes on every upgrade. */
  sponsorshipPaymasterImplementation?: \`0x\${string}\`;
  /**
   * Testing-only permissive paymaster. Deliberately a different field from
   * {@link sponsorshipPaymaster} so that no consumer can pass one where the other is meant —
   * the separation is structural rather than a matter of operator discipline.
   */
  testPaymaster?: \`0x\${string}\`;
  /** Testing-only ERC-20 (not deployed on production chains). */
  testErc20?: \`0x\${string}\`;
};

export const gianoAddresses: Record<number, GianoDeployment> = {
${chainBlocks}
};

/** Returns the Giano deployment for a chain, throwing a descriptive error for unknown chains. */
export function getGianoDeployment(chainId: number): GianoDeployment {
  const deployment = gianoAddresses[chainId];
  if (!deployment) {
    const known = Object.keys(gianoAddresses).join(', ');
    throw new Error(\`No Giano deployment registered for chain \${chainId}. Known chains: \${known}\`);
  }
  return deployment;
}
`;
	return { text: output, chains: Object.keys(chains).length };
}

if (process.argv[1] === import.meta.filename) {
	const { text, chains } = generateRegistry();
	fs.writeFileSync(outPath, text);
	console.log(
		`Wrote ${path.relative(process.cwd(), outPath)} (${chains} chains)`,
	);
}
