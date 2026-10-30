/**
 * Generates addresses.ts (the committed per-chain address registry) from the deployment records the
 * deploy CLI writes (deployments/<chainId>.json) plus address-overrides.json.
 *
 * Run with: pnpm gen:addresses  (CI re-runs it and fails on drift)
 */
import * as fs from "node:fs";
import * as path from "node:path";
import {
	CANONICAL_DEPLOYER,
	CANONICAL_FACTORY,
	CANONICAL_IMPLEMENTATION,
	CANONICAL_SPONSORSHIP_PAYMASTER,
	canonicalCodeAt,
} from "../canonical";
import {
	type LabelKey,
	LOCAL_CHAIN_IDS,
	PRODUCTION_CHAIN_IDS,
} from "../deploy/config";
import { DEPLOYMENTS_DIR, type DeploymentRecord } from "../deploy/records";

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

/** Registry fields that must hold canonical code (CANONICAL_CODE in canonical.ts). */
const CANONICAL_CODE_FIELDS: LabelKey[] = [
	"factory",
	"walletImplementation",
	"paymasterProxy",
	"paymasterImplementation",
];

type Overrides = Record<string, Record<string, string>>;

function isAddress(value: unknown): value is string {
	return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function main(): void {
	const overrides: Overrides = JSON.parse(
		fs.readFileSync(overridesPath, "utf8"),
	);
	delete overrides.$comment;

	const chains: Record<number, Record<string, string>> = {};
	const files = fs.existsSync(DEPLOYMENTS_DIR)
		? fs.readdirSync(DEPLOYMENTS_DIR).sort()
		: [];
	for (const entry of files) {
		const match = /^(\d+)\.json$/.exec(entry);
		if (!match) continue;
		const chainId = Number(match[1]);
		if ((LOCAL_CHAIN_IDS as readonly number[]).includes(chainId)) continue; // local chains are never committed
		const record = JSON.parse(
			fs.readFileSync(path.join(DEPLOYMENTS_DIR, entry), "utf8"),
		) as DeploymentRecord;
		if (record.chainId !== chainId)
			throw new Error(`${entry} records chain ${record.chainId}`);
		if (record.deployer.toLowerCase() !== CANONICAL_DEPLOYER.toLowerCase()) {
			throw new Error(
				`chain ${chainId}: deployed by ${record.deployer}, not the canonical deployer ${CANONICAL_DEPLOYER}`,
			);
		}

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
			// MC-19/MC-27: an address is not enough under CREATE3 — the code must be a release's too.
			if (
				CANONICAL_CODE_FIELDS.includes(key) &&
				!canonicalCodeAt(deployed.address, deployed.codehash)
			) {
				throw new Error(
					`chain ${chainId}: ${key} at ${deployed.address} has codehash ${deployed.codehash}, which no release puts there (canonical.ts CANONICAL_CODE)`,
				);
			}
			out[field] = deployed.address;
		}
		chains[chainId] = out;
	}

	const defaults = overrides.default ?? {};
	for (const chainId of Object.keys(chains)) {
		const merged = { ...defaults, ...(overrides[chainId] ?? {}) };
		for (const [field, address] of Object.entries(merged)) {
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

	// MC-19/MC-27: every chain the registry admits carries the canonical factory, implementation and
	// paymaster proxy — under CREATE3 that holds by construction for the canonical deployer, and is
	// checked anyway so a hand-edited record cannot slip through.
	for (const [chainId, record] of Object.entries(chains)) {
		for (const [field, canonical] of [
			["factory", CANONICAL_FACTORY],
			["implementation", CANONICAL_IMPLEMENTATION],
			["sponsorshipPaymaster", CANONICAL_SPONSORSHIP_PAYMASTER],
		] as const) {
			if (
				record[field] &&
				record[field].toLowerCase() !== canonical.toLowerCase()
			) {
				throw new Error(
					`chain ${chainId}: ${field} ${record[field]} differs from the canonical ${canonical}`,
				);
			}
		}
	}

	// R-29 layer 2: a testing artifact on a production chain is a build failure, not a warning.
	for (const chainId of PRODUCTION_CHAIN_IDS) {
		const record = chains[chainId];
		if (!record) continue;
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
	fs.writeFileSync(outPath, output);
	console.log(
		`Wrote ${path.relative(process.cwd(), outPath)} (${Object.keys(chains).length} chains)`,
	);
}

main();
