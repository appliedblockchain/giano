/**
 * Generates canonical.ts from deploy/config.ts (deployer + labels) and releases/.
 *
 * Addresses are pure functions of the deployer and the labels (deploy/create3.ts). Codehashes are
 * not: a contract's runtime code can embed its own address or a constructor argument, so the only
 * honest way to know what the canonical code hashes to is to deploy it there. This script does so
 * on a throwaway anvil — every release under the fixed labels, and every release after the first
 * under its upgrade labels — impersonating the canonical deployer, and records what it finds.
 *
 *   pnpm gen:canonical            (needs `anvil` on PATH; CI fails on drift)
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import {
	type Address,
	createPublicClient,
	createTestClient,
	createWalletClient,
	type Hex,
	http,
	type PublicClient,
} from "viem";
import { anvil as anvilChain } from "viem/chains";
import {
	CANONICAL_DEPLOYER,
	DEPLOYER_IS_PLACEHOLDER,
	ENTRY_POINT_V07,
	LABELS,
	upgradeLabel,
} from "../deploy/config";
import { create3Address } from "../deploy/create3";
import {
	type DeployContext,
	deployCore,
	deployUpgradeTarget,
} from "../deploy/deploy";
import {
	impersonate,
	installCreateX,
	installEntryPoint,
} from "../deploy/local";
import { listReleases, loadRelease } from "../deploy/release";

const outPath = path.resolve(import.meta.dirname, "..", "canonical.ts");

async function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = net.createServer();
		server.listen(0, "127.0.0.1", () => {
			const { port } = server.address() as net.AddressInfo;
			server.close(() => resolve(port));
		});
		server.on("error", reject);
	});
}

type CodeEntry = { label: string; release: string; codehash: Hex };

async function main(): Promise<void> {
	const releases = listReleases();
	if (releases.length === 0)
		throw new Error("no releases; cut one first (pnpm release:cut v1)");

	const port = await freePort();
	const anvilProcess = spawn(
		"anvil",
		[
			"--host",
			"127.0.0.1",
			"--port",
			String(port),
			"--chain-id",
			"31337",
			"--silent",
		],
		{ stdio: "ignore" },
	);
	const transport = http(`http://127.0.0.1:${port}`);
	const chain = { ...anvilChain, id: 31337 };
	const publicClient = createPublicClient({ chain, transport }) as PublicClient;
	const testClient = createTestClient({ chain, transport, mode: "anvil" });
	try {
		for (let i = 0; ; i++) {
			try {
				await publicClient.getChainId();
				break;
			} catch (error) {
				if (i > 80)
					throw new Error(
						`anvil did not start on port ${port}: ${String(error)}`,
					);
				await new Promise((r) => setTimeout(r, 100));
			}
		}
		const quiet = () => undefined;
		await installCreateX(publicClient, testClient, quiet);
		await installEntryPoint(
			publicClient,
			testClient,
			CANONICAL_DEPLOYER,
			quiet,
		);
		await impersonate(testClient, CANONICAL_DEPLOYER);
		const base = await testClient.snapshot();

		const code = new Map<Address, CodeEntry[]>();
		const note = (address: Address, entry: CodeEntry) =>
			code.set(address, [...(code.get(address) ?? []), entry]);

		for (const version of releases) {
			await testClient.revert({ id: base });
			const snapshot = await testClient.snapshot();
			const release = loadRelease(version);
			const ctx: DeployContext = {
				publicClient,
				walletClient: createWalletClient({
					chain,
					transport,
					account: CANONICAL_DEPLOYER,
				}),
				deployer: CANONICAL_DEPLOYER,
				record: {
					chainId: 31337,
					deployer: CANONICAL_DEPLOYER,
					contracts: {},
					upgrades: [],
				},
				log: quiet,
			};
			// The paymaster's configuration lives in proxy storage, so these values do not reach any codehash.
			await deployCore(ctx, release, {
				entryPoint: ENTRY_POINT_V07,
				roleAdmin: CANONICAL_DEPLOYER,
				defaultFeeWei: 0n,
				postOpGasAllowance: 0,
				penaltyBps: 0,
			});
			for (const key of [
				"walletImplementation",
				"factory",
				"paymasterImplementation",
				"paymasterProxy",
			] as const) {
				const deployed = ctx.record.contracts[key]!;
				note(deployed.address, {
					label: deployed.label,
					release: version,
					codehash: deployed.codehash,
				});
			}
			if (version !== releases[0]) {
				for (const of of [
					"paymasterImplementation",
					"walletImplementation",
				] as const) {
					const target = await deployUpgradeTarget(ctx, release, of);
					note(target.address, {
						label: target.label,
						release: version,
						codehash: target.codehash,
					});
				}
			}
			await testClient.revert({ id: snapshot });
		}

		const at = (label: string) => create3Address(CANONICAL_DEPLOYER, label);
		const codeEntries = [...code.entries()]
			.map(([address, entries]) => {
				const lines = entries
					.map(
						(e) =>
							`    { label: '${e.label}', release: '${e.release}', codehash: '${e.codehash}' },`,
					)
					.join("\n");
				return `  '${address}': [\n${lines}\n  ],`;
			})
			.join("\n");

		const output = `// AUTO-GENERATED by scripts/generate-canonical.ts — do not edit by hand.
// Inputs: deploy/config.ts (deployer, labels) and releases/. Regenerate with: pnpm gen:canonical
// (CI fails on drift).
//
// The canonical addresses. Every one is a pure function of CANONICAL_DEPLOYER and a label: CREATE3
// through CreateX with a permissioned salt (deploy/create3.ts). No bytecode, compiler setting or
// constructor argument enters an address, so a new release or a new toolchain never moves one, and
// a chain adopted later gets the same addresses as every other (MC-16, MC-19).
//
// The flip side: an address no longer proves which code sits there. CANONICAL_CODE does — the code
// each release puts at each canonical address. A deployment checks both (giano-doctor chain, and
// the wallet-api's chain verification at boot).
${
	DEPLOYER_IS_PLACEHOLDER
		? `//
// ⚠ CANONICAL_DEPLOYER IS A PLACEHOLDER (deploy/config.ts). Every address below changes when the real
// deployer is set. Nothing has been deployed to a public chain with it.
`
		: ""
}
/** The EOA that owns every canonical CREATE3 salt. */
export const CANONICAL_DEPLOYER = '${CANONICAL_DEPLOYER}' as const;

/** The fixed labels the canonical addresses are derived from (deploy/config.ts). */
export const CANONICAL_LABELS = {
${Object.entries(LABELS)
	.map(([key, label]) => `  ${key}: '${label}',`)
	.join("\n")}
} as const;

/** GianoSmartWalletFactory. */
export const CANONICAL_FACTORY = '${at(LABELS.factory)}' as const;

/** The GianoSmartWallet implementation the canonical factory clones. */
export const CANONICAL_IMPLEMENTATION = '${at(LABELS.walletImplementation)}' as const;

/**
 * The account nonce Giano derives every user's address with. Part of the factory's CREATE2 salt
 * for each account, so it must be identical on every chain (MC-21) — it is simply always zero.
 */
export const CANONICAL_ACCOUNT_NONCE = 0n;

/**
 * The sponsorship paymaster proxy: the address tenants send funding to and the one a dApp names in
 * \`paymasterAndData\`. Upgrades go through UUPS and keep it.
 */
export const CANONICAL_SPONSORSHIP_PAYMASTER = '${at(LABELS.paymasterProxy)}' as const;

/**
 * The implementation a fresh deployment initialises the paymaster proxy with (the fixed label).
 * Upgrades on a live chain point the proxy elsewhere: \`${upgradeLabel(LABELS.paymasterImplementation, "v<N>")}\`.
 */
export const CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION = '${at(LABELS.paymasterImplementation)}' as const;

export type CanonicalCode = { label: string; release: string; codehash: \`0x\${string}\` };

/** For every canonical address, the runtime codehash each release leaves there. */
export const CANONICAL_CODE: Record<\`0x\${string}\`, readonly CanonicalCode[]> = {
${codeEntries}
};

/** Which release's code \`codehash\` is at \`address\`, or undefined if it is not canonical code. */
export function canonicalCodeAt(address: string, codehash: string): CanonicalCode | undefined {
  const key = Object.keys(CANONICAL_CODE).find((a) => a.toLowerCase() === address.toLowerCase());
  return key ? CANONICAL_CODE[key as \`0x\${string}\`].find((entry) => entry.codehash.toLowerCase() === codehash.toLowerCase()) : undefined;
}
`;
		fs.writeFileSync(outPath, output);
		console.log(
			`Wrote ${path.relative(process.cwd(), outPath)} (${releases.join(", ")}; deployer ${CANONICAL_DEPLOYER}${DEPLOYER_IS_PLACEHOLDER ? " — placeholder" : ""})`,
		);
	} finally {
		anvilProcess.kill();
	}
}

main().catch((error: unknown) => {
	console.error(error);
	process.exit(1);
});
