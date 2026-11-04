/**
 * The determinism gate (CI: .github/workflows/determinism.yml). For the local class, and for every
 * class whose canonical deployer is configured (deploy/config.ts DEPLOYERS), deploys the latest
 * release's core contracts through CreateX on a throwaway anvil, impersonating that deployer, and
 * checks that:
 *   - every contract landed on CREATE3(deployer, label), as deploy/create3.ts computes it;
 *   - the code there is the release's (releaseOf against release-fingerprints.ts);
 *   - the record marks each one deterministic, with its fingerprint.
 *
 *   pnpm check:determinism       (needs `anvil` on PATH)
 */
import { spawn } from "node:child_process";
import * as net from "node:net";
import {
	type Address,
	createPublicClient,
	createTestClient,
	createWalletClient,
	getAddress,
	http,
	type PublicClient,
} from "viem";
import { anvil as anvilChain } from "viem/chains";
import {
	CONTRACT_OF,
	DEPLOYERS,
	ENTRY_POINT_V09,
	LABELS,
	type NetworkClass,
} from "../deploy/config";
import { create3Address } from "../deploy/create3";
import { type DeployContext, deployCore } from "../deploy/deploy";
import {
	impersonate,
	installCreateX,
	installEntryPoint,
} from "../deploy/local";
import { CORE_KEYS } from "../deploy/plan";
import { latestRelease, loadRelease } from "../deploy/release";
import { releaseOf } from "../release-code";

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

async function check(
	network: NetworkClass,
	deployer: Address,
): Promise<string[]> {
	const port = await freePort();
	const anvil = spawn(
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
	const failures: string[] = [];
	try {
		for (let i = 0; ; i++) {
			try {
				await publicClient.getChainId();
				break;
			} catch (error) {
				if (i > 80) throw new Error(`anvil did not start: ${String(error)}`);
				await new Promise((r) => setTimeout(r, 100));
			}
		}
		const quiet = () => undefined;
		await installCreateX(publicClient, testClient, quiet);
		await installEntryPoint(publicClient, testClient, deployer, quiet);
		await impersonate(testClient, deployer);
		const release = loadRelease(latestRelease());
		const ctx: DeployContext = {
			publicClient,
			walletClient: createWalletClient({ chain, transport, account: deployer }),
			deployer,
			network,
			classDeployer: deployer,
			record: { chainId: 31337, deployer, contracts: {}, upgrades: [] },
			log: quiet,
		};
		await deployCore(ctx, release, {
			entryPoint: ENTRY_POINT_V09,
			roleAdmin: deployer,
			defaultFeeWei: 0n,
			postOpGasAllowance: 0,
			penaltyBps: 0,
		});
		for (const key of CORE_KEYS) {
			const deployed = ctx.record.contracts[key];
			const want = create3Address(deployer, LABELS[key]);
			if (!deployed || getAddress(deployed.address) !== want) {
				failures.push(
					`${network} ${key}: deployed at ${deployed?.address}, CREATE3 math says ${want}`,
				);
				continue;
			}
			const code = await publicClient.getCode({ address: want });
			const match = code
				? releaseOf(CONTRACT_OF[key], code, want, release.version)
				: undefined;
			if (match?.release !== release.version)
				failures.push(
					`${network} ${key} at ${want}: code is ${match ? match.release : "no release"}'s, not ${release.version}'s`,
				);
			if (
				!deployed.deterministic ||
				deployed.fingerprint !== match?.fingerprint
			)
				failures.push(
					`${network} ${key}: the record does not mark it deterministic with fingerprint ${match?.fingerprint}`,
				);
			if (!failures.length)
				console.log(
					`OK ${network} ${key.padEnd(24)} ${want}  ${release.version}`,
				);
		}
	} finally {
		anvil.kill();
	}
	return failures;
}

async function main(): Promise<void> {
	const failures: string[] = [];
	for (const network of ["local", "testnet", "mainnet"] as const) {
		const deployer = DEPLOYERS[network];
		if (!deployer) {
			console.log(`skip ${network}: canonical deployer not configured`);
			continue;
		}
		failures.push(...(await check(network, deployer)));
	}
	if (failures.length) {
		console.error(`DETERMINISM FAILURE:\n  ${failures.join("\n  ")}`);
		process.exit(1);
	}
}

main().catch((error: unknown) => {
	console.error(error);
	process.exit(1);
});
