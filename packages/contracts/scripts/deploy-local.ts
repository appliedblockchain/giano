/**
 * One command to give a local anvil chain everything Giano expects of a public chain, then the
 * canonical contracts and the test fixtures at their canonical addresses:
 *
 *   CreateX, EntryPoint v0.7, the P-256 verifier, the wallet factory + implementation, the paymaster
 *   (proxy initialised with ROLE_ADMIN on anvil account 0), PrivateERC20 and PermissivePaymaster.
 *
 * The canonical deployer is impersonated, so no key is involved. Writes deployments/<chainId>.json
 * (gitignored for local chains). Provisioning the paymaster (roles, stake, tenants) is separate:
 * `pnpm provision:paymaster`, or e2e/devnet/generate-state.mjs, which does all of it.
 *
 *   RPC_URL=http://127.0.0.1:8545 pnpm local:deploy        (RPC_URL defaults to that)
 *   PAYMASTER_FUND_ETH=500                                  (the test paymaster's deposit)
 */
import {
	createPublicClient,
	createTestClient,
	createWalletClient,
	defineChain,
	http,
	type PublicClient,
	parseEther,
} from "viem";
import {
	CANONICAL_DEPLOYER,
	ENTRY_POINT_V07,
	LOCAL_CHAIN_IDS,
} from "../deploy/config";
import {
	type DeployContext,
	deployCore,
	deployTesting,
} from "../deploy/deploy";
import {
	impersonate,
	installCreateX,
	installEntryPoint,
} from "../deploy/local";
import { deployP256Verifier } from "../deploy/p256";
import { readRecord, writeRecord } from "../deploy/records";
import { latestRelease, loadRelease } from "../deploy/release";

/** Anvil's first default account. Never used anywhere real. */
const ANVIL_ACCOUNT_0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

const log = (line: string) => console.log(line);

async function main(): Promise<void> {
	const url = process.env.RPC_URL ?? "http://127.0.0.1:8545";
	const transport = http(url);
	const chainId = await createPublicClient({ transport }).getChainId();
	if (!(LOCAL_CHAIN_IDS as readonly number[]).includes(chainId))
		throw new Error(
			`chain ${chainId} is not a local chain (${LOCAL_CHAIN_IDS.join(", ")})`,
		);
	const chain = defineChain({
		id: chainId,
		name: `local-${chainId}`,
		nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
		rpcUrls: { default: { http: [url] } },
	});
	const publicClient = createPublicClient({ chain, transport }) as PublicClient;
	const testClient = createTestClient({ chain, transport, mode: "anvil" });
	const release = loadRelease(process.env.RELEASE || latestRelease());
	log(
		`Local deployment on chain ${chainId} (${url}), release ${release.version}, deployer ${CANONICAL_DEPLOYER} (impersonated)`,
	);

	await installCreateX(publicClient, testClient, log);
	// Sent by the impersonated deployer, so anvil account 0 (the operator) keeps a clean nonce.
	await installEntryPoint(publicClient, testClient, CANONICAL_DEPLOYER, log);
	await impersonate(testClient, CANONICAL_DEPLOYER);
	const ctx: DeployContext = {
		publicClient,
		walletClient: createWalletClient({
			chain,
			transport,
			account: CANONICAL_DEPLOYER,
		}),
		deployer: CANONICAL_DEPLOYER,
		record: readRecord(chainId, CANONICAL_DEPLOYER),
		log,
	};
	await deployP256Verifier(publicClient, ctx.walletClient, log);
	await deployCore(ctx, release, {
		entryPoint: ENTRY_POINT_V07,
		roleAdmin: ANVIL_ACCOUNT_0,
		defaultFeeWei: 100_000_000_000_000n,
		postOpGasAllowance: 40_000,
		penaltyBps: 1000,
	});
	await deployTesting(ctx, release, {
		holder: ANVIL_ACCOUNT_0,
		owner: ANVIL_ACCOUNT_0,
		entryPoint: ENTRY_POINT_V07,
		fundWei: parseEther(process.env.PAYMASTER_FUND_ETH ?? "500"),
	});
	log(`recorded in ${writeRecord(ctx.record)}`);
}

main().catch((error: unknown) => {
	console.error(error instanceof Error ? error.message : error);
	process.exit(1);
});
