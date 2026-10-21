/**
 * giano-deploy — deploys the canonical contracts with CREATE3 through CreateX.
 *
 *   pnpm deploy:cli addresses
 *   pnpm deploy:cli core     --rpc <url> --role-admin <0x…> [--release vN] [paymaster options]
 *   pnpm deploy:cli testing  --rpc <url> --holder <0x…> --owner <0x…> [--fund-eth <n>]
 *   pnpm deploy:cli upgrade  --rpc <url> --contract paymaster|wallet [--release vN] [--execute]
 *   pnpm deploy:cli p256     --rpc <url>
 *   pnpm deploy:cli install-createx | install-entrypoint --rpc <url>      (local chains only)
 *
 * Signing: DEPLOYER_PRIVATE_KEY (must be the canonical deployer), or --impersonate on a local
 * chain. `upgrade --execute` sends the paymaster's upgradeToAndCall from UPGRADER_PRIVATE_KEY;
 * without --execute it prints the calldata for whoever holds UPGRADER_ROLE (the timelock).
 *
 * Every run records what it found and deployed in deployments/<chainId>.json (or --record-dir).
 * Commit that file for any chain other than 31337/31338.
 */
import { parseArgs } from "node:util";
import {
	type Account,
	type Address,
	type Chain,
	createPublicClient,
	createTestClient,
	createWalletClient,
	defineChain,
	getAddress,
	http,
	type PublicClient,
	parseEther,
	type Transport,
	type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { gianoPaymasterAbi } from "../generated";
import {
	CANONICAL_DEPLOYER,
	DEPLOYER_IS_PLACEHOLDER,
	ENTRY_POINT_V07,
	LABELS,
	type LabelKey,
	LOCAL_CHAIN_IDS,
	PRODUCTION_CHAIN_IDS,
} from "./config";
import { create3Address } from "./create3";
import {
	type DeployContext,
	deployCore,
	deployTesting,
	deployUpgradeTarget,
	paymasterUpgradeCalldata,
} from "./deploy";
import { impersonate, installCreateX, installEntryPoint } from "./local";
import { deployP256Verifier } from "./p256";
import { DEPLOYMENTS_DIR, readRecord, writeRecord } from "./records";
import {
	DEV_RELEASE,
	latestRelease,
	loadRelease,
	type Release,
} from "./release";

const { positionals, values } = parseArgs({
	allowPositionals: true,
	options: {
		rpc: { type: "string" },
		release: { type: "string" },
		impersonate: { type: "boolean", default: false },
		"record-dir": { type: "string" },
		// core
		"role-admin": { type: "string" },
		"entry-point": { type: "string", default: ENTRY_POINT_V07 },
		"default-fee-wei": { type: "string", default: "100000000000000" }, // 0.0001 ETH per sponsored op
		// Gas units charged for settlement's own gas: ~9.7k warm, ~49k cold (test/GianoPaymaster/Gas.t.sol).
		"post-op-gas-allowance": { type: "string", default: "40000" },
		// Basis points of the execution gas limits charged against the EntryPoint's unused-gas penalty.
		"penalty-bps": { type: "string", default: "1000" },
		// testing
		holder: { type: "string" },
		owner: { type: "string" },
		"fund-eth": { type: "string", default: "0" },
		// upgrade
		contract: { type: "string" },
		execute: { type: "boolean", default: false },
	},
});

const log = (line: string) => console.log(line);
const [command] = positionals;

function required(name: keyof typeof values): string {
	const value = values[name];
	if (typeof value !== "string" || value === "")
		throw new Error(`--${name} is required for \`${command}\``);
	return value;
}

function address(name: keyof typeof values): Address {
	return getAddress(required(name));
}

async function connect(): Promise<{
	chainId: number;
	chain: Chain;
	transport: Transport;
	publicClient: PublicClient;
	local: boolean;
}> {
	const url = required("rpc");
	const transport = http(url);
	const chainId = await createPublicClient({ transport }).getChainId();
	const chain = defineChain({
		id: chainId,
		name: `chain-${chainId}`,
		nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
		rpcUrls: { default: { http: [url] } },
	});
	const publicClient = createPublicClient({ chain, transport }) as PublicClient;
	const local = (LOCAL_CHAIN_IDS as readonly number[]).includes(chainId);
	log(`chain ${chainId} via ${url}${local ? " (local)" : ""}`);
	return { chainId, chain, transport, publicClient, local };
}

function localOnly(local: boolean, what: string): void {
	if (!local)
		throw new Error(
			`${what} is for local chains (${LOCAL_CHAIN_IDS.join(", ")}) only`,
		);
}

async function deployerContext(): Promise<
	DeployContext & { chainId: number; local: boolean }
> {
	const { chainId, chain, transport, publicClient, local } = await connect();
	if (DEPLOYER_IS_PLACEHOLDER && !local) {
		throw new Error(
			`CANONICAL_DEPLOYER is still the placeholder (deploy/config.ts); set the real deployer before deploying to chain ${chainId}`,
		);
	}
	let walletClient: WalletClient<Transport, Chain, Account>;
	if (values.impersonate) {
		localOnly(local, "--impersonate");
		await impersonate(
			createTestClient({ chain, transport, mode: "anvil" }),
			CANONICAL_DEPLOYER,
		);
		walletClient = createWalletClient({
			chain,
			transport,
			account: CANONICAL_DEPLOYER,
		});
	} else {
		const key = process.env.DEPLOYER_PRIVATE_KEY;
		if (!key)
			throw new Error(
				"set DEPLOYER_PRIVATE_KEY (the canonical deployer), or pass --impersonate on a local chain",
			);
		walletClient = createWalletClient({
			chain,
			transport,
			account: privateKeyToAccount(key as `0x${string}`),
		});
	}
	log(
		`deployer ${CANONICAL_DEPLOYER}${values.impersonate ? " (impersonated)" : ""}`,
	);
	const record = readRecord(
		chainId,
		CANONICAL_DEPLOYER,
		values["record-dir"] ?? DEPLOYMENTS_DIR,
	);
	return {
		publicClient,
		walletClient,
		deployer: CANONICAL_DEPLOYER,
		record,
		log,
		chainId,
		local,
	};
}

/** --release (default: the latest). `dev` — the working tree, unreleased — only on a local chain. */
function release(local: boolean): Release {
	const version = values.release ?? latestRelease();
	if (version === DEV_RELEASE) localOnly(local, "--release dev");
	const loaded = loadRelease(version);
	log(`release ${loaded.version}`);
	return loaded;
}

function save(ctx: DeployContext): void {
	log(
		`recorded in ${writeRecord(ctx.record, values["record-dir"] ?? DEPLOYMENTS_DIR)}`,
	);
}

async function main(): Promise<void> {
	switch (command) {
		case "addresses": {
			log(
				`deployer ${CANONICAL_DEPLOYER}${DEPLOYER_IS_PLACEHOLDER ? "  ⚠ placeholder" : ""}`,
			);
			for (const [key, label] of Object.entries(LABELS) as [
				LabelKey,
				string,
			][]) {
				log(
					`  ${key.padEnd(24)} ${create3Address(CANONICAL_DEPLOYER, label)}  (${label})`,
				);
			}
			return;
		}
		case "install-createx":
		case "install-entrypoint": {
			const { chain, transport, publicClient, local } = await connect();
			localOnly(local, command);
			const testClient = createTestClient({ chain, transport, mode: "anvil" });
			if (command === "install-createx")
				await installCreateX(publicClient, testClient, log);
			else
				await installEntryPoint(
					publicClient,
					testClient,
					CANONICAL_DEPLOYER,
					log,
				);
			return;
		}
		case "p256": {
			const ctx = await deployerContext();
			await deployP256Verifier(ctx.publicClient, ctx.walletClient, log);
			return;
		}
		case "core": {
			const ctx = await deployerContext();
			await deployCore(ctx, release(ctx.local), {
				entryPoint: address("entry-point"),
				roleAdmin: address("role-admin"),
				defaultFeeWei: BigInt(required("default-fee-wei")),
				postOpGasAllowance: Number(required("post-op-gas-allowance")),
				penaltyBps: Number(required("penalty-bps")),
			});
			save(ctx);
			return;
		}
		case "testing": {
			const ctx = await deployerContext();
			if ((PRODUCTION_CHAIN_IDS as readonly number[]).includes(ctx.chainId)) {
				throw new Error(
					`chain ${ctx.chainId} is a production chain; the test fixtures must never be deployed there (R-29)`,
				);
			}
			await deployTesting(ctx, release(ctx.local), {
				holder: address("holder"),
				owner: address("owner"),
				entryPoint: address("entry-point"),
				fundWei: parseEther(required("fund-eth")),
			});
			save(ctx);
			return;
		}
		case "upgrade": {
			const ctx = await deployerContext();
			const which = required("contract");
			if (which !== "paymaster" && which !== "wallet")
				throw new Error("--contract is paymaster or wallet");
			const target = await deployUpgradeTarget(
				ctx,
				release(ctx.local),
				which === "paymaster"
					? "paymasterImplementation"
					: "walletImplementation",
			);
			save(ctx);
			if (which === "wallet") {
				log(
					`Accounts move to ${target.address} through their own UUPS upgrade (upgradeToAndCall, signed by an owner).`,
				);
				return;
			}
			const proxy =
				ctx.record.contracts.paymasterProxy?.address ??
				create3Address(CANONICAL_DEPLOYER, LABELS.paymasterProxy);
			const calldata = paymasterUpgradeCalldata(target.address);
			if (!values.execute) {
				log(
					`To upgrade, the UPGRADER_ROLE holder sends to ${proxy}:\n  ${calldata}`,
				);
				return;
			}
			const key = process.env.UPGRADER_PRIVATE_KEY;
			if (!key)
				throw new Error(
					"--execute needs UPGRADER_PRIVATE_KEY (an account holding UPGRADER_ROLE)",
				);
			const upgrader = createWalletClient({
				chain: ctx.walletClient.chain,
				transport: http(required("rpc")),
				account: privateKeyToAccount(key as `0x${string}`),
			});
			const role = await ctx.publicClient.readContract({
				address: proxy,
				abi: gianoPaymasterAbi,
				functionName: "UPGRADER_ROLE",
			});
			const allowed = await ctx.publicClient.readContract({
				address: proxy,
				abi: gianoPaymasterAbi,
				functionName: "hasRole",
				args: [role, upgrader.account.address],
			});
			if (!allowed)
				throw new Error(
					`${upgrader.account.address} does not hold UPGRADER_ROLE on ${proxy}`,
				);
			const hash = await upgrader.sendTransaction({
				to: proxy,
				data: calldata,
			});
			const receipt = await ctx.publicClient.waitForTransactionReceipt({
				hash,
			});
			if (receipt.status !== "success")
				throw new Error(`upgradeToAndCall reverted (${hash})`);
			ctx.record.contracts.paymasterImplementation = target;
			save(ctx);
			log(`Upgraded ${proxy} to ${target.address} (${hash})`);
			return;
		}
		default:
			console.error(
				"usage: giano-deploy addresses | core | testing | upgrade | p256 | install-createx | install-entrypoint  (see deploy/cli.ts)",
			);
			process.exit(2);
	}
}

main().catch((error: unknown) => {
	console.error(error instanceof Error ? error.message : error);
	process.exit(1);
});
