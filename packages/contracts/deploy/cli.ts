/**
 * giano-deploy — deploys the Giano contracts with CREATE3 through CreateX.
 *
 *   pnpm deploy:cli addresses
 *   pnpm deploy:cli core     --rpc <url> --role-admin <0x…> [--release vN] [paymaster options]
 *                            [--chain <profile> | --network mainnet|testnet] [--allow-deviation]
 *   pnpm deploy:cli testing  --rpc <url> --holder <0x…> --owner <0x…> [--fund-eth <n>]
 *   pnpm deploy:cli upgrade  --rpc <url> --contract paymaster|wallet [--release vN] [--execute]
 *                            [--timelock <0x…> [--salt <0x…>] [--safe-json <file>]]
 *   pnpm deploy:cli timelock --rpc <url> --proposer <safe> [--proposer …] [--executor <0x…> …]
 *                            --min-delay <dur> --delay <function>=<dur> … [--release vN]
 *   pnpm deploy:cli handoff  --rpc <url> --timelock <0x…> [--execute] [--safe-json <file>]
 *   pnpm deploy:cli p256     --rpc <url>
 *   pnpm deploy:cli install-createx | install-entrypoint --rpc <url>      (local chains only)
 *
 * Network class: local chains (31337/31338) are `local`. Any other chain takes its class, and any
 * address overrides, from --chain <profile> (deploy/chains/), else from the committed profile with
 * its chain id, else from --network. The class picks the canonical deployer whose CREATE3 addresses
 * are expected (deploy/config.ts DEPLOYERS); a class whose deployer is not configured yet is
 * planned but never signed for.
 *
 * Signing: DEPLOYER_PRIVATE_KEY, or --impersonate on a local chain. A key that is not the class's
 * canonical deployer deploys at its own CREATE3 addresses: every such contract is a deviation. On a
 * mainnet `core` refuses any deviation (an override, another key, a contract recorded elsewhere)
 * unless --allow-deviation is passed; this command has no prompt, so prefer the guided wizard
 * (deploy/guided.ts), which shows the deviations and asks for a typed confirmation. Without a key,
 * `core` and `testing` only verify: every contract must already be in place with a release's code,
 * and nothing is sent. The canonical deployer keys are development-team keys kept in 1Password
 * (docs/key-ceremony.md): load one into this shell's environment only, never into a file or a
 * client's configuration.
 * `upgrade --execute` sends the paymaster's upgradeToAndCall from UPGRADER_PRIVATE_KEY;
 * without --execute it prints the calldata for whoever holds UPGRADER_ROLE. With --timelock it
 * prints the timelock proposal instead (schedule / execute / cancel calldata, and with --safe-json
 * a Safe Transaction Builder file for the proposer Safe).
 *
 * Timelock (G9): `timelock` deploys a GianoTimelock with one delay per timelocked paymaster
 * function (timelock.ts lists them; durations like 7d or 12h). It signs with
 * ROLE_ADMIN_PRIVATE_KEY, or --impersonate --role-admin <0x…> on a local chain. `handoff` gives the
 * timelock every timelocked role and takes them from every other holder, renouncing the sender's
 * ROLE_ADMIN last. Without --execute it prints the calls (with --safe-json it also writes them as
 * a Safe batch, for a ROLE_ADMIN that is itself a Safe); with --execute it sends them from
 * ROLE_ADMIN_PRIVATE_KEY. Only the timelock can undo the hand-off.
 *
 * Every run records what it found and deployed in deployments/<chainId>.json (or --record-dir).
 * Commit that file for any chain other than 31337/31338.
 */

import { writeFileSync } from "node:fs";
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
import { gianoPaymasterAbi, gianoTimelockAbi } from "../generated";
import {
	formatDuration,
	parseDuration,
	safeTransactionBatch,
	TIMELOCKED_FUNCTION_NAMES,
	type TimelockDelays,
	type TimelockedFunctionName,
} from "../timelock";
import {
	classDeployer,
	DEPLOYERS,
	ENTRY_POINT_V09,
	LABELS,
	type LabelKey,
	LOCAL_CHAIN_IDS,
	type NetworkClass,
	type OverrideKey,
	PRODUCTION_CHAIN_IDS,
	PROFILE_NETWORKS,
} from "./config";
import { create3Address } from "./create3";
import {
	type DeployContext,
	deployCore,
	deployTesting,
	deployTimelock,
	deployUpgradeTarget,
	paymasterUpgradeCalldata,
	paymasterUpgradeProposal,
	planHandOff,
} from "./deploy";
import { impersonate, installCreateX, installEntryPoint } from "./local";
import { deployP256Verifier } from "./p256";
import { deviationGate, fixedAddresses, formatPlan, planCore } from "./plan";
import { loadProfile, profileForChain } from "./profiles";
import {
	DEPLOYMENTS_DIR,
	type DeploymentRecord,
	readRecord,
	recordDeviations,
	writeRecord,
} from "./records";
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
		// network class: a committed profile, or the class alone
		chain: { type: "string" },
		network: { type: "string" },
		"allow-deviation": { type: "boolean", default: false },
		// core
		"role-admin": { type: "string" },
		"entry-point": { type: "string", default: ENTRY_POINT_V09 },
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
		// timelock / handoff
		timelock: { type: "string" },
		salt: { type: "string" },
		"safe-json": { type: "string" },
		proposer: { type: "string", multiple: true },
		executor: { type: "string", multiple: true },
		"min-delay": { type: "string" },
		delay: { type: "string", multiple: true },
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

/** `--min-delay` and one `--delay <function>=<duration>` per timelocked paymaster function. */
function timelockDelays(): TimelockDelays {
	const delays: Partial<TimelockDelays> = {
		minDelay: parseDuration(required("min-delay")),
	};
	for (const entry of values.delay ?? []) {
		const [name, duration] = entry.split("=");
		if (!TIMELOCKED_FUNCTION_NAMES.includes(name as TimelockedFunctionName))
			throw new Error(
				`--delay ${entry}: the timelocked functions are ${TIMELOCKED_FUNCTION_NAMES.join(", ")}`,
			);
		delays[name as TimelockedFunctionName] = parseDuration(duration ?? "");
	}
	const missing = TIMELOCKED_FUNCTION_NAMES.filter(
		(name) => delays[name] === undefined,
	);
	if (missing.length)
		throw new Error(
			`every timelocked function needs its own delay; missing --delay for ${missing.join(", ")}`,
		);
	return delays as TimelockDelays;
}

/**
 * The account that holds ROLE_ADMIN before the hand-off: ROLE_ADMIN_PRIVATE_KEY, or on a local
 * chain --impersonate with --role-admin.
 */
async function roleAdminClient(
	chain: Chain,
	transport: Transport,
	local: boolean,
): Promise<WalletClient<Transport, Chain, Account>> {
	if (values.impersonate) {
		localOnly(local, "--impersonate");
		const admin = address("role-admin");
		await impersonate(
			createTestClient({ chain, transport, mode: "anvil" }),
			admin,
		);
		return createWalletClient({ chain, transport, account: admin });
	}
	const key = process.env.ROLE_ADMIN_PRIVATE_KEY;
	if (!key)
		throw new Error(
			"set ROLE_ADMIN_PRIVATE_KEY (the paymaster's current ROLE_ADMIN), or pass --impersonate --role-admin <0x…> on a local chain",
		);
	return createWalletClient({
		chain,
		transport,
		account: privateKeyToAccount(key as `0x${string}`),
	});
}

/** The recorded paymaster proxy, else the class's deterministic one. */
function paymasterProxy(
	record: DeploymentRecord | undefined,
	network: NetworkClass,
	overrides: Partial<Record<OverrideKey, string>> = {},
): Address {
	if (overrides.paymasterProxy) return getAddress(overrides.paymasterProxy);
	if (record?.contracts.paymasterProxy?.address)
		return record.contracts.paymasterProxy.address;
	const deployer = classDeployer(network);
	if (!deployer)
		throw new Error(
			`no paymaster proxy is recorded for this chain and the ${network} canonical deployer is not configured; pass the chain's record (--record-dir)`,
		);
	return create3Address(deployer, LABELS.paymasterProxy);
}

type Network = {
	network: NetworkClass;
	/** The committed profile's id, when the class came from one. */
	profileId?: string;
	overrides: Partial<Record<OverrideKey, string>>;
};

/** The chain's network class and overrides (see the header). */
function resolveNetwork(chainId: number, local: boolean): Network {
	if (local) {
		if (values.chain || values.network)
			throw new Error(
				`chain ${chainId} is a local chain; it is always the local class (no --chain or --network)`,
			);
		return { network: "local", overrides: {} };
	}
	if (values.chain && values.network)
		throw new Error("pass --chain <profile> or --network, not both");
	const selected = values.chain
		? loadProfile({ chain: values.chain })
		: values.network
			? undefined
			: profileForChain(chainId);
	if (selected) {
		if (selected.profile.chainId !== chainId)
			throw new Error(
				`profile ${selected.id} is chain ${selected.profile.chainId}, but the RPC is chain ${chainId}`,
			);
		return {
			network: selected.profile.network,
			profileId: selected.id,
			overrides: selected.profile.addresses ?? {},
		};
	}
	if (!values.network)
		throw new Error(
			`chain ${chainId} has no committed profile; pass --chain <profile> or --network ${PROFILE_NETWORKS.join("|")}`,
		);
	if (!(PROFILE_NETWORKS as readonly string[]).includes(values.network))
		throw new Error(
			`--network is ${PROFILE_NETWORKS.join(" or ")}, not ${values.network}`,
		);
	return { network: values.network as NetworkClass, overrides: {} };
}

function writeSafeJson(contents: unknown): void {
	const file = values["safe-json"];
	if (!file) return;
	writeFileSync(file, `${JSON.stringify(contents, null, 2)}\n`);
	log(`wrote the Safe Transaction Builder batch to ${file}`);
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

/** `verifyOnly`: without a key, run with no signer instead of failing (`core`, `testing`). */
async function deployerContext({
	verifyOnly = false,
}: {
	verifyOnly?: boolean;
} = {}): Promise<
	DeployContext & {
		chainId: number;
		chain: Chain;
		local: boolean;
		target: Network;
	}
> {
	const { chainId, chain, transport, publicClient, local } = await connect();
	const target = resolveNetwork(chainId, local);
	const canonical = classDeployer(target.network);
	let walletClient: WalletClient<Transport, Chain, Account> | undefined;
	if (values.impersonate) {
		localOnly(local, "--impersonate");
		await impersonate(
			createTestClient({ chain, transport, mode: "anvil" }),
			DEPLOYERS.local,
		);
		walletClient = createWalletClient({
			chain,
			transport,
			account: DEPLOYERS.local,
		});
	} else {
		const key = process.env.DEPLOYER_PRIVATE_KEY;
		if (key)
			walletClient = createWalletClient({
				chain,
				transport,
				account: privateKeyToAccount(key as `0x${string}`),
			});
		else if (!verifyOnly)
			throw new Error(
				`set DEPLOYER_PRIVATE_KEY (the ${target.network} canonical deployer, from its 1Password item), or pass --impersonate on a local chain`,
			);
	}
	// Without a key, the class's canonical deployer is who the addresses are derived from.
	const deployer = walletClient?.account.address ?? canonical;
	log(
		`network ${target.network}${target.profileId ? ` (profile ${target.profileId})` : ""}; canonical deployer ${canonical ?? "NOT CONFIGURED"}; ${walletClient ? `signer ${walletClient.account.address}${values.impersonate ? " (impersonated)" : ""}` : "no key: verify only"}`,
	);
	if (!deployer)
		throw new Error(
			`the ${target.network} canonical deployer is not configured (DEPLOYERS.${target.network} in deploy/config.ts), so there are no addresses to verify`,
		);
	// `core` prints its plan first and refuses there (planOrRefuse); nothing else signs for a class
	// without a canonical deployer either.
	if (walletClient && !canonical && command !== "core")
		throw new Error(
			`the ${target.network} canonical deployer is not configured (DEPLOYERS.${target.network} in deploy/config.ts); refusing to sign for chain ${chainId}`,
		);
	const record = readRecord(
		chainId,
		undefined,
		values["record-dir"] ?? DEPLOYMENTS_DIR,
	);
	return {
		publicClient,
		walletClient,
		deployer,
		network: target.network,
		record,
		log,
		chainId,
		chain,
		local,
		target,
	};
}

/**
 * Prints the plan and refuses what must not be signed: a blocker (an override without release
 * code, foreign code, a class deployer that is not configured), or a mainnet deviation without
 * --allow-deviation. Returns the addresses deployCore must use rather than derive.
 */
async function planOrRefuse(
	ctx: Awaited<ReturnType<typeof deployerContext>>,
): Promise<
	Partial<
		Record<
			| "walletImplementation"
			| "factory"
			| "paymasterImplementation"
			| "paymasterProxy",
			Address
		>
	>
> {
	const plan = await planCore(ctx.publicClient, {
		network: ctx.network,
		signer: ctx.walletClient?.account.address ?? null,
		overrides: ctx.target.overrides,
		record: ctx.record,
	});
	for (const line of formatPlan(plan)) log(line);
	if (plan.blockers.length)
		throw new Error(`refusing to deploy:\n  ${plan.blockers.join("\n  ")}`);
	const gate = deviationGate(
		plan,
		ctx.target.profileId ?? `chain-${ctx.chainId}`,
		{
			interactive: false,
			allowDeviation: values["allow-deviation"],
		},
	);
	if (gate.kind === "refuse")
		throw new Error(`${gate.reason} Pass --allow-deviation to accept them.`);
	if (plan.deviations.length && ctx.walletClient)
		recordDeviations(
			ctx.record,
			plan.deviations,
			plan.network === "mainnet" && values["allow-deviation"],
		);
	if (ctx.walletClient) ctx.record.deployer = ctx.walletClient.account.address;
	return fixedAddresses(plan);
}

function signer(ctx: DeployContext): WalletClient<Transport, Chain, Account> {
	if (!ctx.walletClient) throw new Error(`\`${command}\` needs a signer`);
	return ctx.walletClient;
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
			for (const network of ["mainnet", "testnet", "local"] as const) {
				const deployer = classDeployer(network);
				log(`${network}: canonical deployer ${deployer ?? "NOT CONFIGURED"}`);
				if (!deployer) continue;
				for (const [key, label] of Object.entries(LABELS) as [
					LabelKey,
					string,
				][]) {
					log(
						`  ${key.padEnd(24)} ${create3Address(deployer, label)}  (${label})`,
					);
				}
			}
			log(
				"These are the deterministic addresses; a chain profile may override single contracts (deploy/chains/).",
			);
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
				await installEntryPoint(publicClient, testClient, DEPLOYERS.local, log);
			return;
		}
		case "p256": {
			const ctx = await deployerContext();
			await deployP256Verifier(ctx.publicClient, signer(ctx), log);
			return;
		}
		case "core": {
			const ctx = await deployerContext({ verifyOnly: true });
			const fixed = await planOrRefuse(ctx);
			await deployCore(
				ctx,
				release(ctx.local),
				{
					entryPoint: address("entry-point"),
					roleAdmin: address("role-admin"),
					defaultFeeWei: BigInt(required("default-fee-wei")),
					postOpGasAllowance: Number(required("post-op-gas-allowance")),
					penaltyBps: Number(required("penalty-bps")),
				},
				fixed,
			);
			save(ctx);
			return;
		}
		case "testing": {
			const ctx = await deployerContext({ verifyOnly: true });
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
			const proxy = paymasterProxy(
				ctx.record,
				ctx.network,
				ctx.target.overrides,
			);
			const calldata = paymasterUpgradeCalldata(target.address);
			if (values.timelock) {
				const proposal = await paymasterUpgradeProposal(
					ctx.publicClient,
					address("timelock"),
					proxy,
					target.address,
					values.salt as `0x${string}` | undefined,
				);
				log(
					`Timelock proposal ${proposal.id} (delay ${formatDuration(proposal.delay)}):\n  1. a proposer sends to ${proposal.timelock}:\n     ${proposal.schedule}\n  2. after the delay, an executor sends to ${proposal.timelock}:\n     ${proposal.execute}\n  To cancel while it is pending, a canceller sends:\n     ${proposal.cancel}`,
				);
				writeSafeJson(
					safeTransactionBatch(proposal, {
						chainId: ctx.chainId,
						step: "schedule",
						description: `Upgrade the Giano paymaster ${proxy} to ${target.address}`,
					}),
				);
				return;
			}
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
				chain: ctx.chain,
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
		case "timelock": {
			const { chainId, chain, transport, publicClient, local } =
				await connect();
			const walletClient = await roleAdminClient(chain, transport, local);
			const target = resolveNetwork(chainId, local);
			const record = readRecord(
				chainId,
				undefined,
				values["record-dir"] ?? DEPLOYMENTS_DIR,
			);
			const params = {
				paymaster: paymasterProxy(record, target.network, target.overrides),
				proposers: (values.proposer ?? []).map((p) => getAddress(p)),
				executors: (values.executor ?? []).map((e) => getAddress(e)),
				delays: timelockDelays(),
			};
			for (const proposer of params.proposers) {
				const code = await publicClient.getCode({ address: proposer });
				if (!code || code === "0x")
					log(
						`  ⚠ proposer ${proposer} has no code: an EOA proposer is one key that can queue anything. Use a Safe outside local testing (G9 R3).`,
					);
			}
			log(
				`timelock for ${params.paymaster}: minDelay ${formatDuration(params.delays.minDelay)}; ${TIMELOCKED_FUNCTION_NAMES.map((n) => `${n} ${formatDuration(params.delays[n])}`).join(", ")}`,
			);
			const deployed = await deployTimelock(
				{ publicClient, walletClient, log },
				release(local),
				params,
			);
			record.timelock = {
				...deployed,
				proposers: params.proposers,
				executors: params.executors,
				delays: params.delays,
			};
			log(
				`recorded in ${writeRecord(record, values["record-dir"] ?? DEPLOYMENTS_DIR)}`,
			);
			log(
				`Next: \`handoff --timelock ${deployed.address}\` gives it the timelocked roles; then run doctor chain --timelock ${deployed.address}.`,
			);
			return;
		}
		case "handoff": {
			const { chainId, chain, transport, publicClient, local } =
				await connect();
			const target = resolveNetwork(chainId, local);
			const record = readRecord(
				chainId,
				undefined,
				values["record-dir"] ?? DEPLOYMENTS_DIR,
			);
			const proxy = paymasterProxy(record, target.network, target.overrides);
			const timelock = address("timelock");
			// A typo here would hand the paymaster to an address nobody controls, irreversibly.
			try {
				await publicClient.readContract({
					address: timelock,
					abi: gianoTimelockAbi,
					functionName: "getEffectiveDelay",
					args: [proxy, "0x00000000"],
				});
			} catch {
				throw new Error(
					`${timelock} is not a GianoTimelock on chain ${chainId}; refusing to hand it the paymaster`,
				);
			}
			const walletClient =
				values.execute || values.impersonate
					? await roleAdminClient(chain, transport, local)
					: undefined;
			const from = walletClient
				? walletClient.account.address
				: address("role-admin");
			const calls = await planHandOff(publicClient, proxy, timelock, from);
			if (calls.length === 0) {
				log(
					`nothing to do: ${timelock} already holds every timelocked role alone`,
				);
				return;
			}
			log(`hand-off of ${proxy} to ${timelock}, sent by ${from}:`);
			for (const [i, call] of calls.entries())
				log(`  ${i + 1}. ${call.description}\n     ${call.data}`);
			writeSafeJson({
				version: "1.0",
				chainId: String(chainId),
				createdAt: Date.now(),
				meta: {
					name: "Giano paymaster timelock hand-off",
					description: `Give ${timelock} every timelocked role on ${proxy}; the sender renounces ROLE_ADMIN last.`,
				},
				transactions: calls.map((call) => ({
					to: proxy,
					value: "0",
					data: call.data,
				})),
			});
			if (!values.execute || !walletClient) {
				log(
					"Not sent. Rerun with --execute to send these from ROLE_ADMIN_PRIVATE_KEY.",
				);
				return;
			}
			for (const call of calls) {
				const hash = await walletClient.sendTransaction({
					to: proxy,
					data: call.data,
				});
				const receipt = await publicClient.waitForTransactionReceipt({ hash });
				if (receipt.status !== "success")
					throw new Error(`${call.description} reverted (${hash})`);
				log(`  + ${call.description}  ${hash}`);
			}
			const remaining = await planHandOff(publicClient, proxy, timelock, from);
			if (remaining.length)
				throw new Error(
					`the hand-off did not complete: ${remaining.map((c) => c.description).join("; ")}`,
				);
			log(
				`${timelock} now holds every timelocked role alone. Verify with doctor chain --timelock ${timelock}.`,
			);
			return;
		}
		default:
			console.error(
				"usage: giano-deploy addresses | core | testing | upgrade | timelock | handoff | p256 | install-createx | install-entrypoint  (see deploy/cli.ts)",
			);
			process.exit(2);
	}
}

main().catch((error: unknown) => {
	console.error(error instanceof Error ? error.message : error);
	process.exit(1);
});
