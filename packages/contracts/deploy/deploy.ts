/**
 * The deployments themselves, shared by the CLI (deploy/cli.ts) and the generators that deploy to a
 * throwaway anvil (scripts/generate-canonical.ts). Every canonical contract goes through CreateX
 * with CREATE3 (deploy/create3.ts); everything is idempotent — a contract already at its address is
 * checked and recorded, never redeployed.
 */
import {
	type Account,
	type Address,
	type Chain,
	concat,
	encodeAbiParameters,
	encodeFunctionData,
	getAddress,
	type Hex,
	keccak256,
	type PublicClient,
	parseAbiParameters,
	type Transport,
	type WalletClient,
	zeroAddress,
} from "viem";
import { CANONICAL_CODE, canonicalCodeAt } from "../canonical";
import { gianoPaymasterAbi, gianoTimelockAbi } from "../generated";
import {
	delayPolicyProblems,
	encodeTimelockProposal,
	paymasterFunctionDelays,
	TIMELOCKED_ROLES,
	type TimelockDelays,
} from "../timelock";
import { LABELS, type LabelKey, upgradeLabel } from "./config";
import {
	CREATEX_ADDRESS,
	create3Address,
	create3Salt,
	guardedSalt,
} from "./create3";
import { createxAbi } from "./createx";
import type { DeployedContract, DeploymentRecord } from "./records";
import { DEV_RELEASE, type Release } from "./release";

export type DeployContext = {
	publicClient: PublicClient;
	/**
	 * Signs as the canonical deployer. Absent, the run is verify-only: a contract already in place is
	 * checked against the code a release leaves there, and a missing one fails without sending
	 * anything — adopting a chain is a DevOps operation with the deployer key (docs/key-ceremony.md).
	 */
	walletClient?: WalletClient<Transport, Chain, Account>;
	/** The canonical deployer; the wallet client's account must be this address. */
	deployer: Address;
	record: DeploymentRecord;
	log: (line: string) => void;
	/** Persist each completed contract, so interrupted runs retain transaction provenance. */
	onRecord?: () => void;
};

export type PaymasterParams = {
	entryPoint: Address;
	/** Sole ROLE_ADMIN. A TimelockController in production. */
	roleAdmin: Address;
	defaultFeeWei: bigint;
	postOpGasAllowance: number;
	penaltyBps: number;
};

export type TestingParams = {
	/** Receives PrivateERC20's initial supply. */
	holder: Address;
	/** Owns PermissivePaymaster (stake and deposit withdrawals). */
	owner: Address;
	entryPoint: Address;
	/** Wei forwarded to PermissivePaymaster's EntryPoint deposit; 0 skips funding. */
	fundWei: bigint;
};

function assertDeployerAccount(ctx: DeployContext): void {
	// CreateX only honours a permissioned salt from the address in its first 20 bytes. From any
	// other sender it treats the salt as ordinary and deploys somewhere else, unprotected — so a
	// wrong key must stop us here, before anything is sent.
	if (!ctx.walletClient) return;
	if (
		getAddress(ctx.walletClient.account.address) !== getAddress(ctx.deployer)
	) {
		throw new Error(
			`the signing account ${ctx.walletClient.account.address} is not the canonical deployer ${ctx.deployer}`,
		);
	}
}

async function assertCreateX(ctx: DeployContext): Promise<void> {
	const code = await ctx.publicClient.getCode({ address: CREATEX_ADDRESS });
	if (!code || code === "0x") {
		throw new Error(
			`CreateX is not deployed at ${CREATEX_ADDRESS} on this chain. On a local chain run \`install-createx\`; elsewhere follow github.com/pcaversaccio/createx`,
		);
	}
}

async function codehashAt(
	ctx: DeployContext,
	address: Address,
): Promise<Hex | null> {
	const code = await ctx.publicClient.getCode({ address });
	return code && code !== "0x" ? keccak256(code) : null;
}

/**
 * Deploys `initCode` under `label` with CREATE3, optionally calling `init` on it in the same
 * transaction. Returns the contract whether it was deployed now or found already in place.
 */
export async function deployLabel(
	ctx: DeployContext,
	{
		label,
		release,
		initCode,
		init,
	}: { label: string; release: string; initCode: Hex; init?: Hex },
): Promise<DeployedContract> {
	assertDeployerAccount(ctx);
	await assertCreateX(ctx);
	const salt = create3Salt(ctx.deployer, label);
	const address = create3Address(ctx.deployer, label);

	// The local address math must agree with CreateX's own; a disagreement means create3.ts is wrong
	// and every address it ever produced is suspect.
	const onChain = (await ctx.publicClient.readContract({
		address: CREATEX_ADDRESS,
		abi: createxAbi,
		functionName: "computeCreate3Address",
		args: [guardedSalt(ctx.deployer, salt)],
	})) as Address;
	if (getAddress(onChain) !== address)
		throw new Error(
			`create3.ts computed ${address} for ${label} but CreateX says ${onChain}`,
		);

	const existing = await codehashAt(ctx, address);
	if (existing) {
		// Verify-only, the address alone proves nothing (canonical.ts): the code there must be what a
		// release puts at that address. Test fixtures have no canonical code to compare with.
		if (
			!ctx.walletClient &&
			Object.keys(CANONICAL_CODE).some(
				(a) => a.toLowerCase() === address.toLowerCase(),
			) &&
			!canonicalCodeAt(address, existing)
		)
			throw new Error(
				`${label} at ${address} holds code ${existing}, which no Giano release puts there`,
			);
		ctx.log(`  = ${label.padEnd(28)} ${address} (already deployed)`);
		return { address, label, release, codehash: existing };
	}

	const walletClient = ctx.walletClient;
	if (!walletClient)
		throw new Error(
			`${label} is not deployed at ${address} on this chain, and this run has no deployer key, so it only verifies. ` +
				"Adopting a chain needs the canonical deployer, which Applied Blockchain DevOps operate (docs/key-ceremony.md); " +
				"never put that key in a client deployment.",
		);

	const { request, result } = init
		? await ctx.publicClient.simulateContract({
				account: walletClient.account,
				address: CREATEX_ADDRESS,
				abi: createxAbi,
				functionName: "deployCreate3AndInit",
				args: [
					salt,
					initCode,
					init,
					{ constructorAmount: 0n, initCallAmount: 0n },
				],
			})
		: await ctx.publicClient.simulateContract({
				account: walletClient.account,
				address: CREATEX_ADDRESS,
				abi: createxAbi,
				functionName: "deployCreate3",
				args: [salt, initCode],
			});
	if (getAddress(result as Address) !== address)
		throw new Error(
			`CreateX would deploy ${label} at ${result as Address}, expected ${address}`,
		);

	const transactionHash = await walletClient.writeContract(request);
	ctx.log(`  → ${label}: submitted ${transactionHash}; waiting for receipt`);
	const receipt = await ctx.publicClient.waitForTransactionReceipt({
		hash: transactionHash,
	});
	if (receipt.status !== "success")
		throw new Error(`deploying ${label} reverted (${transactionHash})`);
	const codehash = await codehashAt(ctx, address);
	if (!codehash)
		throw new Error(
			`no code at ${address} after deploying ${label} (${transactionHash})`,
		);
	ctx.log(`  + ${label.padEnd(28)} ${address}  ${transactionHash}`);
	return { address, label, release, codehash, transactionHash };
}

/**
 * Records `deployed` under `key`. A contract found already in place keeps the transaction hash and
 * release from the run that actually deployed it.
 */
function record(
	ctx: DeployContext,
	key: LabelKey,
	deployed: DeployedContract,
): DeployedContract {
	const previous = ctx.record.contracts[key];
	const merged =
		previous &&
		previous.address === deployed.address &&
		!deployed.transactionHash
			? { ...previous, codehash: deployed.codehash }
			: deployed;
	ctx.record.contracts[key] = merged;
	ctx.onRecord?.();
	return merged;
}

function withArgs(
	creationCode: Hex,
	types: string,
	values: readonly unknown[],
): Hex {
	return concat([
		creationCode,
		encodeAbiParameters(parseAbiParameters(types), values),
	]);
}

/**
 * The canonical contracts under their fixed labels: wallet implementation, factory, paymaster
 * implementation and paymaster proxy. On a chain that already has them this verifies and records.
 */
export async function deployCore(
	ctx: DeployContext,
	release: Release,
	paymaster: PaymasterParams,
): Promise<void> {
	const c = release.contracts;
	const put = (key: LabelKey, deployed: DeployedContract) =>
		record(ctx, key, deployed);

	const wallet = put(
		"walletImplementation",
		await deployLabel(ctx, {
			label: LABELS.walletImplementation,
			release: release.version,
			initCode: c.GianoSmartWallet.creationCode,
		}),
	);
	put(
		"factory",
		await deployLabel(ctx, {
			label: LABELS.factory,
			release: release.version,
			initCode: withArgs(c.GianoSmartWalletFactory.creationCode, "address", [
				wallet.address,
			]),
		}),
	);
	const implementation = put(
		"paymasterImplementation",
		await deployLabel(ctx, {
			label: LABELS.paymasterImplementation,
			release: release.version,
			initCode: c.GianoPaymaster.creationCode,
		}),
	);
	// A stock ERC1967Proxy with an EMPTY payload, initialised by CreateX in the same transaction: no
	// window in which an unconfigured proxy could be claimed, and nothing operator-specific in the
	// init code (§4.2 of specs/PAYMASTER-SPECS.md).
	put(
		"paymasterProxy",
		await deployLabel(ctx, {
			label: LABELS.paymasterProxy,
			release: release.version,
			initCode: withArgs(c.ERC1967Proxy.creationCode, "address, bytes", [
				implementation.address,
				"0x",
			]),
			init: encodeFunctionData({
				abi: gianoPaymasterAbi,
				functionName: "initialize",
				args: [
					paymaster.entryPoint,
					paymaster.roleAdmin,
					paymaster.defaultFeeWei,
					paymaster.postOpGasAllowance,
					paymaster.penaltyBps,
				],
			}),
		}),
	);
}

/** PrivateERC20 and PermissivePaymaster. Never on a production chain (the CLI enforces it). */
export async function deployTesting(
	ctx: DeployContext,
	release: Release,
	params: TestingParams,
): Promise<void> {
	const c = release.contracts;
	record(
		ctx,
		"testErc20",
		await deployLabel(ctx, {
			label: LABELS.testErc20,
			release: release.version,
			initCode: withArgs(c.PrivateERC20.creationCode, "uint256, address", [
				100_000_000_000_000n * 10n ** 18n,
				params.holder,
			]),
		}),
	);
	const testPaymaster = await deployLabel(ctx, {
		label: LABELS.testPaymaster,
		release: release.version,
		initCode: withArgs(c.PermissivePaymaster.creationCode, "address, address", [
			params.entryPoint,
			params.owner,
		]),
	});
	record(ctx, "testPaymaster", testPaymaster);
	if (
		params.fundWei > 0n &&
		testPaymaster.transactionHash &&
		ctx.walletClient
	) {
		// receive() forwards to the EntryPoint deposit. Only on first deployment, so re-runs do not
		// keep topping it up.
		const hash = await ctx.walletClient.sendTransaction({
			to: testPaymaster.address,
			value: params.fundWei,
		});
		await ctx.publicClient.waitForTransactionReceipt({ hash });
		ctx.log(
			`  + funded the test paymaster's deposit with ${params.fundWei} wei`,
		);
	}
}

/**
 * A newer release's implementation as an upgrade target on a chain that already has the fixed one:
 * `giano.paymaster.impl@v2`, `giano.wallet.impl@v2`. The fixed-label contracts do not change.
 */
export async function deployUpgradeTarget(
	ctx: DeployContext,
	release: Release,
	of: "paymasterImplementation" | "walletImplementation",
): Promise<DeployedContract> {
	const creationCode =
		of === "paymasterImplementation"
			? release.contracts.GianoPaymaster.creationCode
			: release.contracts.GianoSmartWallet.creationCode;
	// A working-tree build changes between runs, so its label names the code rather than a version.
	const version =
		release.version === DEV_RELEASE
			? `${DEV_RELEASE}-${keccak256(creationCode).slice(2, 10)}`
			: release.version;
	const deployed = await deployLabel(ctx, {
		label: upgradeLabel(LABELS[of], version),
		release: release.version,
		initCode: creationCode,
	});
	if (!ctx.record.upgrades.some((u) => u.address === deployed.address))
		ctx.record.upgrades.push({ ...deployed, of });
	return deployed;
}

/** `upgradeToAndCall(implementation, '')` on the paymaster proxy, for an account holding UPGRADER_ROLE. */
export function paymasterUpgradeCalldata(implementation: Address): Hex {
	return encodeFunctionData({
		abi: gianoPaymasterAbi,
		functionName: "upgradeToAndCall",
		args: [implementation, "0x"],
	});
}

export type TimelockParams = {
	paymaster: Address;
	/** May schedule and cancel: a Safe in production (G9 R3). */
	proposers: Address[];
	/** May execute a ready operation. Empty opens execution to anyone. */
	executors: Address[];
	delays: TimelockDelays;
};

/**
 * Deploys a GianoTimelock for the paymaster with plain CREATE. It is not canonical: its proposers
 * and delays are the operator's, so its address differs per deployment and is recorded instead.
 */
export async function deployTimelock(
	ctx: Pick<DeployContext, "publicClient" | "walletClient" | "log">,
	release: Release,
	params: TimelockParams,
): Promise<DeployedContract> {
	const problems = delayPolicyProblems(params.delays);
	if (problems.length)
		throw new Error(`refusing the delay policy:\n  ${problems.join("\n  ")}`);
	if (params.proposers.length === 0)
		throw new Error("a timelock needs at least one proposer (a Safe in production)");

	const initCode = withArgs(
		release.contracts.GianoTimelock.creationCode,
		"uint256, address[], address[], (address target, bytes4 selector, uint256 delay)[]",
		[
			BigInt(params.delays.minDelay),
			params.proposers,
			params.executors.length ? params.executors : [zeroAddress],
			paymasterFunctionDelays(params.paymaster, params.delays),
		],
	);
	if (!ctx.walletClient) throw new Error("Timelock deployment needs a signer");
	const hash = await ctx.walletClient.sendTransaction({ data: initCode });
	ctx.log(`  → GianoTimelock: submitted ${hash}; waiting for receipt`);
	const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
	if (receipt.status !== "success" || !receipt.contractAddress)
		throw new Error(`deploying GianoTimelock reverted (${hash})`);
	const address = getAddress(receipt.contractAddress);
	const code = await ctx.publicClient.getCode({ address });
	if (!code || code === "0x")
		throw new Error(`no code at ${address} after deploying GianoTimelock`);
	ctx.log(`  + ${"GianoTimelock".padEnd(28)} ${address}  ${hash}`);
	return {
		address,
		label: "giano.paymaster.timelock",
		release: release.version,
		codehash: keccak256(code),
		transactionHash: hash,
	};
}

/** One call in the hand-off, in the order it must be sent. */
export type HandOffCall = { description: string; data: Hex };

/**
 * The calls that give the timelock every timelocked role and take them from everyone else, sent
 * by the current ROLE_ADMIN holder (`from`). ROLE_ADMIN is renounced last: after it, only the
 * timelock can change a role, and only after the role delay. Already-correct state yields no call.
 */
export async function planHandOff(
	publicClient: PublicClient,
	paymaster: Address,
	timelock: Address,
	from: Address,
): Promise<HandOffCall[]> {
	const read = <T>(functionName: string, args: readonly unknown[] = []) =>
		publicClient.readContract({
			address: paymaster,
			abi: gianoPaymasterAbi,
			functionName: functionName as never,
			args: args as never,
		}) as Promise<T>;
	const calls: HandOffCall[] = [];
	const call = (
		description: string,
		functionName: "grantRole" | "revokeRole" | "renounceRole",
		role: Hex,
		account: Address,
	) =>
		calls.push({
			description,
			data: encodeFunctionData({
				abi: gianoPaymasterAbi,
				functionName,
				args: [role, account],
			}),
		});

	// ROLE_ADMIN last, so the sender keeps the power to make every other change first.
	const order = [
		...TIMELOCKED_ROLES.filter((role) => role !== "ROLE_ADMIN"),
		"ROLE_ADMIN" as const,
	];
	for (const name of order) {
		const role = await read<Hex>(name);
		const count = await read<bigint>("getRoleMemberCount", [role]);
		const holders: Address[] = [];
		for (let i = 0n; i < count; i++)
			holders.push(getAddress(await read<Address>("getRoleMember", [role, i])));
		if (!holders.includes(getAddress(timelock)))
			call(`grant ${name} to the timelock ${timelock}`, "grantRole", role, timelock);
		for (const holder of holders) {
			if (holder === getAddress(timelock)) continue;
			if (name === "ROLE_ADMIN" && holder === getAddress(from)) continue;
			call(`revoke ${name} from ${holder}`, "revokeRole", role, holder);
		}
		if (name === "ROLE_ADMIN" && holders.includes(getAddress(from)))
			call(`renounce ${name} (${from})`, "renounceRole", role, from);
	}
	return calls;
}

/** `upgradeToAndCall(implementation, '')` as a timelock proposal, with the delay the timelock requires. */
export async function paymasterUpgradeProposal(
	publicClient: PublicClient,
	timelock: Address,
	proxy: Address,
	implementation: Address,
	salt?: Hex,
) {
	const data = paymasterUpgradeCalldata(implementation);
	const delay = (await publicClient.readContract({
		address: timelock,
		abi: gianoTimelockAbi,
		functionName: "getDelay",
		args: [proxy, data],
	})) as bigint;
	return encodeTimelockProposal({
		timelock,
		calls: [{ target: proxy, data }],
		delay,
		salt,
	});
}
