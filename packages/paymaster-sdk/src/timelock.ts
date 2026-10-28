import {
	encodeTimelockProposal,
	formatDuration,
	gianoPaymasterAbi,
	gianoTimelockAbi,
	paymasterSelector,
	type SafeTransactionBatch,
	safeTransactionBatch,
	TIMELOCKED_FUNCTION_NAMES,
	TIMELOCKED_OPERATIONS,
	TIMELOCKED_ROLES,
	type TimelockCall,
	type TimelockedFunctionName,
	type TimelockedOperation,
	type TimelockProposal,
} from "@appliedblockchain/giano-contracts";
import {
	type Address,
	decodeFunctionData,
	encodeFunctionData,
	formatEther,
	type Hash,
	type Hex,
	isAddressEqual,
	keccak256,
	toBytes,
	toHex,
	zeroAddress,
	zeroHash,
} from "viem";
import type { PaymasterPublicClient, PaymasterWalletClient } from "./client";
import {
	PaymasterSdkError,
	SignerRequiredError,
	translateContractError,
} from "./errors";
import {
	type BlockRange,
	DEFAULT_LOG_WINDOW,
	type Page,
	readWindow,
	resolveWindow,
} from "./log-window";
import {
	PAYMASTER_ROLES,
	type PaymasterRoleName,
	roleName as paymasterRoleName,
} from "./roles";
import { toTenantId, toTenantUuid } from "./tenant-id";
import type { WriteResult } from "./types";

/**
 * The paymaster's timelock (G9), from the operator's side.
 *
 * Every paymaster function in `TIMELOCKED_OPERATIONS` — upgrades, role changes, withdrawal
 * addresses and fees — is gated by a role only the timelock holds on a handed-off deployment, so
 * it cannot be sent from a key at all. It is *proposed* (the timelock's `schedule`), waits out a
 * public delay during which tenants can see it coming, and is then *executed*. This module is what
 * lets an operator do that without hand-encoding calldata (R5): it reads the delays, builds each
 * proposal with the delay the timelock will actually demand, lists what is pending with its ETA,
 * and executes a ready operation from its own logs.
 *
 * It never assumes the proposer is a key that signs here. In production the proposer is a Safe
 * (R3), so a proposal is data — the `schedule` calldata, and the Safe Transaction Builder batch
 * that sends it — and sending it is the Safe's business. The writes on this client are for the
 * cases where a key legitimately acts: an executor role opened to anyone (`address(0)`), and a
 * devnet where one EOA holds everything.
 *
 * The policy itself — which functions are timelocked, by which role, and the encoders — lives in
 * `@appliedblockchain/giano-contracts` (`timelock.ts`) and is re-exported here rather than copied,
 * so this client, the deploy CLI and giano-doctor cannot disagree about it.
 */

export {
	encodeTimelockProposal,
	formatDuration,
	parseDuration,
	type SafeTransactionBatch,
	safeTransactionBatch,
	TIMELOCKED_FUNCTION_NAMES,
	TIMELOCKED_OPERATIONS,
	TIMELOCKED_ROLES,
	type TimelockCall,
	type TimelockDelays,
	type TimelockedFunctionName,
	type TimelockedOperation,
	type TimelockProposal,
} from "@appliedblockchain/giano-contracts";

/** The timelock's own roles, OpenZeppelin's names hashed as `TimelockController` hashes them. */
export const TIMELOCK_ROLE_NAMES = [
	"PROPOSER_ROLE",
	"EXECUTOR_ROLE",
	"CANCELLER_ROLE",
] as const;

export type TimelockRoleName = (typeof TIMELOCK_ROLE_NAMES)[number];

/** Role name → its `bytes32` identifier on the timelock. Pinned in `test/timelock.test.ts`. */
export const TIMELOCK_ROLES: Record<TimelockRoleName, Hex> = Object.fromEntries(
	TIMELOCK_ROLE_NAMES.map((name) => [name, keccak256(toBytes(name))]),
) as Record<TimelockRoleName, Hex>;

/**
 * Where an operation is.
 *
 * The first four are `TimelockController.getOperationState`. `cancelled` is not a state the
 * contract has — cancelling deletes the operation, which reads back as `unset` — and is recovered
 * from the `Cancelled` log, because "it was cancelled" and "it never existed" are different answers
 * for an operator who proposed it.
 */
export type TimelockOperationState =
	| "unset"
	| "waiting"
	| "ready"
	| "done"
	| "cancelled";

const ON_CHAIN_STATES = ["unset", "waiting", "ready", "done"] as const;

/** One timelocked paymaster function's delay, as the timelock will enforce it. */
export type TimelockFunctionDelay = {
	functionName: TimelockedFunctionName;
	selector: Hex;
	/** The paymaster role the timelock holds to make this call. */
	role: TimelockedOperation["role"];
	/** Why it is timelocked, in the policy's words. */
	why: string;
	/** The function's own configured delay; 0 when it has none and falls back to `minDelay`. */
	functionDelay: bigint;
	/** What a proposal must wait: `max(minDelay, functionDelay)`. */
	effectiveDelay: bigint;
};

export type TimelockConfig = {
	address: Address;
	paymaster: Address;
	chainId: number;
	/** The floor every operation waits, and the delay of any call without its own. */
	minDelay: bigint;
	functions: readonly TimelockFunctionDelay[];
	/**
	 * True when `EXECUTOR_ROLE` is held by `address(0)`, so anyone may execute a ready operation —
	 * which is what makes {@link GianoTimelockClient.executeOperation} usable from any key.
	 */
	executorsOpen: boolean;
	/**
	 * Whether the timelock holds each timelocked paymaster role. All true once the deployment has
	 * been handed off; a false entry means that role's functions are still sent from a key.
	 */
	holdsRole: Record<TimelockedOperation["role"], boolean>;
};

/** A call decoded against the paymaster or the timelock, with a sentence for a person. */
export type DecodedTimelockCall = {
	contract: "paymaster" | "timelock";
	functionName: string;
	args: readonly unknown[];
	/** e.g. `set the default fee to 0.0001 ETH`. */
	summary: string;
};

export type TimelockOperationCall = {
	target: Address;
	value: bigint;
	data: Hex;
	/** Absent for a call this client cannot decode — an unknown target or selector. */
	decoded?: DecodedTimelockCall;
};

/** A scheduled operation, reassembled from the timelock's logs and its on-chain state. */
export type TimelockOperation = {
	id: Hex;
	calls: readonly TimelockOperationCall[];
	predecessor: Hex;
	salt: Hex;
	/** The delay it was scheduled with, in seconds. Unknown when its scheduling predates the window. */
	delay?: bigint;
	state: TimelockOperationState;
	/**
	 * Unix seconds from which it can execute (`getTimestamp`). Present while it is waiting or ready;
	 * the contract forgets it once the operation is done or cancelled.
	 */
	readyAt?: number;
	scheduledBlock?: bigint;
	scheduledTransaction?: Hash;
	executedBlock?: bigint;
	executedTransaction?: Hash;
	cancelledBlock?: bigint;
	cancelledTransaction?: Hash;
	/**
	 * True when every call's scheduling log was in the window, so the calls, predecessor and salt
	 * are known exactly and the operation can be executed from here. An operation scheduled before
	 * the window and executed or cancelled within it is still listed, with what its later logs say.
	 */
	complete: boolean;
};

/** A proposal ready to hand to a proposer, with what a person needs to review it. */
export type TimelockProposalDraft = TimelockProposal & {
	chainId: number;
	/** The least delay the timelock will accept for these calls (`getDelay` / `getBatchDelay`). */
	requiredDelay: bigint;
	/** Unix seconds it would become executable if scheduled in the latest block. */
	readyAtIfScheduledNow: number;
	/** One line per call, from the decoded calldata. */
	summary: string;
	decoded: readonly (DecodedTimelockCall | undefined)[];
};

export type ProposeOptions = {
	/**
	 * Defaults to a random salt, because the operation id is a hash of the calls and the salt: a
	 * second proposal of the same change under the same salt is the same id, and the timelock
	 * refuses to schedule an id it has seen. Pass one to reproduce a proposal exactly.
	 */
	salt?: Hex;
	predecessor?: Hex;
	/** Seconds. Defaults to the delay the timelock requires; anything shorter is refused here. */
	delay?: bigint;
};

export type TimelockClientConfig = {
	/** The GianoTimelock. */
	address: Address;
	/** The paymaster proxy whose timelocked roles it holds. Its delays are keyed on this target. */
	paymaster: Address;
	publicClient: PaymasterPublicClient;
	/** Only needed to execute (or, where a key is a proposer, schedule or cancel). */
	walletClient?: PaymasterWalletClient;
	/** As on `GianoPaymasterClient`: the span one log read covers, narrowed on refusal. */
	logWindow?: bigint;
};

export type TimelockOperationsOptions = {
	/** The newest window to read. Defaults to the one ending at the head. */
	range?: Partial<BlockRange>;
	/**
	 * Consecutive windows to read, newest first. Defaults to 1. An operation's logs span from its
	 * scheduling to its execution — at least its delay apart — so a list meant to show what is
	 * pending should read back at least as far as the longest delay.
	 */
	windows?: number;
};

/**
 * Client for the paymaster's GianoTimelock.
 *
 * ```ts
 * const timelock = new GianoTimelockClient({ address, paymaster: paymaster.address, publicClient });
 * const proposal = await timelock.proposeSetDefaultFee(parseEther('0.0002'));
 * proposal.schedule;                       // calldata for the proposer
 * timelock.safeBatch(proposal);            // the Safe Transaction Builder file that sends it
 * const { operations } = await timelock.getOperations({ windows: 10 });
 * ```
 */
export class GianoTimelockClient {
	readonly address: Address;
	readonly paymaster: Address;
	readonly publicClient: PaymasterPublicClient;
	readonly walletClient?: PaymasterWalletClient;

	private logWindow: bigint;

	constructor(config: TimelockClientConfig) {
		this.address = config.address;
		this.paymaster = config.paymaster;
		this.publicClient = config.publicClient;
		this.walletClient = config.walletClient;
		this.logWindow = config.logWindow ?? DEFAULT_LOG_WINDOW;
	}

	/** A copy of this client bound to a different (or a newly connected) wallet. */
	withWallet(walletClient: PaymasterWalletClient): GianoTimelockClient {
		return new GianoTimelockClient({
			address: this.address,
			paymaster: this.paymaster,
			publicClient: this.publicClient,
			walletClient,
			logWindow: this.logWindow,
		});
	}

	private read<T>(
		functionName: string,
		args: readonly unknown[] = [],
	): Promise<T> {
		return this.publicClient.readContract({
			address: this.address,
			abi: gianoTimelockAbi,
			functionName,
			args,
		} as never) as Promise<T>;
	}

	// -------------------------------------------------------------------------------------------
	// Reads — configuration
	// -------------------------------------------------------------------------------------------

	getMinDelay(): Promise<bigint> {
		return this.read<bigint>("getMinDelay");
	}

	/** The delay a call to `functionName` on the paymaster waits: `max(minDelay, its own)`. */
	getEffectiveDelay(functionName: TimelockedFunctionName): Promise<bigint> {
		return this.read<bigint>("getEffectiveDelay", [
			this.paymaster,
			paymasterSelector(functionName),
		]);
	}

	hasRole(role: TimelockRoleName, account: Address): Promise<boolean> {
		return this.read<boolean>("hasRole", [TIMELOCK_ROLES[role], account]);
	}

	/** Whether anyone may execute a ready operation (`EXECUTOR_ROLE` held by `address(0)`). */
	executorsOpen(): Promise<boolean> {
		return this.hasRole("EXECUTOR_ROLE", zeroAddress);
	}

	/**
	 * The timelock's delays for every timelocked paymaster function, and whether it actually holds
	 * the roles it is meant to. One call, for a status screen.
	 */
	async getConfig(): Promise<TimelockConfig> {
		const [chainId, minDelay, executorsOpen, functions, held] =
			await Promise.all([
				this.publicClient.getChainId(),
				this.getMinDelay(),
				this.executorsOpen(),
				Promise.all(
					TIMELOCKED_FUNCTION_NAMES.map(async (functionName) => {
						const selector = paymasterSelector(functionName);
						const [functionDelay, effectiveDelay] = await Promise.all([
							this.read<bigint>("getFunctionDelay", [this.paymaster, selector]),
							this.read<bigint>("getEffectiveDelay", [
								this.paymaster,
								selector,
							]),
						]);
						const { role, why } = TIMELOCKED_OPERATIONS[functionName];
						return {
							functionName,
							selector,
							role,
							why,
							functionDelay,
							effectiveDelay,
						};
					}),
				),
				Promise.all(
					TIMELOCKED_ROLES.map(
						(role) =>
							this.publicClient.readContract({
								address: this.paymaster,
								abi: gianoPaymasterAbi,
								functionName: "hasRole",
								args: [PAYMASTER_ROLES[role], this.address],
							} as never) as Promise<boolean>,
					),
				),
			]);

		return {
			address: this.address,
			paymaster: this.paymaster,
			chainId,
			minDelay,
			functions,
			executorsOpen,
			holdsRole: Object.fromEntries(
				TIMELOCKED_ROLES.map((role, index) => [role, held[index]]),
			) as Record<TimelockedOperation["role"], boolean>,
		};
	}

	// -------------------------------------------------------------------------------------------
	// Reads — operations
	// -------------------------------------------------------------------------------------------

	/** The on-chain state of one operation. `cancelled` needs the logs; see {@link getOperations}. */
	async getOperationState(id: Hex): Promise<TimelockOperationState> {
		const state = await this.read<number>("getOperationState", [id]);
		return ON_CHAIN_STATES[Number(state)] ?? "unset";
	}

	/**
	 * Operations scheduled, executed or cancelled within one or more windows of blocks, newest
	 * first, with the range that was read.
	 *
	 * Like every log read in this SDK this is a window, not the whole history — see
	 * `GianoPaymasterClient.getSponsorships`. One query per window covers all four timelock events,
	 * so reading back a week costs the same few queries whatever the timelock did in it. Each
	 * operation's state and ETA come from the contract, not the logs, so "ready" means ready now.
	 */
	async getOperations(
		options: TimelockOperationsOptions = {},
	): Promise<Page & { operations: readonly TimelockOperation[] }> {
		const windows = options.windows ?? 1;
		if (!Number.isSafeInteger(windows) || windows < 1)
			throw new RangeError(`windows must be a positive whole number`);

		const logs: TimelockLog[] = [];
		let page = await this.readLogs(options.range);
		const toBlock = page.toBlock;
		logs.push(...page.logs);
		for (let read = 1; read < windows && page.older; read++) {
			page = await this.readLogs(page.older);
			logs.push(...page.logs);
		}

		const operations = await Promise.all(
			assemble(logs).map((partial) => this.withState(partial)),
		);
		operations.sort((a, b) => Number(latestBlock(b) - latestBlock(a)));
		return {
			fromBlock: page.fromBlock,
			toBlock,
			older: page.older,
			operations,
		};
	}

	/** One operation, found in the windows {@link getOperations} reads. `undefined` if not there. */
	async findOperation(
		id: Hex,
		options: TimelockOperationsOptions = {},
	): Promise<TimelockOperation | undefined> {
		const { operations } = await this.getOperations(options);
		return operations.find(
			(operation) => operation.id.toLowerCase() === id.toLowerCase(),
		);
	}

	private async withState(
		partial: Omit<TimelockOperation, "state" | "readyAt">,
	): Promise<TimelockOperation> {
		const [state, timestamp] = await Promise.all([
			this.getOperationState(partial.id),
			this.read<bigint>("getTimestamp", [partial.id]),
		]);
		return {
			...partial,
			calls: partial.calls.map((call) => ({
				...call,
				decoded: this.decodeCall(call.target, call.data),
			})),
			state:
				state === "unset" && partial.cancelledBlock !== undefined
					? "cancelled"
					: state,
			// The contract stores 1 for a done operation and 0 for none; neither is a time.
			readyAt:
				state === "waiting" || state === "ready"
					? Number(timestamp)
					: undefined,
		};
	}

	/** Every timelock event in one window, with the node's real span discovered on refusal. */
	private readLogs(range: Partial<BlockRange> | undefined) {
		return resolveWindow(this.publicClient, range, this.logWindow).then(
			(resolved) =>
				readWindow<TimelockLog>(
					resolved,
					({ fromBlock, toBlock }) =>
						this.publicClient.getContractEvents({
							address: this.address,
							abi: gianoTimelockAbi,
							fromBlock,
							toBlock,
						} as never) as unknown as Promise<readonly TimelockLog[]>,
					(narrowed) => {
						this.logWindow = narrowed;
					},
				),
		);
	}

	/**
	 * Decodes a call the timelock would make, against the paymaster or the timelock itself, into the
	 * function, its arguments and a sentence. `undefined` for any other target or an unknown selector
	 * — an operator should see raw calldata rather than a confident wrong reading of it.
	 */
	decodeCall(target: Address, data: Hex): DecodedTimelockCall | undefined {
		const contract = isAddressEqual(target, this.paymaster)
			? "paymaster"
			: isAddressEqual(target, this.address)
				? "timelock"
				: undefined;
		if (!contract) return undefined;
		try {
			const { functionName, args = [] } = decodeFunctionData({
				abi: contract === "paymaster" ? gianoPaymasterAbi : gianoTimelockAbi,
				data,
			}) as { functionName: string; args?: readonly unknown[] };
			return {
				contract,
				functionName,
				args,
				summary: summarise(contract, functionName, args, this.paymaster),
			};
		} catch {
			return undefined;
		}
	}

	// -------------------------------------------------------------------------------------------
	// Proposals
	// -------------------------------------------------------------------------------------------

	/**
	 * Builds the proposal for any calls the timelock should make, with the delay read from the
	 * timelock (`getDelay` for one call, `getBatchDelay` for several) rather than from a profile
	 * that may have drifted from what it enforces.
	 *
	 * Sends nothing. The result carries the `schedule`, `execute` and `cancel` calldata, and
	 * {@link safeBatch} turns it into the file a Safe proposer uploads.
	 */
	async propose(
		calls: readonly TimelockCall[],
		options: ProposeOptions = {},
	): Promise<TimelockProposalDraft> {
		if (calls.length === 0)
			throw new PaymasterSdkError("a proposal needs at least one call");

		const [chainId, requiredDelay, head] = await Promise.all([
			this.publicClient.getChainId(),
			calls.length === 1
				? this.read<bigint>("getDelay", [calls[0].target, calls[0].data])
				: this.read<bigint>("getBatchDelay", [
						calls.map((call) => call.target),
						calls.map((call) => call.data),
					]),
			this.publicClient.getBlock(),
		]);

		const delay = options.delay ?? requiredDelay;
		if (delay < requiredDelay)
			throw new PaymasterSdkError(
				`a delay of ${formatDuration(delay)} is shorter than the ${formatDuration(requiredDelay)} the timelock requires for this proposal; it would refuse to schedule it`,
			);

		const proposal = encodeTimelockProposal({
			timelock: this.address,
			calls: [...calls],
			delay,
			salt: options.salt ?? randomSalt(),
			predecessor: options.predecessor,
		});

		// A caller-supplied salt can collide with an operation that already exists; the timelock
		// would refuse the schedule, so say so now rather than after a Safe has collected signatures.
		const existing = await this.getOperationState(proposal.id);
		if (existing !== "unset")
			throw new PaymasterSdkError(
				`operation ${proposal.id} already exists on the timelock (${existing}); propose it again with a different salt`,
			);

		const decoded = calls.map((call) =>
			this.decodeCall(call.target, call.data),
		);
		// The schedule lands in a block no earlier than now; a quiet devnet's head can lag the clock.
		const scheduledAt = Math.max(
			Number(head.timestamp),
			Math.floor(Date.now() / 1000),
		);
		return {
			...proposal,
			chainId,
			requiredDelay,
			readyAtIfScheduledNow: scheduledAt + Number(delay),
			summary: decoded
				.map(
					(entry, index) =>
						entry?.summary ??
						`call ${calls[index].target} with ${calls[index].data.slice(0, 10)}…`,
				)
				.join("; "),
			decoded,
		};
	}

	/** A paymaster call for {@link propose}. */
	paymasterCall(functionName: string, args: readonly unknown[]): TimelockCall {
		return {
			target: this.paymaster,
			data: encodeFunctionData({
				abi: gianoPaymasterAbi,
				functionName,
				args,
			} as never),
		};
	}

	/** `setDefaultFee`, through the timelock. (FEE_ADMIN_ROLE) */
	proposeSetDefaultFee(
		feeWei: bigint,
		options?: ProposeOptions,
	): Promise<TimelockProposalDraft> {
		return this.propose(
			[this.paymasterCall("setDefaultFee", [feeWei])],
			options,
		);
	}

	/** `setTenantFee`, through the timelock. `hasOverride: false` clears it. (FEE_ADMIN_ROLE) */
	proposeSetTenantFee(
		tenantId: string,
		hasOverride: boolean,
		feeWei: bigint,
		options?: ProposeOptions,
	): Promise<TimelockProposalDraft> {
		return this.propose(
			[
				this.paymasterCall("setTenantFee", [
					toTenantId(tenantId),
					hasOverride,
					hasOverride ? feeWei : 0n,
				]),
			],
			options,
		);
	}

	/** `setTenantWithdrawAddress`, through the timelock. (WITHDRAW_ADDRESS_ADMIN_ROLE) */
	proposeSetTenantWithdrawAddress(
		tenantId: string,
		withdrawAddress: Address,
		options?: ProposeOptions,
	): Promise<TimelockProposalDraft> {
		return this.propose(
			[
				this.paymasterCall("setTenantWithdrawAddress", [
					toTenantId(tenantId),
					withdrawAddress,
				]),
			],
			options,
		);
	}

	/** `grantRole` on the paymaster, through the timelock. (ROLE_ADMIN) */
	proposeGrantRole(
		role: PaymasterRoleName,
		account: Address,
		options?: ProposeOptions,
	): Promise<TimelockProposalDraft> {
		return this.propose(
			[this.paymasterCall("grantRole", [PAYMASTER_ROLES[role], account])],
			options,
		);
	}

	/** `revokeRole` on the paymaster, through the timelock. (ROLE_ADMIN) */
	proposeRevokeRole(
		role: PaymasterRoleName,
		account: Address,
		options?: ProposeOptions,
	): Promise<TimelockProposalDraft> {
		return this.propose(
			[this.paymasterCall("revokeRole", [PAYMASTER_ROLES[role], account])],
			options,
		);
	}

	/** `upgradeToAndCall` on the paymaster proxy, through the timelock. (UPGRADER_ROLE) */
	proposeUpgrade(
		implementation: Address,
		data: Hex = "0x",
		options?: ProposeOptions,
	): Promise<TimelockProposalDraft> {
		return this.propose(
			[this.paymasterCall("upgradeToAndCall", [implementation, data])],
			options,
		);
	}

	/**
	 * The Safe Transaction Builder file for one step of a proposal: `schedule` for the proposer
	 * Safe, `execute` once ready (when executors are restricted to the Safe), or `cancel`.
	 */
	safeBatch(
		proposal: TimelockProposalDraft,
		step: "schedule" | "execute" | "cancel" = "schedule",
	): SafeTransactionBatch {
		return safeTransactionBatch(proposal, {
			chainId: proposal.chainId,
			step,
			description: `${step[0].toUpperCase()}${step.slice(1)} on timelock ${proposal.timelock}: ${proposal.summary} (delay ${formatDuration(proposal.delay)})`,
		});
	}

	/**
	 * The proposal an operation was scheduled from, rebuilt from its logs: the `execute` and `cancel`
	 * calldata for a scheduled operation, for an executor or canceller that is a Safe. Only for a
	 * complete operation, whose calls, predecessor, salt and delay are all known.
	 */
	toProposal(operation: TimelockOperation): TimelockProposal {
		if (!operation.complete || operation.delay === undefined)
			throw new PaymasterSdkError(
				`operation ${operation.id} was scheduled before the blocks read, so its calls cannot be rebuilt from here; read further back`,
			);
		const proposal = encodeTimelockProposal({
			timelock: this.address,
			calls: operation.calls.map(({ target, value, data }) => ({
				target,
				value,
				data,
			})),
			delay: operation.delay,
			salt: operation.salt,
			predecessor: operation.predecessor,
		});
		// The id is a hash of exactly these fields, so a mismatch means the logs were misread.
		if (proposal.id.toLowerCase() !== operation.id.toLowerCase())
			throw new PaymasterSdkError(
				`rebuilt operation ${proposal.id} does not match ${operation.id}; its logs were not read completely`,
			);
		return proposal;
	}

	// -------------------------------------------------------------------------------------------
	// Writes
	// -------------------------------------------------------------------------------------------

	/**
	 * Executes a ready operation from its logs.
	 *
	 * Meant for a timelock whose executors are open, where any account may execute — the delay is
	 * the protection, not who presses the button. Takes an operation from {@link getOperations}, or
	 * an id to look up there; the calls, predecessor and salt are rebuilt from the scheduling logs,
	 * so nobody has to keep the original proposal around.
	 */
	async executeOperation(
		operation: TimelockOperation | Hex,
		options: TimelockOperationsOptions = {},
	): Promise<WriteResult> {
		const found =
			typeof operation === "string"
				? await this.findOperation(operation, options)
				: operation;
		const id = typeof operation === "string" ? operation : operation.id;
		if (!found)
			throw new PaymasterSdkError(
				`operation ${id} is not in the blocks read (${options.windows ?? 1} window(s) back from ${options.range?.toBlock ?? "the head"}); read further back to find its scheduling`,
			);
		if (!found.complete)
			throw new PaymasterSdkError(
				`operation ${id} was scheduled before the blocks read, so its calls cannot be rebuilt from here; read further back`,
			);
		if (found.state !== "ready")
			throw new PaymasterSdkError(
				found.state === "waiting" && found.readyAt
					? `operation ${id} is not ready until ${new Date(found.readyAt * 1000).toISOString()}`
					: `operation ${id} is ${found.state}, not ready to execute`,
			);

		// Rebuilding checks the logs hash back to the id, so nothing misread is ever executed.
		this.toProposal(found);
		const targets = found.calls.map((call) => call.target);
		const values = found.calls.map((call) => call.value);
		const payloads = found.calls.map((call) => call.data);
		const value = values.reduce((sum, each) => sum + each, 0n);
		return found.calls.length === 1
			? this.send(
					"execute",
					[targets[0], values[0], payloads[0], found.predecessor, found.salt],
					`execute timelock operation ${id}`,
					value,
				)
			: this.send(
					"executeBatch",
					[targets, values, payloads, found.predecessor, found.salt],
					`execute timelock operation ${id}`,
					value,
				);
	}

	/**
	 * Schedules a proposal from the connected wallet. Only for a key that holds `PROPOSER_ROLE` — a
	 * devnet or a test. In production the proposer is a Safe: hand it {@link safeBatch} instead.
	 */
	schedule(proposal: TimelockProposal): Promise<WriteResult> {
		const targets = proposal.calls.map((call) => call.target);
		const values = proposal.calls.map((call) => call.value ?? 0n);
		const payloads = proposal.calls.map((call) => call.data);
		return proposal.calls.length === 1
			? this.send(
					"schedule",
					[
						targets[0],
						values[0],
						payloads[0],
						proposal.predecessor,
						proposal.salt,
						proposal.delay,
					],
					`schedule timelock operation ${proposal.id}`,
				)
			: this.send(
					"scheduleBatch",
					[
						targets,
						values,
						payloads,
						proposal.predecessor,
						proposal.salt,
						proposal.delay,
					],
					`schedule timelock operation ${proposal.id}`,
				);
	}

	/** Cancels a pending operation. Needs `CANCELLER_ROLE`, which the proposers hold. */
	cancel(id: Hex): Promise<WriteResult> {
		return this.send("cancel", [id], `cancel timelock operation ${id}`);
	}

	/** Simulate, then send — as `GianoPaymasterClient` does, and for the same reason. */
	private async send(
		functionName: string,
		args: readonly unknown[],
		operation: string,
		value?: bigint,
	): Promise<WriteResult> {
		const walletClient = this.walletClient;
		if (!walletClient) throw new SignerRequiredError(operation);
		const account = walletClient.account;
		if (!account)
			throw new PaymasterSdkError(
				`${operation} needs an account: the supplied wallet client has none. Pass one when creating it, or connect first.`,
			);

		try {
			const { request } = await this.publicClient.simulateContract({
				address: this.address,
				abi: EXECUTION_ABI,
				functionName,
				args,
				account,
				value: value || undefined,
				chain: walletClient.chain ?? this.publicClient.chain,
			} as never);
			const hash = await walletClient.writeContract(request as never);
			return {
				hash,
				wait: (confirmations?: number) =>
					this.publicClient.waitForTransactionReceipt({ hash, confirmations }),
			};
		} catch (error) {
			throw translateContractError(error, {
				operation,
				account: account.address,
				lookupRoleName: (role) =>
					timelockRoleName(role) ?? paymasterRoleName(role),
			});
		}
	}
}

/**
 * The timelock's ABI plus the paymaster's errors.
 *
 * An executed call that reverts in the paymaster bubbles the paymaster's own revert data out of
 * the timelock, so decoding against the timelock's ABI alone would turn `UnknownTenant` into an
 * unreadable selector. With the paymaster's errors alongside, the SDK's usual translation applies.
 */
const EXECUTION_ABI = [
	...gianoTimelockAbi,
	...gianoPaymasterAbi.filter(
		(item) =>
			item.type === "error" &&
			!gianoTimelockAbi.some(
				(own) => own.type === "error" && own.name === item.name,
			),
	),
];

/** Resolves one of the timelock's own role hashes to its name. */
export function timelockRoleName(role: Hex): TimelockRoleName | undefined {
	return TIMELOCK_ROLE_NAMES.find(
		(name) => TIMELOCK_ROLES[name].toLowerCase() === role.toLowerCase(),
	);
}

function randomSalt(): Hex {
	const bytes = new Uint8Array(32);
	globalThis.crypto.getRandomValues(bytes);
	return toHex(bytes);
}

/**
 * A decoded timelock log.
 *
 * Spelled out rather than inferred, as `SponsoredLog` is in the client: the read asks for every
 * event the ABI has, which widens viem's type to a union nobody can narrow usefully.
 */
type TimelockLog = {
	eventName: string;
	args: {
		id?: Hex;
		index?: bigint;
		target?: Address;
		value?: bigint;
		data?: Hex;
		predecessor?: Hex;
		delay?: bigint;
		salt?: Hex;
	};
	blockNumber: bigint | null;
	logIndex: number | null;
	transactionHash: Hash | null;
};

type Assembling = Omit<TimelockOperation, "state" | "readyAt"> & {
	scheduled: Map<bigint, TimelockOperationCall>;
	executed: Map<bigint, TimelockOperationCall>;
};

/**
 * Groups logs into operations by id. Logs are taken in chain order, so an id cancelled and then
 * scheduled again ends up with its latest scheduling.
 */
function assemble(
	logs: readonly TimelockLog[],
): Omit<TimelockOperation, "state" | "readyAt">[] {
	const ordered = [...logs].sort((a, b) =>
		a.blockNumber === b.blockNumber
			? (a.logIndex ?? 0) - (b.logIndex ?? 0)
			: Number((a.blockNumber ?? 0n) - (b.blockNumber ?? 0n)),
	);

	const byId = new Map<string, Assembling>();
	const entry = (id: Hex): Assembling => {
		const key = id.toLowerCase();
		let found = byId.get(key);
		if (!found) {
			found = {
				id,
				calls: [],
				predecessor: zeroHash,
				salt: zeroHash,
				complete: false,
				scheduled: new Map(),
				executed: new Map(),
			};
			byId.set(key, found);
		}
		return found;
	};

	for (const log of ordered) {
		const { args } = log;
		if (!args.id) continue;
		const block = log.blockNumber ?? undefined;
		const transaction = log.transactionHash ?? undefined;
		switch (log.eventName) {
			case "CallScheduled": {
				const operation = entry(args.id);
				// A fresh scheduling (index 0 again, after a cancel) replaces the previous one.
				if (args.index === 0n) {
					operation.scheduled.clear();
					operation.cancelledBlock = undefined;
					operation.cancelledTransaction = undefined;
				}
				operation.scheduled.set(args.index ?? 0n, {
					target: args.target ?? zeroAddress,
					value: args.value ?? 0n,
					data: args.data ?? "0x",
				});
				operation.predecessor = args.predecessor ?? zeroHash;
				operation.delay = args.delay;
				operation.scheduledBlock = block;
				operation.scheduledTransaction = transaction;
				break;
			}
			case "CallSalt":
				entry(args.id).salt = args.salt ?? zeroHash;
				break;
			case "CallExecuted": {
				const operation = entry(args.id);
				operation.executed.set(args.index ?? 0n, {
					target: args.target ?? zeroAddress,
					value: args.value ?? 0n,
					data: args.data ?? "0x",
				});
				operation.executedBlock = block;
				operation.executedTransaction = transaction;
				break;
			}
			case "Cancelled": {
				const operation = entry(args.id);
				operation.cancelledBlock = block;
				operation.cancelledTransaction = transaction;
				break;
			}
		}
	}

	return [...byId.values()].map(({ scheduled, executed, ...operation }) => {
		const source = scheduled.size > 0 ? scheduled : executed;
		const calls = [...source.entries()]
			.sort(([a], [b]) => Number(a - b))
			.map(([, call]) => call);
		// Indices are 0..n-1, so a scheduling whose every index is present is the whole operation.
		const complete =
			scheduled.size > 0 &&
			[...scheduled.keys()].every((index) => index < BigInt(scheduled.size));
		return { ...operation, calls, complete };
	});
}

function latestBlock(operation: TimelockOperation): bigint {
	return (
		operation.executedBlock ??
		operation.cancelledBlock ??
		operation.scheduledBlock ??
		0n
	);
}

/** A sentence for a decoded call. Unknown functions fall back to their name and raw arguments. */
function summarise(
	contract: "paymaster" | "timelock",
	functionName: string,
	args: readonly unknown[],
	paymaster: Address,
): string {
	const tenant = (id: unknown) => {
		try {
			return toTenantUuid(id as Hex);
		} catch {
			return String(id);
		}
	};
	const role = (hash: unknown) =>
		(contract === "paymaster"
			? paymasterRoleName(hash as Hex)
			: timelockRoleName(hash as Hex)) ?? String(hash);

	if (contract === "paymaster") {
		switch (functionName) {
			case "setDefaultFee":
				return `set the default fee to ${formatEther(args[0] as bigint)} ETH`;
			case "setTenantFee":
				return args[1]
					? `set tenant ${tenant(args[0])}'s fee to ${formatEther(args[2] as bigint)} ETH`
					: `clear tenant ${tenant(args[0])}'s fee override`;
			case "setTenantWithdrawAddress":
				return `point tenant ${tenant(args[0])}'s withdrawals at ${args[1]}`;
			case "grantRole":
				return `grant ${role(args[0])} on the paymaster to ${args[1]}`;
			case "revokeRole":
				return `revoke ${role(args[0])} on the paymaster from ${args[1]}`;
			case "renounceRole":
				return `renounce ${role(args[0])} on the paymaster (held by ${args[1]})`;
			case "upgradeToAndCall":
				return `upgrade the paymaster to ${args[0]}${args[1] && args[1] !== "0x" ? " and call it" : ""}`;
		}
	} else {
		switch (functionName) {
			case "setFunctionDelay": {
				const [target, selector, delay] = args as [Address, Hex, bigint];
				const name = isAddressEqual(target, paymaster)
					? TIMELOCKED_FUNCTION_NAMES.find(
							(candidate) => paymasterSelector(candidate) === selector,
						)
					: undefined;
				return `set the delay of ${name ?? `${selector} on ${target}`} to ${formatDuration(delay)}`;
			}
			case "updateDelay":
				return `set the timelock's minimum delay to ${formatDuration(args[0] as bigint)}`;
			case "grantRole":
				return `grant ${role(args[0])} on the timelock to ${args[1]}`;
			case "revokeRole":
				return `revoke ${role(args[0])} on the timelock from ${args[1]}`;
		}
	}
	return `${functionName}(${args.map(String).join(", ")}) on the ${contract}`;
}
