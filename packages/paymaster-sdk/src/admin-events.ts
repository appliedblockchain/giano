import {
	gianoPaymasterAbi,
	gianoTimelockAbi,
	iEntryPointAbi,
	paymasterSelector,
	TIMELOCKED_FUNCTION_NAMES,
} from "@appliedblockchain/giano-contracts";
import {
	type AbiEvent,
	type Address,
	getAddress,
	type Hash,
	type Hex,
	isAddressEqual,
	keccak256,
	toBytes,
} from "viem";
import type { PaymasterPublicClient } from "./client";
import { roleName } from "./roles";
import { toTenantUuid } from "./tenant-id";
import {
	type DecodedTimelockCall,
	TIMELOCK_ROLE_NAMES,
	TIMELOCK_ROLES,
} from "./timelock";

/**
 * Admin events (B1, openspec D12): every privileged change to the paymaster and its timelock, as
 * one decoded list. Who changed a role, a fee or the implementation is otherwise readable nowhere —
 * the contracts keep the current value, and the event is the only record of the change.
 */

/** The paymaster's privileged events: every write that changes authority, configuration or funds. */
export const PAYMASTER_ADMIN_EVENTS = [
	"RoleGranted",
	"RoleRevoked",
	"RoleAdminChanged",
	"FeeChanged",
	"TenantFeeChanged",
	"ParamChanged",
	"Paused",
	"Unpaused",
	"SignerAdded",
	"SignerRemoved",
	"Upgraded",
	"TenantRegistered",
	"TenantEnabledChanged",
	"TenantFunded",
	"TenantWithdrawn",
	"TenantWithdrawAddressChanged",
	"FeesWithdrawn",
] as const;

/**
 * The paymaster's other events, and why each is not an admin event. A test checks the two lists
 * cover the ABI between them, so a privileged event a release adds cannot go unlisted.
 */
export const PAYMASTER_OTHER_EVENTS: Readonly<Record<string, string>> = {
	Sponsored: "a settlement: `getSponsorships`",
	SponsorshipDeficit: "part of a settlement",
	FeesAccrued: "part of a settlement",
	Initialized: "emitted with the Upgraded or deployment it belongs to",
	EIP712DomainChanged: "never emitted: the domain is fixed",
};

/** The timelock's events that change what it will do, or who may make it. */
export const TIMELOCK_ADMIN_EVENTS = [
	"CallScheduled",
	"CallExecuted",
	"Cancelled",
	"MinDelayChange",
	"FunctionDelayChange",
	"RoleGranted",
	"RoleRevoked",
	"RoleAdminChanged",
] as const;

export const TIMELOCK_OTHER_EVENTS: Readonly<Record<string, string>> = {
	CallSalt: "the salt of a CallScheduled in the same transaction",
};

/**
 * The EntryPoint's events about the paymaster's stake. `addStake`, `unlockStake` and `withdrawStake`
 * need STAKE_ADMIN_ROLE, which is not timelocked, and the paymaster emits nothing of its own for
 * them. Read filtered on the indexed `account`, which only the paymaster can make itself. Not
 * `Deposited`: anyone can call `depositTo` for any account.
 */
export const ENTRYPOINT_ADMIN_EVENTS = [
	"StakeLocked",
	"StakeUnlocked",
	"StakeWithdrawn",
] as const;

export type AdminEventKind =
	| (typeof PAYMASTER_ADMIN_EVENTS)[number]
	| (typeof TIMELOCK_ADMIN_EVENTS)[number]
	| (typeof ENTRYPOINT_ADMIN_EVENTS)[number];

/** One privileged event, decoded. */
export type AdminEvent = {
	/** The contract that emitted it: the EntryPoint for the paymaster's stake. */
	source: "paymaster" | "timelock" | "entrypoint";
	kind: AdminEventKind;
	/**
	 * The event's arguments as decoded, except that a role is its name (`FEE_COLLECTOR_ROLE`) and a
	 * `ParamChanged` name its name, rather than a hash. An unknown role keeps its hash.
	 */
	args: Readonly<Record<string, unknown>>;
	/** For the tenant events: the tenant. */
	tenant?: { id: Hex; uuid: string };
	/** For `CallScheduled` and `CallExecuted`: the call, decoded when it targets the paymaster or the timelock. */
	call?: {
		target: Address;
		value: bigint;
		data: Hex;
		decoded?: DecodedTimelockCall;
	};
	/**
	 * A paymaster event in a transaction where the timelock executed a call to the paymaster: the
	 * timelock made the change, whoever sent the transaction (D24).
	 */
	viaTimelock?: true;
	blockNumber: bigint;
	logIndex: number;
	transactionHash: Hash;
	/** Unix seconds; `undefined` when the block could not be read. */
	blockTime: number | undefined;
	/**
	 * The transaction's sender; `undefined` when it was not read (an event that names who acted
	 * needs no transaction read) or could not be.
	 */
	from: Address | undefined;
	/**
	 * Who made the change:
	 * - the account the event names (a role change's `sender`, a pause's `account`, an enable's
	 *   `actor`, a funding's `from`);
	 * - the timelock, for a paymaster change it executed and for its own delay changes (which only
	 *   it can make, after its constructor);
	 * - otherwise whoever called the contract: the transaction's sender when it was sent to the
	 *   contract, else the contract it was sent to (a Safe). Not the EntryPoint: a change a smart
	 *   wallet sent through it has no actor here. Nested calls beyond one hop are not traced.
	 */
	actor: Address | undefined;
};

type DecodedEvent = Omit<AdminEvent, "blockTime" | "from" | "actor">;

const PARAM_NAMES = new Map(
	["postOpGasAllowance", "penaltyBps"].map(
		(name) => [keccak256(toBytes(name)), name] as const,
	),
);

const TIMELOCK_ROLE_BY_HASH = new Map<string, string>([
	...TIMELOCK_ROLE_NAMES.map(
		(name) => [TIMELOCK_ROLES[name].toLowerCase(), name] as const,
	),
	[
		"0x0000000000000000000000000000000000000000000000000000000000000000",
		"DEFAULT_ADMIN_ROLE",
	],
]);

const FUNCTION_BY_SELECTOR = new Map(
	TIMELOCKED_FUNCTION_NAMES.map(
		(name) => [paymasterSelector(name).toLowerCase(), name] as const,
	),
);

const eventsOf = (abi: readonly unknown[], names: readonly string[]) =>
	(abi as readonly AbiEvent[]).filter(
		(item) => item.type === "event" && names.includes(item.name),
	);

type RawLog = {
	eventName: string;
	args: Record<string, unknown>;
	blockNumber: bigint;
	logIndex: number;
	transactionHash: Hash;
	address: Address;
};

/**
 * The admin events of `paymaster` (and of `timelock` and the paymaster's stake at `entryPoint`,
 * when given) in `range`, decoded and newest first, without block times or senders:
 * {@link enrichAdminEvents} adds those.
 *
 * With a timelock, its `CallExecuted` is read even when `kinds` leaves it out: it is how a
 * paymaster change the timelock executed is told from one sent directly (`viaTimelock`).
 */
export async function readAdminEvents(
	publicClient: PaymasterPublicClient,
	range: { fromBlock: bigint; toBlock: bigint },
	options: {
		paymaster: Address;
		timelock?: Address;
		entryPoint?: Address;
		kinds?: readonly AdminEventKind[];
		decodeCall?: (
			target: Address,
			data: Hex,
		) => DecodedTimelockCall | undefined;
	},
): Promise<DecodedEvent[]> {
	const isWanted = (name: string) =>
		!options.kinds || options.kinds.includes(name as AdminEventKind);
	const wanted = (names: readonly string[]) => names.filter(isWanted);
	const timelockNames = [
		...new Set([...wanted(TIMELOCK_ADMIN_EVENTS), "CallExecuted"]),
	];
	const sources = [
		{
			source: "paymaster" as const,
			address: options.paymaster,
			events: eventsOf(gianoPaymasterAbi, wanted(PAYMASTER_ADMIN_EVENTS)),
		},
		...(options.timelock
			? [
					{
						source: "timelock" as const,
						address: options.timelock,
						events: eventsOf(gianoTimelockAbi, timelockNames),
					},
				]
			: []),
	].filter((entry) => entry.events.length > 0);
	// One request per stake event: a topic filter on `account` needs a single event.
	const stakeEvents = options.entryPoint
		? eventsOf(iEntryPointAbi, wanted(ENTRYPOINT_ADMIN_EVENTS))
		: [];

	const [logs, stakeLogs] = await Promise.all([
		Promise.all(
			sources.map(async ({ source, address, events }) => {
				const found = (await publicClient.getLogs({
					address,
					events,
					fromBlock: range.fromBlock,
					toBlock: range.toBlock,
					strict: true,
				} as never)) as unknown as RawLog[];
				return found.map((log) => decode(source, log, options));
			}),
		),
		Promise.all(
			stakeEvents.map(async (event) => {
				const found = (await publicClient.getLogs({
					address: options.entryPoint,
					event,
					args: { account: options.paymaster },
					fromBlock: range.fromBlock,
					toBlock: range.toBlock,
					strict: true,
				} as never)) as unknown as RawLog[];
				return found.map((log) => decode("entrypoint", log, options));
			}),
		),
	]);
	const decoded = [...logs.flat(), ...stakeLogs.flat()];
	// The transactions in which the timelock executed a call to the paymaster.
	const executedOnPaymaster = new Set(
		decoded
			.filter(
				(event) =>
					event.source === "timelock" &&
					event.kind === "CallExecuted" &&
					event.call &&
					isAddressEqual(event.call.target, options.paymaster),
			)
			.map((event) => event.transactionHash),
	);
	return decoded
		.filter((event) => event.source !== "timelock" || isWanted(event.kind))
		.map((event) =>
			event.source === "paymaster" &&
			executedOnPaymaster.has(event.transactionHash)
				? { ...event, viaTimelock: true as const }
				: event,
		)
		.sort((a, b) =>
			a.blockNumber === b.blockNumber
				? b.logIndex - a.logIndex
				: a.blockNumber > b.blockNumber
					? -1
					: 1,
		);
}

function decode(
	source: AdminEvent["source"],
	log: RawLog,
	options: {
		paymaster: Address;
		decodeCall?: (
			target: Address,
			data: Hex,
		) => DecodedTimelockCall | undefined;
	},
): DecodedEvent {
	const args: Record<string, unknown> = { ...log.args };
	const roleNameOf = (hash: Hex) =>
		source === "paymaster"
			? (roleName(hash) ?? hash)
			: (TIMELOCK_ROLE_BY_HASH.get(hash.toLowerCase()) ?? hash);
	for (const key of ["role", "previousAdminRole", "newAdminRole"])
		if (typeof args[key] === "string") args[key] = roleNameOf(args[key] as Hex);
	if (log.eventName === "ParamChanged" && typeof args.name === "string")
		args.name = PARAM_NAMES.get(args.name as Hex) ?? args.name;
	// A selector names a paymaster function only on the paymaster: the timelock's own grantRole has
	// the paymaster's grantRole's selector.
	if (
		log.eventName === "FunctionDelayChange" &&
		typeof args.selector === "string" &&
		typeof args.target === "string" &&
		isAddressEqual(args.target as Address, options.paymaster)
	)
		args.functionName = FUNCTION_BY_SELECTOR.get(
			(args.selector as string).toLowerCase(),
		);

	const tenantId = args.tenantId as Hex | undefined;
	const call =
		log.eventName === "CallScheduled" || log.eventName === "CallExecuted"
			? {
					target: getAddress(args.target as Address),
					value: args.value as bigint,
					data: args.data as Hex,
					decoded: options.decodeCall?.(
						args.target as Address,
						args.data as Hex,
					),
				}
			: undefined;
	return {
		source,
		kind: log.eventName as AdminEventKind,
		args,
		...(tenantId
			? { tenant: { id: tenantId, uuid: toTenantUuid(tenantId) } }
			: {}),
		...(call ? { call } : {}),
		blockNumber: log.blockNumber,
		logIndex: log.logIndex,
		transactionHash: log.transactionHash,
	};
}

/** The account an event itself names as having acted, if it names one. */
function namedActor(event: DecodedEvent) {
	const named =
		event.kind === "RoleGranted" || event.kind === "RoleRevoked"
			? event.args.sender
			: event.kind === "Paused" || event.kind === "Unpaused"
				? event.args.account
				: event.kind === "TenantEnabledChanged"
					? event.args.actor
					: event.kind === "TenantFunded"
						? event.args.from
						: undefined;
	return typeof named === "string" ? getAddress(named) : undefined;
}

/** Only the timelock can change its own delays, once deployed: the executor is not who did it. */
const isOwnDelayChange = (event: DecodedEvent) =>
	event.source === "timelock" &&
	(event.kind === "MinDelayChange" || event.kind === "FunctionDelayChange");

/**
 * Adds each event's block time, transaction sender and actor: one block read per distinct block and,
 * for the events that do not name who acted, one transaction read per distinct transaction. Blocks
 * and transactions are each read five at a time, so up to ten requests at once. A read that fails
 * leaves its fields `undefined` rather than failing the list.
 */
export async function enrichAdminEvents(
	publicClient: PaymasterPublicClient,
	events: readonly DecodedEvent[],
	contracts: { paymaster: Address; timelock?: Address; entryPoint?: Address },
): Promise<AdminEvent[]> {
	const blocks = [...new Set(events.map((event) => event.blockNumber))];
	// An event that names its actor needs no transaction: anyone can fund a tenant with 1 wei, and
	// a read per such transaction would let them slow the list down.
	const hashes = [
		...new Set(
			events
				.filter((event) => !namedActor(event))
				.map((event) => event.transactionHash),
		),
	];
	const [times, transactions] = await Promise.all([
		inBatches(blocks, async (blockNumber) =>
			Number((await publicClient.getBlock({ blockNumber })).timestamp),
		),
		inBatches(hashes, async (hash) => {
			const transaction = await publicClient.getTransaction({ hash });
			return { from: transaction.from, to: transaction.to ?? undefined };
		}),
	]);
	return events.map((event) => {
		const transaction = transactions.get(event.transactionHash);
		// The stake is the paymaster's: whoever called the paymaster changed it.
		const emitter =
			event.source === "timelock" ? contracts.timelock : contracts.paymaster;
		let called: Address | undefined;
		if (transaction && emitter) {
			if (!transaction.to || isAddressEqual(transaction.to, emitter))
				called = getAddress(transaction.from);
			else if (
				!contracts.entryPoint ||
				!isAddressEqual(transaction.to, contracts.entryPoint)
			)
				called = getAddress(transaction.to);
		}
		const timelock = contracts.timelock
			? getAddress(contracts.timelock)
			: undefined;
		// The deploy transaction (no `to`) sets the timelock's first delays: its sender did that.
		const byTimelock =
			(event.viaTimelock ||
				(isOwnDelayChange(event) && transaction?.to !== undefined)) &&
			timelock;
		return {
			...event,
			blockTime: times.get(event.blockNumber),
			from: transaction ? getAddress(transaction.from) : undefined,
			actor: namedActor(event) ?? (byTimelock || undefined) ?? called,
		};
	});
}

async function inBatches<K, V>(
	keys: readonly K[],
	read: (key: K) => Promise<V>,
	size = 5,
): Promise<Map<K, V>> {
	const found = new Map<K, V>();
	for (let start = 0; start < keys.length; start += size)
		await Promise.all(
			keys.slice(start, start + size).map(async (key) => {
				try {
					found.set(key, await read(key));
				} catch {
					// Shown without it; see enrichAdminEvents.
				}
			}),
		);
	return found;
}
