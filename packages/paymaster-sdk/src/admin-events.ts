import {
	gianoPaymasterAbi,
	gianoTimelockAbi,
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

export type AdminEventKind =
	| (typeof PAYMASTER_ADMIN_EVENTS)[number]
	| (typeof TIMELOCK_ADMIN_EVENTS)[number];

/** One privileged event, decoded. */
export type AdminEvent = {
	source: "paymaster" | "timelock";
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
	blockNumber: bigint;
	logIndex: number;
	transactionHash: Hash;
	/** Unix seconds; `undefined` when the block could not be read. */
	blockTime: number | undefined;
	/** The transaction's sender; `undefined` when the transaction could not be read. */
	from: Address | undefined;
	/**
	 * Who made the change: the account the event names (a role change's `sender`, a pause's
	 * `account`, an enable's `actor`) or, failing that, whoever called the contract — the
	 * transaction's sender when it was sent to the contract, otherwise the contract it was sent to
	 * (the timelock executing, a Safe). Nested calls beyond one hop are not traced.
	 */
	actor: Address | undefined;
};

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
 * The admin events of `paymaster` (and of `timelock`, when given) in `range`, decoded and newest
 * first, without block times or senders: {@link enrichAdminEvents} adds those.
 */
export async function readAdminEvents(
	publicClient: PaymasterPublicClient,
	range: { fromBlock: bigint; toBlock: bigint },
	options: {
		paymaster: Address;
		timelock?: Address;
		kinds?: readonly AdminEventKind[];
		decodeCall?: (
			target: Address,
			data: Hex,
		) => DecodedTimelockCall | undefined;
	},
): Promise<Omit<AdminEvent, "blockTime" | "from" | "actor">[]> {
	const wanted = (names: readonly string[]) =>
		options.kinds
			? names.filter((name) => options.kinds?.includes(name as AdminEventKind))
			: names;
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
						events: eventsOf(gianoTimelockAbi, wanted(TIMELOCK_ADMIN_EVENTS)),
					},
				]
			: []),
	].filter((entry) => entry.events.length > 0);

	const logs = await Promise.all(
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
	);
	return logs
		.flat()
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
		decodeCall?: (
			target: Address,
			data: Hex,
		) => DecodedTimelockCall | undefined;
	},
): Omit<AdminEvent, "blockTime" | "from" | "actor"> {
	const args: Record<string, unknown> = { ...log.args };
	const roleNameOf = (hash: Hex) =>
		source === "paymaster"
			? (roleName(hash) ?? hash)
			: (TIMELOCK_ROLE_BY_HASH.get(hash.toLowerCase()) ?? hash);
	for (const key of ["role", "previousAdminRole", "newAdminRole"])
		if (typeof args[key] === "string") args[key] = roleNameOf(args[key] as Hex);
	if (log.eventName === "ParamChanged" && typeof args.name === "string")
		args.name = PARAM_NAMES.get(args.name as Hex) ?? args.name;
	if (
		log.eventName === "FunctionDelayChange" &&
		typeof args.selector === "string"
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
function namedActor(event: Omit<AdminEvent, "blockTime" | "from" | "actor">) {
	const named =
		event.kind === "RoleGranted" || event.kind === "RoleRevoked"
			? event.args.sender
			: event.kind === "Paused" || event.kind === "Unpaused"
				? event.args.account
				: event.kind === "TenantEnabledChanged"
					? event.args.actor
					: undefined;
	return typeof named === "string" ? getAddress(named) : undefined;
}

/**
 * Adds each event's block time, transaction sender and actor: one block read per distinct block and
 * one transaction read per distinct transaction, a few at a time. A read that fails leaves its
 * fields `undefined` rather than failing the list.
 */
export async function enrichAdminEvents(
	publicClient: PaymasterPublicClient,
	events: readonly Omit<AdminEvent, "blockTime" | "from" | "actor">[],
	contracts: { paymaster: Address; timelock?: Address },
): Promise<AdminEvent[]> {
	const blocks = [...new Set(events.map((event) => event.blockNumber))];
	const hashes = [...new Set(events.map((event) => event.transactionHash))];
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
		const emitter =
			event.source === "paymaster" ? contracts.paymaster : contracts.timelock;
		const called =
			transaction && emitter
				? transaction.to && !isAddressEqual(transaction.to, emitter)
					? getAddress(transaction.to)
					: getAddress(transaction.from)
				: undefined;
		return {
			...event,
			blockTime: times.get(event.blockNumber),
			from: transaction ? getAddress(transaction.from) : undefined,
			actor: namedActor(event) ?? called,
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
