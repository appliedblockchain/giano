import {
	gianoPaymasterAbi,
	gianoTimelockAbi,
} from "@appliedblockchain/giano-contracts";
import {
	type Address,
	encodeFunctionData,
	type Hash,
	keccak256,
	toBytes,
} from "viem";
import { describe, expect, it } from "vitest";
import {
	ENTRYPOINT_ADMIN_EVENTS,
	PAYMASTER_ADMIN_EVENTS,
	PAYMASTER_OTHER_EVENTS,
	TIMELOCK_ADMIN_EVENTS,
	TIMELOCK_OTHER_EVENTS,
} from "../src/admin-events";
import {
	GianoPaymasterClient,
	type PaymasterPublicClient,
} from "../src/client";
import { PAYMASTER_ROLES } from "../src/roles";

const PAYMASTER = "0x4Bf0c2F63C4fA20D88B8126298fFFC64710Ece96" as const;
const TIMELOCK = "0xf274De14171Ab928A5Ec19928cE35FaD91a42B64" as const;
const EXECUTOR = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as const;
const OPERATOR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as const;
const GRANTEE = "0x2222222222222222222222222222222222222222" as const;
const HEAD = 50_000n;
const TENANT = "0x3f2504e04f8911d39a0c0305e82c3301" as const;
const ENTRY_POINT = "0x433709009B8330FDa32311DF1C2AFA402eD8D009" as const;
const SAFE = "0x5afe5afE5afE5afE5afE5aFe5aFe5Afe5Afe5AfE" as const;

const eventNames = (abi: readonly { type: string; name?: string }[]) =>
	abi
		.filter((item) => item.type === "event")
		.map((item) => item.name as string);

describe("the admin event lists", () => {
	it.each([
		[
			"paymaster",
			gianoPaymasterAbi,
			PAYMASTER_ADMIN_EVENTS,
			PAYMASTER_OTHER_EVENTS,
		],
		[
			"timelock",
			gianoTimelockAbi,
			TIMELOCK_ADMIN_EVENTS,
			TIMELOCK_OTHER_EVENTS,
		],
	] as const)(
		"cover every %s event, so a new privileged event cannot go undecoded",
		(_source, abi, admin, other) => {
			const listed = new Set<string>([...admin, ...Object.keys(other)]);
			const unlisted = eventNames(abi).filter((name) => !listed.has(name));
			expect(
				unlisted,
				`events neither decoded nor excluded: ${unlisted.join(", ")}`,
			).toEqual([]);
			expect(admin.filter((name) => name in other)).toEqual([]);
			// Nothing listed that the ABI no longer has.
			expect(
				[...listed].filter((name) => !eventNames(abi).includes(name)),
			).toEqual([]);
		},
	);
});

type Log = {
	address: Address;
	eventName: string;
	args: Record<string, unknown>;
	blockNumber: bigint;
	logIndex: number;
	transactionHash: Hash;
};

const hash = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as Hash;

/**
 * A node serving logs filtered by address, event (or one event and its indexed `account`) and range,
 * with blocks and transactions, and the paymaster's EntryPoint.
 */
function node(
	logs: readonly Log[],
	transactions: Record<Hash, { from: Address; to: Address | null }>,
	failing: { blocks?: bigint[] } = {},
) {
	const queries: { address: Address; events: string[] }[] = [];
	const transactionReads: Hash[] = [];
	const client = {
		getBlockNumber: async () => HEAD,
		readContract: async ({ functionName }: { functionName: string }) => {
			if (functionName !== "entryPoint") throw new Error(functionName);
			return ENTRY_POINT;
		},
		getLogs: async ({
			address,
			events,
			event,
			args,
			fromBlock,
			toBlock,
		}: {
			address: Address;
			events?: { name: string }[];
			event?: { name: string };
			args?: { account?: Address };
			fromBlock: bigint;
			toBlock: bigint;
		}) => {
			const names = events
				? events.map((entry) => entry.name)
				: [event?.name as string];
			queries.push({ address, events: names });
			return logs.filter(
				(log) =>
					log.address === address &&
					names.includes(log.eventName) &&
					(!args?.account || log.args.account === args.account) &&
					log.blockNumber >= fromBlock &&
					log.blockNumber <= toBlock,
			);
		},
		getBlock: async ({ blockNumber }: { blockNumber: bigint }) => {
			if (failing.blocks?.includes(blockNumber)) throw new Error("no block");
			return { timestamp: 1_800_000_000n + blockNumber };
		},
		getTransaction: async ({ hash: wanted }: { hash: Hash }) => {
			transactionReads.push(wanted);
			return transactions[wanted];
		},
	};
	return {
		queries,
		transactionReads,
		client: client as unknown as PaymasterPublicClient,
	};
}

const grant = encodeFunctionData({
	abi: gianoPaymasterAbi,
	functionName: "grantRole",
	args: [PAYMASTER_ROLES.FEE_COLLECTOR_ROLE, GRANTEE],
});

/** A role granted through the timelock: executed in block 49,990, fee changed by a key at 49,995. */
const LOGS: Log[] = [
	{
		address: TIMELOCK,
		eventName: "CallExecuted",
		args: { id: hash(9), index: 0n, target: PAYMASTER, value: 0n, data: grant },
		blockNumber: 49_990n,
		logIndex: 3,
		transactionHash: hash(1),
	},
	{
		address: PAYMASTER,
		eventName: "RoleGranted",
		args: {
			role: PAYMASTER_ROLES.FEE_COLLECTOR_ROLE,
			account: GRANTEE,
			sender: TIMELOCK,
		},
		blockNumber: 49_990n,
		logIndex: 2,
		transactionHash: hash(1),
	},
	{
		address: PAYMASTER,
		eventName: "ParamChanged",
		args: {
			name: keccak256(toBytes("penaltyBps")),
			oldValue: 1000n,
			newValue: 500n,
		},
		blockNumber: 49_995n,
		logIndex: 0,
		transactionHash: hash(2),
	},
	{
		address: PAYMASTER,
		eventName: "TenantFunded",
		args: {
			tenantId: TENANT,
			from: OPERATOR,
			amount: 10n,
			deficitCleared: 0n,
			newBalance: 10n,
		},
		blockNumber: 49_980n,
		logIndex: 0,
		transactionHash: hash(3),
	},
	{
		address: PAYMASTER,
		eventName: "FeeChanged",
		args: { oldFeeWei: 1n, newFeeWei: 2n },
		blockNumber: 30_000n,
		logIndex: 0,
		transactionHash: hash(4),
	},
];
const TRANSACTIONS: Record<Hash, { from: Address; to: Address | null }> = {
	[hash(1)]: { from: EXECUTOR, to: TIMELOCK },
	[hash(2)]: { from: OPERATOR, to: PAYMASTER },
	[hash(3)]: { from: OPERATOR, to: PAYMASTER },
	[hash(4)]: { from: OPERATOR, to: PAYMASTER },
};

const paymaster = (client: PaymasterPublicClient) =>
	new GianoPaymasterClient({ address: PAYMASTER, publicClient: client });

describe("getAdminEvents", () => {
	it("decodes a role granted through the timelock, with the role's name and the timelock as actor", async () => {
		const { client } = node(LOGS, TRANSACTIONS);
		const { events } = await paymaster(client).getAdminEvents({
			timelock: TIMELOCK,
		});

		const granted = events.find((event) => event.kind === "RoleGranted");
		expect(granted).toMatchObject({
			source: "paymaster",
			args: { role: "FEE_COLLECTOR_ROLE", account: GRANTEE, sender: TIMELOCK },
			actor: TIMELOCK,
			from: EXECUTOR,
			blockTime: 1_800_000_000 + 49_990,
			transactionHash: hash(1),
		});
		const executed = events.find((event) => event.kind === "CallExecuted");
		expect(executed?.source).toBe("timelock");
		expect(executed?.call?.decoded?.functionName).toBe("grantRole");
		expect(executed?.actor).toBe(EXECUTOR);
	});

	it("merges both contracts newest first, by block then position", async () => {
		const { client } = node(LOGS, TRANSACTIONS);
		const { events } = await paymaster(client).getAdminEvents({
			timelock: TIMELOCK,
		});

		expect(events.map((event) => event.kind)).toEqual([
			"ParamChanged",
			"CallExecuted",
			"RoleGranted",
			"TenantFunded",
		]);
		expect(events[0].args.name).toBe("penaltyBps");
		expect(events[0].actor).toBe(OPERATOR);
	});

	it("reads one window and pages back with `older`, until it is absent", async () => {
		const { client } = node(LOGS, TRANSACTIONS);
		const client_ = paymaster(client);
		const first = await client_.getAdminEvents();
		expect(first).toMatchObject({ fromBlock: HEAD - 8_999n, toBlock: HEAD });
		expect(first.events.some((event) => event.kind === "FeeChanged")).toBe(
			false,
		);

		let page = first;
		const seen: string[] = [];
		while (page.older) {
			page = await client_.getAdminEvents({ range: page.older });
			seen.push(...page.events.map((event) => event.kind));
		}
		expect(seen).toContain("FeeChanged");
		expect(page.fromBlock).toBe(0n);
	});

	it("asks the node only for the kinds wanted, and only the paymaster without a timelock", async () => {
		const { client, queries } = node(LOGS, TRANSACTIONS);
		const { events } = await paymaster(client).getAdminEvents({
			kinds: ["ParamChanged", "CallExecuted"],
		});

		expect(queries).toEqual([{ address: PAYMASTER, events: ["ParamChanged"] }]);
		expect(events.map((event) => event.kind)).toEqual(["ParamChanged"]);
	});

	it("narrows to one tenant: its own events, and timelock calls that change it", async () => {
		const setFee = encodeFunctionData({
			abi: gianoPaymasterAbi,
			functionName: "setTenantFee",
			args: [TENANT, true, 5n],
		});
		const scheduled: Log = {
			address: TIMELOCK,
			eventName: "CallScheduled",
			args: {
				id: hash(8),
				index: 0n,
				target: PAYMASTER,
				value: 0n,
				data: setFee,
				predecessor: hash(0),
				delay: 2n,
			},
			blockNumber: 49_985n,
			logIndex: 0,
			transactionHash: hash(5),
		};
		const { client } = node([...LOGS, scheduled], {
			...TRANSACTIONS,
			[hash(5)]: { from: OPERATOR, to: TIMELOCK },
		});
		const { events } = await paymaster(client).getAdminEvents({
			timelock: TIMELOCK,
			tenantId: "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		});

		expect(events.map((event) => event.kind)).toEqual([
			"CallScheduled",
			"TenantFunded",
		]);
		expect(events[1].tenant?.uuid).toBe("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
	});

	it("keeps an event whose block could not be read, without its time", async () => {
		const { client } = node(LOGS, TRANSACTIONS, { blocks: [49_995n] });
		const { events } = await paymaster(client).getAdminEvents();

		expect(events[0].kind).toBe("ParamChanged");
		expect(events[0].blockTime).toBeUndefined();
		expect(events[0].actor).toBe(OPERATOR);
	});
	it("names the timelock for a paymaster change it executed, whoever sent the transaction", async () => {
		// A Safe sends timelock.execute, which sets the fee: FeeChanged names no actor, and the
		// transaction went to the Safe.
		const setFee = encodeFunctionData({
			abi: gianoPaymasterAbi,
			functionName: "setDefaultFee",
			args: [2n],
		});
		const logs: Log[] = [
			{
				address: TIMELOCK,
				eventName: "CallExecuted",
				args: {
					id: hash(7),
					index: 0n,
					target: PAYMASTER,
					value: 0n,
					data: setFee,
				},
				blockNumber: 49_999n,
				logIndex: 1,
				transactionHash: hash(6),
			},
			{
				address: PAYMASTER,
				eventName: "FeeChanged",
				args: { oldFeeWei: 1n, newFeeWei: 2n },
				blockNumber: 49_999n,
				logIndex: 0,
				transactionHash: hash(6),
			},
		];
		const { client, queries } = node(logs, {
			[hash(6)]: { from: OPERATOR, to: SAFE },
		});
		// Only FeeChanged is asked for: CallExecuted is still read, to know who made the change.
		const { events } = await paymaster(client).getAdminEvents({
			timelock: TIMELOCK,
			kinds: ["FeeChanged"],
		});

		expect(events.map((event) => [event.kind, event.actor])).toEqual([
			["FeeChanged", TIMELOCK],
		]);
		expect(events[0].viaTimelock).toBe(true);
		expect(queries).toContainEqual({
			address: TIMELOCK,
			events: ["CallExecuted"],
		});
	});

	it("names the timelock for its own delay changes, except in the transaction that deployed it", async () => {
		const logs: Log[] = [
			{
				address: TIMELOCK,
				eventName: "MinDelayChange",
				args: { oldDuration: 172_800n, newDuration: 3_600n },
				blockNumber: 49_999n,
				logIndex: 0,
				transactionHash: hash(6),
			},
			{
				address: TIMELOCK,
				eventName: "MinDelayChange",
				args: { oldDuration: 0n, newDuration: 172_800n },
				blockNumber: 49_000n,
				logIndex: 0,
				transactionHash: hash(7),
			},
		];
		const { client } = node(logs, {
			// Executors are open: any account can execute a ready operation.
			[hash(6)]: { from: GRANTEE, to: TIMELOCK },
			[hash(7)]: { from: OPERATOR, to: null },
		});
		const { events } = await paymaster(client).getAdminEvents({
			timelock: TIMELOCK,
		});

		expect(events.map((event) => event.actor)).toEqual([TIMELOCK, OPERATOR]);
	});

	it("names a delay change's function only when its target is the paymaster", async () => {
		const selector = encodeFunctionData({
			abi: gianoPaymasterAbi,
			functionName: "grantRole",
			args: [PAYMASTER_ROLES.FEE_COLLECTOR_ROLE, GRANTEE],
		}).slice(0, 10);
		const change = (target: Address, n: number): Log => ({
			address: TIMELOCK,
			eventName: "FunctionDelayChange",
			args: { target, selector, oldDuration: 1n, newDuration: 2n },
			blockNumber: 49_999n,
			logIndex: n,
			transactionHash: hash(6),
		});
		const { client } = node([change(PAYMASTER, 1), change(TIMELOCK, 0)], {
			[hash(6)]: { from: OPERATOR, to: TIMELOCK },
		});
		const { events } = await paymaster(client).getAdminEvents({
			timelock: TIMELOCK,
		});

		expect(events.map((event) => event.args.functionName)).toEqual([
			"grantRole",
			undefined,
		]);
	});

	it("lists the paymaster's stake changes from the EntryPoint, and no other account's", async () => {
		const stake = (account: Address, n: number): Log => ({
			address: ENTRY_POINT,
			eventName: "StakeUnlocked",
			args: { account, withdrawTime: 1_800_100_000n },
			blockNumber: 49_999n,
			logIndex: n,
			transactionHash: hash(6 + n),
		});
		const { client, queries } = node([stake(PAYMASTER, 0), stake(GRANTEE, 1)], {
			[hash(6)]: { from: OPERATOR, to: PAYMASTER },
			[hash(7)]: { from: GRANTEE, to: ENTRY_POINT },
		});
		const { events } = await paymaster(client).getAdminEvents();

		expect(
			events.map((event) => [event.source, event.kind, event.actor]),
		).toEqual([["entrypoint", "StakeUnlocked", OPERATOR]]);
		for (const name of ENTRYPOINT_ADMIN_EVENTS)
			expect(queries).toContainEqual({ address: ENTRY_POINT, events: [name] });
	});

	it("takes a funding's actor from the event, without reading its transaction", async () => {
		const { client, transactionReads } = node(LOGS, TRANSACTIONS);
		const { events } = await paymaster(client).getAdminEvents({
			kinds: ["TenantFunded"],
		});

		expect(events.map((event) => event.actor)).toEqual([OPERATOR]);
		expect(transactionReads).toEqual([]);
	});

	it("names no actor for a change sent through the EntryPoint", async () => {
		// A smart wallet holding SIGNER_ADMIN_ROLE adds a key: SignerAdded names nobody, and the
		// bundler sent the transaction to the EntryPoint.
		const logs: Log[] = [
			{
				address: PAYMASTER,
				eventName: "SignerAdded",
				args: { signer: GRANTEE },
				blockNumber: 49_999n,
				logIndex: 0,
				transactionHash: hash(6),
			},
		];
		const { client } = node(logs, {
			[hash(6)]: { from: EXECUTOR, to: ENTRY_POINT },
		});
		const { events } = await paymaster(client).getAdminEvents();

		expect(events[0].actor).toBeUndefined();
	});

	it("keeps, on a tenant's page, the cancellation of an operation that changed it", async () => {
		const setFee = encodeFunctionData({
			abi: gianoPaymasterAbi,
			functionName: "setTenantFee",
			args: [TENANT, true, 5n],
		});
		const logs: Log[] = [
			{
				address: TIMELOCK,
				eventName: "CallScheduled",
				args: {
					id: hash(8),
					index: 0n,
					target: PAYMASTER,
					value: 0n,
					data: setFee,
					predecessor: hash(0),
					delay: 2n,
				},
				blockNumber: 49_985n,
				logIndex: 0,
				transactionHash: hash(5),
			},
			{
				address: TIMELOCK,
				eventName: "Cancelled",
				args: { id: hash(8) },
				blockNumber: 49_986n,
				logIndex: 0,
				transactionHash: hash(6),
			},
			{
				address: TIMELOCK,
				eventName: "Cancelled",
				args: { id: hash(9) },
				blockNumber: 49_987n,
				logIndex: 0,
				transactionHash: hash(7),
			},
		];
		const { client } = node(logs, {
			[hash(5)]: { from: OPERATOR, to: TIMELOCK },
			[hash(6)]: { from: OPERATOR, to: TIMELOCK },
			[hash(7)]: { from: OPERATOR, to: TIMELOCK },
		});
		const { events } = await paymaster(client).getAdminEvents({
			timelock: TIMELOCK,
			tenantId: TENANT,
		});

		expect(events.map((event) => [event.kind, event.args.id])).toEqual([
			["Cancelled", hash(8)],
			["CallScheduled", hash(8)],
		]);
	});
});
