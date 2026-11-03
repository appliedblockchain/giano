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

/** A node serving logs filtered by address, event and range, with blocks and transactions. */
function node(
	logs: readonly Log[],
	transactions: Record<Hash, { from: Address; to: Address }>,
	failing: { blocks?: bigint[] } = {},
) {
	const queries: { address: Address; events: string[] }[] = [];
	const client = {
		getBlockNumber: async () => HEAD,
		getLogs: async ({
			address,
			events,
			fromBlock,
			toBlock,
		}: {
			address: Address;
			events: { name: string }[];
			fromBlock: bigint;
			toBlock: bigint;
		}) => {
			const names = events.map((event) => event.name);
			queries.push({ address, events: names });
			return logs.filter(
				(log) =>
					log.address === address &&
					names.includes(log.eventName) &&
					log.blockNumber >= fromBlock &&
					log.blockNumber <= toBlock,
			);
		},
		getBlock: async ({ blockNumber }: { blockNumber: bigint }) => {
			if (failing.blocks?.includes(blockNumber)) throw new Error("no block");
			return { timestamp: 1_800_000_000n + blockNumber };
		},
		getTransaction: async ({ hash: wanted }: { hash: Hash }) =>
			transactions[wanted],
	};
	return { queries, client: client as unknown as PaymasterPublicClient };
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
const TRANSACTIONS: Record<Hash, { from: Address; to: Address }> = {
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
});
