import {
	encodeTimelockProposal,
	gianoPaymasterAbi,
	gianoTimelockAbi,
	paymasterSelector,
	TIMELOCKED_FUNCTION_NAMES,
} from "@appliedblockchain/giano-contracts";
import {
	type Address,
	decodeFunctionData,
	encodeFunctionData,
	type Hex,
	isAddressEqual,
	parseEther,
	zeroAddress,
	zeroHash,
} from "viem";
import { describe, expect, it } from "vitest";
import type {
	PaymasterPublicClient,
	PaymasterWalletClient,
} from "../src/client";
import { PaymasterSdkError, SignerRequiredError } from "../src/errors";
import { PAYMASTER_ROLES } from "../src/roles";
import {
	GianoTimelockClient,
	TIMELOCK_ROLES,
	type TimelockOperation,
	timelockRoleName,
} from "../src/timelock";

const TIMELOCK = "0x7111111111111111111111111111111111111111" as const;
const PAYMASTER = "0x4Bf0c2F63C4fA20D88B8126298fFFC64710Ece96" as const;
const EXECUTOR = "0x2222222222222222222222222222222222222222" as const;
const TENANT = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const TENANT_HEX = "0x3f2504e04f8911d39a0c0305e82c3301" as const;
const HEAD = 1_000_000n;
const NOW = 1_800_000_000n;
const MIN_DELAY = 300n;

/** Per-function delays as a GianoTimelock would hold them; setTenantFee has none of its own. */
const FUNCTION_DELAYS: Partial<Record<string, bigint>> = {
	upgradeToAndCall: 3600n,
	grantRole: 3600n,
	revokeRole: 3600n,
	renounceRole: 3600n,
	setTenantWithdrawAddress: 1800n,
	setDefaultFee: 1200n,
};

const selectorDelay = (selector: string): bigint => {
	const name = TIMELOCKED_FUNCTION_NAMES.find(
		(candidate) => paymasterSelector(candidate) === selector.slice(0, 10),
	);
	return name ? (FUNCTION_DELAYS[name] ?? 0n) : 0n;
};
const effective = (selector: string): bigint => {
	const own = selectorDelay(selector);
	return own > MIN_DELAY ? own : MIN_DELAY;
};

const paymasterData = (functionName: string, args: readonly unknown[]): Hex =>
	encodeFunctionData({
		abi: gianoPaymasterAbi,
		functionName,
		args,
	} as never);

type Log = {
	eventName: string;
	args: Record<string, unknown>;
	blockNumber: bigint;
	logIndex: number;
	transactionHash: Hex;
};

type ChainOptions = {
	logs?: Log[];
	states?: Record<string, number>;
	timestamps?: Record<string, bigint>;
	executorsOpen?: boolean;
	cap?: bigint;
};

/** A node serving one GianoTimelock and the paymaster it governs. */
function chain(options: ChainOptions = {}) {
	const queries: { fromBlock: bigint; toBlock: bigint }[] = [];
	const simulated: Record<string, unknown>[] = [];
	const read = ({
		address,
		functionName,
		args = [],
	}: {
		address: Address;
		functionName: string;
		args?: readonly unknown[];
	}): unknown => {
		if (isAddressEqual(address, PAYMASTER)) {
			if (functionName === "hasRole")
				return args[0] !== PAYMASTER_ROLES.WITHDRAW_ADDRESS_ADMIN_ROLE;
			throw new Error(`unexpected paymaster read ${functionName}`);
		}
		switch (functionName) {
			case "getMinDelay":
				return MIN_DELAY;
			case "getFunctionDelay":
				return selectorDelay(args[1] as string);
			case "getEffectiveDelay":
				return effective(args[1] as string);
			case "getDelay":
				return effective(args[1] as string);
			case "getBatchDelay":
				return (args[1] as string[])
					.map(effective)
					.reduce(
						(longest, each) => (each > longest ? each : longest),
						MIN_DELAY,
					);
			case "hasRole":
				return (
					args[0] === TIMELOCK_ROLES.EXECUTOR_ROLE &&
					args[1] === zeroAddress &&
					(options.executorsOpen ?? true)
				);
			case "getOperationState":
				return options.states?.[(args[0] as string).toLowerCase()] ?? 0;
			case "getTimestamp":
				return options.timestamps?.[(args[0] as string).toLowerCase()] ?? 0n;
		}
		throw new Error(`unexpected timelock read ${functionName}`);
	};

	const client = {
		chain: undefined,
		getChainId: async () => 84532,
		getBlockNumber: async () => HEAD,
		getBlock: async () => ({ number: HEAD, timestamp: NOW }),
		readContract: async (params: Parameters<typeof read>[0]) => read(params),
		getContractEvents: async ({
			fromBlock,
			toBlock,
		}: {
			fromBlock: bigint;
			toBlock: bigint;
		}) => {
			if (options.cap && toBlock - fromBlock + 1n > options.cap)
				throw new Error("eth_getLogs is limited to a 10,000 range");
			queries.push({ fromBlock, toBlock });
			return (options.logs ?? []).filter(
				(log) => log.blockNumber >= fromBlock && log.blockNumber <= toBlock,
			);
		},
		simulateContract: async (params: Record<string, unknown>) => {
			simulated.push(params);
			return { request: params };
		},
		waitForTransactionReceipt: async () => ({ status: "success" }),
	};
	return {
		queries,
		simulated,
		client: client as unknown as PaymasterPublicClient,
	};
}

const wallet = () => {
	const written: unknown[] = [];
	const walletClient = {
		account: { address: EXECUTOR },
		chain: undefined,
		writeContract: async (request: unknown) => {
			written.push(request);
			return `0x${"ab".repeat(32)}`;
		},
	} as unknown as PaymasterWalletClient;
	return { written, walletClient };
};

const timelock = (
	client: PaymasterPublicClient,
	walletClient?: PaymasterWalletClient,
) =>
	new GianoTimelockClient({
		address: TIMELOCK,
		paymaster: PAYMASTER,
		publicClient: client,
		walletClient,
	});

const SALT = `0x${"5a".repeat(32)}` as Hex;
const TX = `0x${"cd".repeat(32)}` as Hex;

const fee = paymasterData("setDefaultFee", [parseEther("0.0002")]);
const grant = paymasterData("grantRole", [
	PAYMASTER_ROLES.FEE_ADMIN_ROLE,
	EXECUTOR,
]);
const withdraw = paymasterData("setTenantWithdrawAddress", [
	TENANT_HEX,
	EXECUTOR,
]);

// Real ids, as the timelock hashes them: executing rebuilds the id from the logs and checks it.
const ID_SINGLE = encodeTimelockProposal({
	timelock: TIMELOCK,
	calls: [{ target: PAYMASTER, data: fee }],
	delay: 1200n,
}).id;
const ID_BATCH = encodeTimelockProposal({
	timelock: TIMELOCK,
	calls: [
		{ target: PAYMASTER, data: grant },
		{ target: PAYMASTER, data: withdraw },
	],
	delay: 3600n,
	salt: SALT,
}).id;
const ID_CANCELLED = `0x${"33".repeat(32)}` as Hex;

/** One single-call operation (ready), one batch (waiting, salted), one cancelled. */
function scheduledLogs(): Log[] {
	const log = (
		eventName: string,
		args: Record<string, unknown>,
		blockNumber: bigint,
		logIndex = 0,
	): Log => ({ eventName, args, blockNumber, logIndex, transactionHash: TX });
	return [
		log(
			"CallScheduled",
			{
				id: ID_SINGLE,
				index: 0n,
				target: PAYMASTER,
				value: 0n,
				data: fee,
				predecessor: zeroHash,
				delay: 1200n,
			},
			HEAD - 100n,
		),
		log(
			"CallScheduled",
			{
				id: ID_BATCH,
				index: 0n,
				target: PAYMASTER,
				value: 0n,
				data: grant,
				predecessor: zeroHash,
				delay: 3600n,
			},
			HEAD - 50n,
			0,
		),
		log(
			"CallScheduled",
			{
				id: ID_BATCH,
				index: 1n,
				target: PAYMASTER,
				value: 0n,
				data: withdraw,
				predecessor: zeroHash,
				delay: 3600n,
			},
			HEAD - 50n,
			1,
		),
		log("CallSalt", { id: ID_BATCH, salt: SALT }, HEAD - 50n, 2),
		log(
			"CallScheduled",
			{
				id: ID_CANCELLED,
				index: 0n,
				target: PAYMASTER,
				value: 0n,
				data: fee,
				predecessor: zeroHash,
				delay: 1200n,
			},
			HEAD - 40n,
		),
		log("Cancelled", { id: ID_CANCELLED }, HEAD - 30n),
		// Another contract's event in the same window is ignored.
		log("RoleGranted", { role: zeroHash }, HEAD - 20n),
	];
}

const STATES = {
	[ID_SINGLE]: 2, // Ready
	[ID_BATCH]: 1, // Waiting
	[ID_CANCELLED]: 0, // Unset: cancelling deletes it
};
const TIMESTAMPS = {
	[ID_SINGLE]: NOW - 10n,
	[ID_BATCH]: NOW + 3000n,
};

describe("timelock roles", () => {
	it("hashes the timelock's roles as OpenZeppelin does", () => {
		// `cast keccak PROPOSER_ROLE` etc.
		expect(TIMELOCK_ROLES).toEqual({
			PROPOSER_ROLE:
				"0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1",
			EXECUTOR_ROLE:
				"0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63",
			CANCELLER_ROLE:
				"0xfd643c72710c63c0180259aba6b2d05451e3591a24e58b62239378085726f783",
		});
		expect(timelockRoleName(TIMELOCK_ROLES.CANCELLER_ROLE)).toBe(
			"CANCELLER_ROLE",
		);
	});
});

describe("getConfig", () => {
	it("reads minDelay and every timelocked function's own and effective delay", async () => {
		const { client } = chain();
		const config = await timelock(client).getConfig();

		expect(config.minDelay).toBe(MIN_DELAY);
		expect(config.functions.map((entry) => entry.functionName)).toEqual(
			TIMELOCKED_FUNCTION_NAMES,
		);
		const byName = Object.fromEntries(
			config.functions.map((entry) => [entry.functionName, entry]),
		);
		expect(byName.setDefaultFee).toMatchObject({
			functionDelay: 1200n,
			effectiveDelay: 1200n,
			role: "FEE_ADMIN_ROLE",
		});
		// No delay of its own: it waits the floor.
		expect(byName.setTenantFee).toMatchObject({
			functionDelay: 0n,
			effectiveDelay: MIN_DELAY,
		});
		expect(byName.setTenantWithdrawAddress.role).toBe(
			"WITHDRAW_ADDRESS_ADMIN_ROLE",
		);
	});

	it("reports whether executors are open and which roles the timelock holds", async () => {
		const { client } = chain({ executorsOpen: false });
		const config = await timelock(client).getConfig();

		expect(config.executorsOpen).toBe(false);
		expect(config.holdsRole).toEqual({
			ROLE_ADMIN: true,
			UPGRADER_ROLE: true,
			FEE_ADMIN_ROLE: true,
			WITHDRAW_ADDRESS_ADMIN_ROLE: false,
		});
	});
});

describe("getOperations", () => {
	it("reassembles operations from the logs, with state and ETA from the contract", async () => {
		const { client } = chain({
			logs: scheduledLogs(),
			states: STATES,
			timestamps: TIMESTAMPS,
		});
		const { operations } = await timelock(client).getOperations();

		const byId = Object.fromEntries(
			operations.map((operation) => [operation.id, operation]),
		);
		expect(operations).toHaveLength(3);

		const single = byId[ID_SINGLE];
		expect(single).toMatchObject({
			state: "ready",
			readyAt: Number(NOW - 10n),
			delay: 1200n,
			salt: zeroHash,
			complete: true,
		});
		expect(single.calls[0].decoded).toMatchObject({
			contract: "paymaster",
			functionName: "setDefaultFee",
			summary: "set the default fee to 0.0002 ETH",
		});

		const batch = byId[ID_BATCH];
		expect(batch).toMatchObject({
			state: "waiting",
			readyAt: Number(NOW + 3000n),
			salt: SALT,
			complete: true,
		});
		expect(batch.calls.map((call) => call.decoded?.summary)).toEqual([
			`grant FEE_ADMIN_ROLE on the paymaster to ${EXECUTOR}`,
			`point tenant ${TENANT}'s withdrawals at ${EXECUTOR}`,
		]);

		// Cancelling deletes the operation on-chain; the log is what tells it apart from "never was".
		expect(byId[ID_CANCELLED]).toMatchObject({
			state: "cancelled",
			readyAt: undefined,
			cancelledBlock: HEAD - 30n,
		});
	});

	it("lists newest activity first", async () => {
		const { client } = chain({ logs: scheduledLogs(), states: STATES });
		const { operations } = await timelock(client).getOperations();
		expect(operations.map((operation) => operation.id)).toEqual([
			ID_CANCELLED,
			ID_BATCH,
			ID_SINGLE,
		]);
	});

	it("reads all four events in one query per window, back as many windows as asked", async () => {
		const { client, queries } = chain();
		const page = await timelock(client).getOperations({ windows: 3 });

		expect(queries).toEqual([
			{ fromBlock: HEAD - 8_999n, toBlock: HEAD },
			{ fromBlock: HEAD - 17_999n, toBlock: HEAD - 9_000n },
			{ fromBlock: HEAD - 26_999n, toBlock: HEAD - 18_000n },
		]);
		expect(page).toMatchObject({ fromBlock: HEAD - 26_999n, toBlock: HEAD });
		expect(page.older?.toBlock).toBe(HEAD - 27_000n);
	});

	it("narrows to the node's cap as every other log read does", async () => {
		const { client } = chain({ cap: 2_000n });
		const page = await timelock(client).getOperations();
		expect(page.toBlock - page.fromBlock + 1n).toBe(1_125n);
	});

	it("marks an operation scheduled before the window as incomplete", async () => {
		const executedOnly: Log = {
			eventName: "CallExecuted",
			args: {
				id: ID_SINGLE,
				index: 0n,
				target: PAYMASTER,
				value: 0n,
				data: paymasterData("setDefaultFee", [1n]),
			},
			blockNumber: HEAD - 5n,
			logIndex: 0,
			transactionHash: TX,
		};
		const { client } = chain({
			logs: [executedOnly],
			states: { [ID_SINGLE]: 3 },
			timestamps: { [ID_SINGLE]: 1n },
		});
		const [operation] = (await timelock(client).getOperations()).operations;
		expect(operation).toMatchObject({
			state: "done",
			readyAt: undefined,
			complete: false,
			executedBlock: HEAD - 5n,
		});
		expect(operation.calls[0].decoded?.functionName).toBe("setDefaultFee");
	});
});

describe("proposals", () => {
	it("schedules with the delay the timelock demands for that function", async () => {
		const { client } = chain();
		const proposal = await timelock(client).proposeSetDefaultFee(
			parseEther("0.0002"),
		);

		expect(proposal.requiredDelay).toBe(1200n);
		expect(proposal.delay).toBe(1200n);
		expect(proposal.readyAtIfScheduledNow).toBe(Number(NOW + 1200n));
		expect(proposal.summary).toBe("set the default fee to 0.0002 ETH");

		const schedule = decodeFunctionData({
			abi: gianoTimelockAbi,
			data: proposal.schedule,
		});
		expect(schedule.functionName).toBe("schedule");
		expect(schedule.args?.[0]).toBe(PAYMASTER);
		expect(schedule.args?.[5]).toBe(1200n);
		expect(
			decodeFunctionData({
				abi: gianoPaymasterAbi,
				data: schedule.args?.[2] as Hex,
			}),
		).toMatchObject({
			functionName: "setDefaultFee",
			args: [parseEther("0.0002")],
		});
	});

	it("encodes each timelocked action against the right function", async () => {
		const { client } = chain();
		const client_ = timelock(client);
		const cases = await Promise.all([
			client_.proposeSetTenantFee(TENANT, true, 5n),
			client_.proposeSetTenantWithdrawAddress(TENANT, EXECUTOR),
			client_.proposeGrantRole("PAUSER_ROLE", EXECUTOR),
			client_.proposeRevokeRole("PAUSER_ROLE", EXECUTOR),
			client_.proposeUpgrade(EXECUTOR),
		]);
		expect(
			cases.map((proposal) => [
				proposal.decoded[0]?.functionName,
				proposal.requiredDelay,
			]),
		).toEqual([
			["setTenantFee", MIN_DELAY],
			["setTenantWithdrawAddress", 1800n],
			["grantRole", 3600n],
			["revokeRole", 3600n],
			["upgradeToAndCall", 3600n],
		]);
		expect(cases[0].decoded[0]?.args).toEqual([TENANT_HEX, true, 5n]);
	});

	it("asks for the batch delay — the longest of its calls — for several calls", async () => {
		const { client } = chain();
		const client_ = timelock(client);
		const proposal = await client_.propose([
			client_.paymasterCall("setTenantFee", [TENANT_HEX, false, 0n]),
			client_.paymasterCall("setTenantWithdrawAddress", [TENANT_HEX, EXECUTOR]),
		]);
		expect(proposal.requiredDelay).toBe(1800n);
		expect(
			decodeFunctionData({ abi: gianoTimelockAbi, data: proposal.schedule })
				.functionName,
		).toBe("scheduleBatch");
	});

	it("is reproducible under a given salt, and unique by default", async () => {
		const { client } = chain();
		const client_ = timelock(client);
		const [a, b, c, d] = await Promise.all([
			client_.proposeSetDefaultFee(1n, { salt: SALT }),
			client_.proposeSetDefaultFee(1n, { salt: SALT }),
			client_.proposeSetDefaultFee(1n),
			client_.proposeSetDefaultFee(1n),
		]);
		expect(a.id).toBe(b.id);
		expect(a.salt).toBe(SALT);
		expect(c.id).not.toBe(d.id);
	});

	it("refuses a delay shorter than the timelock would accept", async () => {
		const { client } = chain();
		await expect(
			timelock(client).proposeSetDefaultFee(1n, { delay: 60n }),
		).rejects.toThrow(/shorter than the 20m the timelock requires/);
	});

	it("refuses to propose an id that already exists", async () => {
		const { client } = chain();
		const first = await timelock(client).proposeSetDefaultFee(1n, {
			salt: SALT,
		});
		const { client: busy } = chain({ states: { [first.id]: 1 } });
		await expect(
			timelock(busy).proposeSetDefaultFee(1n, { salt: SALT }),
		).rejects.toThrow(/already exists on the timelock \(waiting\)/);
	});

	it("builds the Safe Transaction Builder file for each step", async () => {
		const { client } = chain();
		const client_ = timelock(client);
		const proposal = await client_.proposeSetDefaultFee(1n);

		const batch = client_.safeBatch(proposal);
		expect(batch).toMatchObject({
			version: "1.0",
			chainId: "84532",
			transactions: [{ to: TIMELOCK, value: "0", data: proposal.schedule }],
		});
		expect(batch.meta.description).toContain("set the default fee");
		expect(client_.safeBatch(proposal, "execute").transactions[0].data).toBe(
			proposal.execute,
		);
	});
});

describe("executeOperation", () => {
	it("rebuilds a single call from its logs and sends execute", async () => {
		const { client, simulated } = chain({
			logs: scheduledLogs(),
			states: STATES,
			timestamps: TIMESTAMPS,
		});
		const { walletClient, written } = wallet();
		const result = await timelock(client, walletClient).executeOperation(
			ID_SINGLE,
		);

		expect(result.hash).toMatch(/^0x/);
		expect(written).toHaveLength(1);
		expect(simulated[0]).toMatchObject({
			address: TIMELOCK,
			functionName: "execute",
			args: [
				PAYMASTER,
				0n,
				paymasterData("setDefaultFee", [parseEther("0.0002")]),
				zeroHash,
				zeroHash,
			],
		});
	});

	it("sends executeBatch with the salt from CallSalt for a batch", async () => {
		const { client, simulated } = chain({
			logs: scheduledLogs(),
			states: { ...STATES, [ID_BATCH]: 2 },
			timestamps: TIMESTAMPS,
		});
		const { walletClient } = wallet();
		const client_ = timelock(client, walletClient);
		const operation = (await client_.findOperation(
			ID_BATCH,
		)) as TimelockOperation;
		await client_.executeOperation(operation);

		expect(simulated[0].functionName).toBe("executeBatch");
		const [targets, values, , predecessor, salt] = simulated[0]
			.args as unknown[];
		expect(targets).toEqual([PAYMASTER, PAYMASTER]);
		expect(values).toEqual([0n, 0n]);
		expect(predecessor).toBe(zeroHash);
		expect(salt).toBe(SALT);
	});

	it("says when a waiting operation becomes ready rather than sending it", async () => {
		const { client, simulated } = chain({
			logs: scheduledLogs(),
			states: STATES,
			timestamps: TIMESTAMPS,
		});
		const { walletClient } = wallet();
		await expect(
			timelock(client, walletClient).executeOperation(ID_BATCH),
		).rejects.toThrow(new Date(Number(NOW + 3000n) * 1000).toISOString());
		expect(simulated).toHaveLength(0);
	});

	it("refuses an operation it cannot see, or cannot rebuild", async () => {
		const { client } = chain({ logs: [], states: STATES });
		const { walletClient } = wallet();
		await expect(
			timelock(client, walletClient).executeOperation(ID_SINGLE),
		).rejects.toBeInstanceOf(PaymasterSdkError);
		await expect(
			timelock(client, walletClient).executeOperation({
				id: ID_SINGLE,
				calls: [],
				predecessor: zeroHash,
				salt: zeroHash,
				state: "ready",
				complete: false,
			}),
		).rejects.toThrow(/scheduled before the blocks read/);
	});

	it("refuses logs that do not hash back to the operation's id", async () => {
		const { client, simulated } = chain({ states: STATES });
		const { walletClient } = wallet();
		const tampered: TimelockOperation = {
			id: ID_SINGLE,
			calls: [{ target: PAYMASTER, value: 0n, data: grant }],
			predecessor: zeroHash,
			salt: zeroHash,
			delay: 1200n,
			state: "ready",
			complete: true,
		};
		await expect(
			timelock(client, walletClient).executeOperation(tampered),
		).rejects.toThrow(/does not match/);
		expect(simulated).toHaveLength(0);
	});

	it("rebuilds the execute and cancel calldata for a Safe executor", async () => {
		const { client } = chain({
			logs: scheduledLogs(),
			states: STATES,
			timestamps: TIMESTAMPS,
		});
		const client_ = timelock(client);
		const operation = (await client_.findOperation(
			ID_BATCH,
		)) as TimelockOperation;
		const proposal = client_.toProposal(operation);
		expect(proposal.id).toBe(ID_BATCH);
		expect(
			decodeFunctionData({ abi: gianoTimelockAbi, data: proposal.execute }),
		).toMatchObject({ functionName: "executeBatch" });
	});

	it("needs a wallet", async () => {
		const { client } = chain({
			logs: scheduledLogs(),
			states: STATES,
			timestamps: TIMESTAMPS,
		});
		await expect(
			timelock(client).executeOperation(ID_SINGLE),
		).rejects.toBeInstanceOf(SignerRequiredError);
	});
});
