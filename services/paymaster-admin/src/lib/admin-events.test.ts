import {
	type AdminEvent,
	type AdminEventKind,
	ENTRYPOINT_ADMIN_EVENTS,
	PAYMASTER_ADMIN_EVENTS,
	TIMELOCK_ADMIN_EVENTS,
} from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import {
	describeAdminEvent,
	eventGroup,
	type Namer,
	shortAddress,
} from "./admin-events";

const KEY = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const OTHER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
const ZERO = "0x0000000000000000000000000000000000000000";
const OP = `0x${"cd".repeat(32)}`;

const namer: Namer = {
	address: (address) => shortAddress(address, address === KEY ? ["you"] : []),
	tenant: (uuid) => (uuid === UUID ? "acme" : uuid),
	money: (wei) => `${wei} wei`,
	time: (unix) => `t${unix}`,
};

const event = (
	kind: AdminEventKind,
	args: Record<string, unknown>,
	extra: Partial<AdminEvent> = {},
): AdminEvent => ({
	source: "paymaster",
	kind,
	args,
	blockNumber: 1n,
	logIndex: 0,
	transactionHash: `0x${"ab".repeat(32)}`,
	blockTime: 1_800_000_000,
	from: KEY,
	actor: KEY,
	...extra,
});

const tenant = {
	tenant: { id: "0x3f2504e04f8911d39a0c0305e82c3301" as const, uuid: UUID },
};

describe("describeAdminEvent", () => {
	it("says what each change did, naming roles, tenants and addresses", () => {
		expect(
			describeAdminEvent(
				event("RoleGranted", {
					role: "FEE_COLLECTOR_ROLE",
					account: OTHER,
					sender: KEY,
				}),
				namer,
			),
		).toBe("granted FEE_COLLECTOR_ROLE to 0x7099…79C8");
		expect(
			describeAdminEvent(
				event("RoleRevoked", {
					role: "PAUSER_ROLE",
					account: KEY,
					sender: KEY,
				}),
				namer,
			),
		).toBe("renounced PAUSER_ROLE");
		expect(
			describeAdminEvent(
				event("TenantFunded", { amount: 10n, deficitCleared: 3n }, tenant),
				namer,
			),
		).toBe("funded acme with 10 wei, clearing a 3 wei deficit");
		expect(
			describeAdminEvent(
				event(
					"TenantWithdrawAddressChanged",
					{ oldAddress: KEY, newAddress: OTHER },
					tenant,
				),
				namer,
			),
		).toBe(
			"changed acme's withdrawal address from you (0xf39F…2266) to 0x7099…79C8",
		);
		expect(
			describeAdminEvent(
				event("ParamChanged", {
					name: "penaltyBps",
					oldValue: 1000n,
					newValue: 500n,
				}),
				namer,
			),
		).toBe("changed penaltyBps from 1000 to 500");
	});

	it("reads a timelock call by its decoded summary, and the delay it waits", () => {
		const scheduled = event(
			"CallScheduled",
			{ delay: 7200n },
			{
				source: "timelock",
				call: {
					target: OTHER,
					value: 0n,
					data: "0x",
					decoded: {
						contract: "paymaster",
						functionName: "setDefaultFee",
						args: [1n],
						summary: "set the default fee to 0.0002 ETH",
					},
				},
			},
		);
		expect(describeAdminEvent(scheduled, namer)).toBe(
			"scheduled: set the default fee to 0.0002 ETH, to wait 2h",
		);
		expect(
			describeAdminEvent(
				event(
					"RoleGranted",
					{ role: "PROPOSER_ROLE", account: OTHER, sender: KEY },
					{ source: "timelock" },
				),
				namer,
			),
		).toBe("granted PROPOSER_ROLE on the timelock to 0x7099…79C8");
		expect(
			describeAdminEvent(
				event(
					"RoleGranted",
					{
						role: "EXECUTOR_ROLE",
						account: "0x0000000000000000000000000000000000000000",
						sender: KEY,
					},
					{ source: "timelock" },
				),
				namer,
			),
		).toBe("opened EXECUTOR_ROLE on the timelock to anyone");
	});
});

/** One example of every kind each source emits, and the exact sentence it reads as. */
const SENTENCES: [
	AdminEvent["source"],
	AdminEventKind,
	Record<string, unknown>,
	string,
][] = [
	[
		"paymaster",
		"RoleGranted",
		{ role: "FEE_COLLECTOR_ROLE", account: OTHER, sender: KEY },
		"granted FEE_COLLECTOR_ROLE to 0x7099…79C8",
	],
	[
		"paymaster",
		"RoleGranted",
		{ role: "PAUSER_ROLE", account: ZERO, sender: KEY },
		"granted PAUSER_ROLE to 0x0000…0000",
	],
	[
		"paymaster",
		"RoleRevoked",
		{ role: "PAUSER_ROLE", account: OTHER, sender: KEY },
		"revoked PAUSER_ROLE from 0x7099…79C8",
	],
	[
		"paymaster",
		"RoleAdminChanged",
		{
			role: "PAUSER_ROLE",
			previousAdminRole: "DEFAULT_ADMIN_ROLE",
			newAdminRole: "ROLE_ADMIN",
		},
		"made ROLE_ADMIN the admin of PAUSER_ROLE",
	],
	[
		"paymaster",
		"FeeChanged",
		{ oldFeeWei: 1n, newFeeWei: 2n },
		"changed the default fee from 1 wei to 2 wei",
	],
	[
		"paymaster",
		"TenantFeeChanged",
		{ hasOverride: true, feeWei: 5n },
		"set acme's fee to 5 wei",
	],
	[
		"paymaster",
		"TenantFeeChanged",
		{ hasOverride: false, feeWei: 0n },
		"removed acme's fee override",
	],
	[
		"paymaster",
		"ParamChanged",
		{ name: "penaltyBps", oldValue: 1000n, newValue: 500n },
		"changed penaltyBps from 1000 to 500",
	],
	["paymaster", "Paused", { account: KEY }, "paused new sponsorships"],
	["paymaster", "Unpaused", { account: KEY }, "unpaused sponsorships"],
	[
		"paymaster",
		"SignerAdded",
		{ signer: OTHER },
		"added the signing key 0x7099…79C8",
	],
	[
		"paymaster",
		"SignerRemoved",
		{ signer: OTHER },
		"removed the signing key 0x7099…79C8",
	],
	[
		"paymaster",
		"Upgraded",
		{ implementation: OTHER },
		"upgraded the paymaster to 0x7099…79C8",
	],
	[
		"paymaster",
		"TenantRegistered",
		{ withdrawAddress: OTHER, slug: "acme" },
		"registered acme, withdrawing to 0x7099…79C8",
	],
	[
		"paymaster",
		"TenantEnabledChanged",
		{ enabled: false, actor: KEY },
		"disabled acme",
	],
	[
		"paymaster",
		"TenantFunded",
		{ from: KEY, amount: 10n, deficitCleared: 0n },
		"funded acme with 10 wei",
	],
	[
		"paymaster",
		"TenantWithdrawn",
		{ to: OTHER, amount: 4n },
		"withdrew 4 wei from acme to 0x7099…79C8",
	],
	[
		"paymaster",
		"TenantWithdrawAddressChanged",
		{ oldAddress: KEY, newAddress: OTHER },
		"changed acme's withdrawal address from you (0xf39F…2266) to 0x7099…79C8",
	],
	[
		"paymaster",
		"FeesWithdrawn",
		{ to: OTHER, amount: 7n },
		"withdrew 7 wei of platform fees to 0x7099…79C8",
	],
	[
		"timelock",
		"CallScheduled",
		{ id: OP, delay: 7200n },
		"scheduled: a call to 0x7099…79C8, to wait 2h",
	],
	["timelock", "CallExecuted", { id: OP }, "executed: a call to 0x7099…79C8"],
	["timelock", "Cancelled", { id: OP }, "cancelled operation 0xcdcdcdcd…"],
	[
		"timelock",
		"MinDelayChange",
		{ oldDuration: 172_800n, newDuration: 3_600n },
		"changed the minimum delay from 2d to 1h",
	],
	[
		"timelock",
		"FunctionDelayChange",
		{
			target: OTHER,
			selector: "0x2f2ff15d",
			functionName: "grantRole",
			oldDuration: 3_600n,
			newDuration: 7_200n,
		},
		"changed the delay of grantRole from 1h to 2h",
	],
	[
		"timelock",
		"FunctionDelayChange",
		{
			target: KEY,
			selector: "0x2f2ff15d",
			oldDuration: 3_600n,
			newDuration: 7_200n,
		},
		"changed the delay of 0x2f2ff15d on you (0xf39F…2266) from 1h to 2h",
	],
	[
		"timelock",
		"RoleGranted",
		{ role: "EXECUTOR_ROLE", account: ZERO, sender: KEY },
		"opened EXECUTOR_ROLE on the timelock to anyone",
	],
	[
		"timelock",
		"RoleGranted",
		{ role: "PROPOSER_ROLE", account: ZERO, sender: KEY },
		"granted PROPOSER_ROLE on the timelock to 0x0000…0000",
	],
	[
		"timelock",
		"RoleRevoked",
		{ role: "PROPOSER_ROLE", account: OTHER, sender: KEY },
		"revoked PROPOSER_ROLE on the timelock from 0x7099…79C8",
	],
	[
		"timelock",
		"RoleAdminChanged",
		{
			role: "PROPOSER_ROLE",
			previousAdminRole: "DEFAULT_ADMIN_ROLE",
			newAdminRole: "PROPOSER_ROLE",
		},
		"made PROPOSER_ROLE the admin of PROPOSER_ROLE on the timelock",
	],
	[
		"entrypoint",
		"StakeLocked",
		{ account: KEY, totalStaked: 100n, unstakeDelaySec: 86_400n },
		"locked 100 wei of stake, 1d to unlock",
	],
	[
		"entrypoint",
		"StakeUnlocked",
		{ account: KEY, withdrawTime: 1_800_086_400n },
		"unlocked the stake, withdrawable from t1800086400",
	],
	[
		"entrypoint",
		"StakeWithdrawn",
		{ account: KEY, withdrawAddress: OTHER, amount: 100n },
		"withdrew 100 wei of stake to 0x7099…79C8",
	],
];

describe("describeAdminEvent, kind by kind", () => {
	it.each(SENTENCES)("%s %s", (source, kind, args, sentence) => {
		const extra: Partial<AdminEvent> = {
			source,
			...(args.slug ||
			"hasOverride" in args ||
			"enabled" in args ||
			"amount" in args ||
			"oldAddress" in args
				? tenant
				: {}),
			...(kind === "CallScheduled" || kind === "CallExecuted"
				? { call: { target: OTHER, value: 0n, data: "0x" as const } }
				: {}),
		};
		expect(describeAdminEvent(event(kind, args, extra), namer)).toBe(sentence);
	});

	it("has a sentence for every kind each source emits", () => {
		const covered = new Set(
			SENTENCES.map(([source, kind]) => `${source}:${kind}`),
		);
		const kinds = [
			...PAYMASTER_ADMIN_EVENTS.map((kind) => `paymaster:${kind}`),
			...TIMELOCK_ADMIN_EVENTS.map((kind) => `timelock:${kind}`),
			...ENTRYPOINT_ADMIN_EVENTS.map((kind) => `entrypoint:${kind}`),
		];
		expect(kinds.filter((kind) => !covered.has(kind))).toEqual([]);
	});
});

describe("eventGroup", () => {
	it("files each kind where an operator looks for it", () => {
		expect(eventGroup(event("RoleGranted", {}))).toBe("roles");
		expect(eventGroup(event("TenantFeeChanged", {}))).toBe("fees");
		expect(eventGroup(event("Upgraded", {}))).toBe("state");
		expect(eventGroup(event("TenantFunded", {}))).toBe("funds");
		expect(eventGroup(event("TenantRegistered", {}))).toBe("tenants");
		expect(eventGroup(event("RoleGranted", {}, { source: "timelock" }))).toBe(
			"timelock",
		);
	});
});
