import type {
	AdminEvent,
	AdminEventKind,
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

const namer: Namer = {
	address: (address) => shortAddress(address, address === KEY ? ["you"] : []),
	tenant: (uuid) => (uuid === UUID ? "acme" : uuid),
	money: (wei) => `${wei} wei`,
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
