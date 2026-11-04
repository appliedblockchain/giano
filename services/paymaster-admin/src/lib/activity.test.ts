import type { SponsorshipRecord } from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import {
	filterSettlements,
	settlementsCsv,
	settlementTotals,
} from "./activity";

const STOCK = "11111111-1111-4111-8111-111111111111";
const BYO = "22222222-2222-4222-8222-222222222222";

const record = (overrides: Partial<SponsorshipRecord>): SponsorshipRecord =>
	({
		tenantId: "0x11",
		uuid: STOCK,
		sender: "0xAbC0000000000000000000000000000000000001",
		userOpHash: `0x${"aa".repeat(32)}`,
		gasCostWei: 300n,
		feeWei: 100n,
		overheadWei: 10n,
		newBalanceWei: 1_000_000_000_000_000_000n,
		success: true,
		blockNumber: 5n,
		transactionHash: `0x${"bb".repeat(32)}`,
		...overrides,
	}) as SponsorshipRecord;

const records = [
	record({}),
	record({
		uuid: BYO,
		success: false,
		sender: "0xDEF0000000000000000000000000000000000002",
	}),
	record({ uuid: BYO, gasCostWei: 700n }),
];

describe("filterSettlements", () => {
	it("narrows by tenant, outcome and part of the account, in any case", () => {
		expect(
			filterSettlements(records, { tenant: BYO, outcome: "all", account: "" }),
		).toHaveLength(2);
		expect(
			filterSettlements(records, {
				tenant: "",
				outcome: "reverted",
				account: "",
			}),
		).toHaveLength(1);
		expect(
			filterSettlements(records, {
				tenant: "",
				outcome: "all",
				account: "def0",
			}),
		).toEqual([records[1]]);
	});
});

describe("settlementTotals", () => {
	it("totals what is shown", () => {
		expect(
			settlementTotals(
				filterSettlements(records, {
					tenant: BYO,
					outcome: "all",
					account: "",
				}),
			),
		).toEqual({
			count: 2,
			reverted: 1,
			gasWei: 1000n,
			feeWei: 200n,
			overheadWei: 20n,
		});
	});
});

describe("settlementsCsv", () => {
	it("writes a header and one line per settlement, at full precision", () => {
		const csv = settlementsCsv([records[0]], {
			tenantName: (uuid) => (uuid === STOCK ? "stock, the demo" : uuid),
			blockTime: () => 1_800_000_000,
			decimals: 18,
		});
		const [header, line] = csv.trim().split("\n");
		expect(header.split(",")).toHaveLength(12);
		expect(line).toBe(
			[
				"2027-01-15T08:00:00.000Z",
				"5",
				'"stock, the demo"',
				STOCK,
				records[0].sender,
				"succeeded",
				"0.0000000000000003",
				"0.0000000000000001",
				"0.00000000000000001",
				"1",
				records[0].userOpHash,
				records[0].transactionHash,
			].join(","),
		);
	});
});
