import type { AdminEvent } from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import { tenantCancellations } from "./admin-events";

const event = (
	kind: AdminEvent["kind"],
	id: string,
	withCall: boolean,
	block: bigint,
): AdminEvent => ({
	source: "timelock",
	kind,
	args: { id },
	...(withCall
		? { call: { target: `0x${"11".repeat(20)}`, value: 0n, data: "0x" } }
		: {}),
	blockNumber: block,
	logIndex: 0,
	transactionHash: `0x${"ab".repeat(32)}`,
	blockTime: undefined,
	from: undefined,
	actor: undefined,
});

describe("tenantCancellations", () => {
	it("keeps a cancellation whose schedule is loaded in another window, in either order, and no other", () => {
		const scheduled = event("CallScheduled", "0x01", true, 100n);
		const cancelled = event("Cancelled", "0x01", false, 9_500n);
		const otherTenants = event("Cancelled", "0x02", false, 9_600n);
		// newest window first: the cancellation, then the schedule a window back
		expect(
			tenantCancellations([otherTenants, cancelled, scheduled]).map(
				(entry) => entry.args.id,
			),
		).toEqual(["0x01", "0x01"]);
		// before the schedule's window is loaded, the cancellation waits
		expect(tenantCancellations([cancelled])).toEqual([]);
	});
});
