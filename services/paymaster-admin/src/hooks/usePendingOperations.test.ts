import type { TimelockOperation } from "@appliedblockchain/giano-paymaster-sdk";
import { describe, expect, it } from "vitest";
import { merge } from "./usePendingOperations";

const operation = (
	id: string,
	overrides: Partial<TimelockOperation> = {},
): TimelockOperation => ({
	id: `0x${id.padStart(64, "0")}`,
	calls: [{ target: `0x${"11".repeat(20)}`, value: 0n, data: "0x1234" }],
	predecessor: `0x${"00".repeat(32)}`,
	salt: `0x${"5a".repeat(32)}`,
	delay: 60n,
	state: "waiting",
	readyAt: 1_800_000_000,
	scheduledBlock: 10n,
	scheduledTransaction: `0x${"aa".repeat(32)}`,
	complete: true,
	...overrides,
});

describe("merge", () => {
	it("keeps what an operation was scheduled with, and takes its new state from the newer read", () => {
		const scheduled = operation("1");
		// what an execution log alone reconstructs: no scheduling, so incomplete
		const executed = operation("1", {
			state: "done",
			readyAt: undefined,
			complete: false,
			salt: `0x${"00".repeat(32)}`,
			scheduledBlock: undefined,
			scheduledTransaction: undefined,
			executedBlock: 20n,
			executedTransaction: `0x${"bb".repeat(32)}`,
		});
		const [merged] = merge([scheduled], [executed]);
		expect(merged).toMatchObject({
			state: "done",
			complete: true,
			salt: scheduled.salt,
			scheduledTransaction: scheduled.scheduledTransaction,
			executedTransaction: executed.executedTransaction,
			readyAt: scheduled.readyAt,
		});
	});

	it("adds operations the newer read found, and keeps those it did not mention", () => {
		const merged = merge(
			[operation("1")],
			[operation("2", { scheduledBlock: 30n })],
		);
		expect(merged.map((entry) => entry.id.slice(-1))).toEqual(["1", "2"]);
	});

	it("lets a complete newer read fill in an operation first seen incomplete", () => {
		const partial = operation("3", {
			complete: false,
			salt: `0x${"00".repeat(32)}`,
		});
		const [merged] = merge([partial], [operation("3")]);
		expect(merged.complete).toBe(true);
		expect(merged.salt).toBe(`0x${"5a".repeat(32)}`);
	});
});
