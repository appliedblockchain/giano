import { pino } from "pino";
import type { PublicClient } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { createMetrics } from "../src/metrics.js";
import {
	createSubmitter,
	laneAcrossRead,
	laneStuckAfterMs,
} from "../src/submitter.js";

/**
 * giano_executors' source: the real executorStatus over a faked node, so the lanes, the timing of
 * the reads and the absence of keys are those the bundler actually reports.
 */

const keys = [generatePrivateKey(), generatePrivateKey()];
const executors = keys.map((key) => privateKeyToAccount(key));

function submitter(client: Partial<PublicClient>) {
	return createSubmitter({
		client: client as PublicClient,
		chainId: 84532,
		entryPoint: "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
		executors,
		resubmitTimeoutMs: 30_000,
		maxReplacements: 3,
		pollIntervalMs: 1_000,
		log: pino({ level: "silent" }),
		metrics: createMetrics(),
	});
}

const node = (reads: { count: number }) => ({
	getGasPrice: async () => 1_000_000_000n,
	getBalance: async () => {
		reads.count++;
		return 10n ** 18n;
	},
	getTransactionCount: async ({ blockTag }: { blockTag?: string }) =>
		blockTag === "pending" ? 6 : 5,
});

describe("executorStatus", () => {
	it("reports idle lanes by address, never a key, and shares one read for a few seconds", async () => {
		const reads = { count: 0 };
		const subject = submitter(node(reads));
		const first = await subject.executorStatus();
		expect(
			first.executors.map((lane) => [lane.address, lane.busy, lane.busySince]),
		).toEqual(
			executors.map((executor) => [executor.address, false, undefined]),
		);
		const text = JSON.stringify(first, (_, value) =>
			typeof value === "bigint" ? value.toString() : value,
		);
		for (const key of keys) expect(text).not.toContain(key.slice(2));
		await subject.executorStatus();
		expect(reads.count).toBe(executors.length);
		subject.stop();
	});

	it("reads a lane as busy when it was busy before or after the nonces, so a transaction mined mid-read is not a false stuck lane", () => {
		// mined during the read: busy before, idle after
		expect(
			laneAcrossRead(
				{ busy: true, since: 1_000 },
				{ busy: false, since: undefined },
			),
		).toEqual({ busy: true, busySince: 1_000 });
		// took new work during the read: the newer transaction's time
		expect(
			laneAcrossRead(
				{ busy: false, since: undefined },
				{ busy: true, since: 2_000 },
			),
		).toEqual({ busy: true, busySince: 2_000 });
		expect(
			laneAcrossRead(
				{ busy: false, since: undefined },
				{ busy: false, since: undefined },
			),
		).toEqual({ busy: false, busySince: undefined });
	});

	it("gives up on a lane after every replacement and cancel bump has had its time", () => {
		expect(
			laneStuckAfterMs({ resubmitTimeoutMs: 30_000, maxReplacements: 3 }),
		).toBe(9 * 30_000);
	});
});
