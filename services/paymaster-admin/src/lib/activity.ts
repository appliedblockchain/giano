import type { SponsorshipRecord } from "@appliedblockchain/giano-paymaster-sdk";
import { formatUnits } from "viem";

export type Outcome = "all" | "succeeded" | "reverted";

export type SettlementFilter = {
	/** A tenant's lowercase UUID, or "" for every tenant. */
	tenant: string;
	outcome: Outcome;
	/** Part of the account (sender) address, any case. */
	account: string;
};

export function filterSettlements(
	records: readonly SponsorshipRecord[],
	{ tenant, outcome, account }: SettlementFilter,
): SponsorshipRecord[] {
	const needle = account.trim().toLowerCase();
	return records.filter(
		(record) =>
			(!tenant || record.uuid.toLowerCase() === tenant) &&
			(outcome === "all" || record.success === (outcome === "succeeded")) &&
			(!needle || record.sender.toLowerCase().includes(needle)),
	);
}

export type SettlementTotals = {
	count: number;
	reverted: number;
	gasWei: bigint;
	feeWei: bigint;
	overheadWei: bigint;
};

export function settlementTotals(
	records: readonly SponsorshipRecord[],
): SettlementTotals {
	const totals: SettlementTotals = {
		count: 0,
		reverted: 0,
		gasWei: 0n,
		feeWei: 0n,
		overheadWei: 0n,
	};
	for (const record of records) {
		totals.count += 1;
		if (!record.success) totals.reverted += 1;
		totals.gasWei += record.gasCostWei;
		totals.feeWei += record.feeWei;
		totals.overheadWei += record.overheadWei;
	}
	return totals;
}

/** A CSV field: quoted when it holds a comma, a quote or a line break. */
const field = (value: string) =>
	/[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;

/**
 * The rows as loaded, one settlement a line, amounts in the chain's currency to full precision so a
 * spreadsheet sums them exactly.
 */
export function settlementsCsv(
	records: readonly SponsorshipRecord[],
	{
		tenantName,
		blockTime,
		decimals,
	}: {
		tenantName: (uuid: string) => string;
		blockTime: (block: bigint) => number | undefined;
		decimals: number;
	},
): string {
	const header = [
		"time",
		"block",
		"tenant",
		"tenant_id",
		"account",
		"outcome",
		"gas",
		"fee",
		"overhead",
		"balance_after",
		"user_op_hash",
		"transaction",
	];
	const amount = (wei: bigint) => formatUnits(wei, decimals);
	const lines = records.map((record) => {
		const time = blockTime(record.blockNumber);
		return [
			time === undefined ? "" : new Date(time * 1000).toISOString(),
			record.blockNumber.toString(),
			tenantName(record.uuid),
			record.uuid,
			record.sender,
			record.success ? "succeeded" : "reverted",
			amount(record.gasCostWei),
			amount(record.feeWei),
			amount(record.overheadWei),
			amount(record.newBalanceWei),
			record.userOpHash,
			record.transactionHash,
		]
			.map(field)
			.join(",");
	});
	return `${[header.join(","), ...lines].join("\n")}\n`;
}
