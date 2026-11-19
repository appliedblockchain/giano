/**
 * The private token section's reading of what an outsider gets back (demo-dapp spec, "The section
 * shows what an outsider sees"). Kept apart from the component so the rules are tested.
 */

import {
	decodeFunctionData,
	erc20Abi,
	maxUint256,
	parseUnits,
	zeroAddress,
} from "viem";
import type { Hex } from "./format";
import type { LedgerEntry } from "./ledger";

/** The fields of `eth_getTransactionByHash` the outsider view shows. */
export type TransactionView = {
	from?: string | null;
	to?: string | null;
	input?: string | null;
	value?: string | null;
};

export type Redaction = {
	/** True when every field the chain hides came back as a placeholder. */
	hidden: boolean;
	/** The RPC answered `0x`: a bundle transaction always carries `handleOps` calldata. */
	calldataHidden: boolean;
	/** The RPC answered the zero address: no real transaction is sent from it. */
	senderHidden: boolean;
};

/** Whether an unsigned read of a bundle transaction got the RPC's placeholders instead of the real values. */
export function redactionOf(tx: TransactionView | null | undefined): Redaction {
	const calldataHidden = !tx?.input || tx.input === "0x";
	const senderHidden = !tx?.from || tx.from.toLowerCase() === zeroAddress;
	return {
		hidden: calldataHidden && senderHidden,
		calldataHidden,
		senderHidden,
	};
}

/** `UCEFUnauthorizedBalanceAccess(address,address)`: the private token's refusal of a balance read. */
export const UNAUTHORIZED_BALANCE_ACCESS = "0xdb11736b";

/**
 * Whether a failed balance read is the private token's own refusal. Only this refusal shows that the
 * balance is private: an unreachable RPC, a timeout or a declined approval proves nothing.
 */
export function isBalanceRefusal(message: string): boolean {
	return message.includes(UNAUTHORIZED_BALANCE_ACCESS);
}

/**
 * One line that says why a read failed. viem puts an undecoded revert's selector on the line after
 * "reverted with the following signature:", so the first line alone does not name the error.
 */
export function refusalReason(message: string): string {
	const lines = message
		.split("\n")
		.map((line) => line.trim())
		.filter(Boolean);
	if (isBalanceRefusal(message))
		return `UCEFUnauthorizedBalanceAccess (${UNAUTHORIZED_BALANCE_ACCESS}): only the holder can read this balance`;
	const signature = lines.findIndex((line) =>
		line.endsWith("reverted with the following signature:"),
	);
	if (signature !== -1 && lines[signature + 1])
		return `${lines[signature]} ${lines[signature + 1]}`;
	return lines[0] ?? message;
}

/** The address the "another account" read targets: the latest transfer's recipient, else a fixed one. */
export const OUTSIDER_FALLBACK_ADDRESS =
	"0x000000000000000000000000000000000000dEaD" as const;

export function otherAccount(
	wallet: string,
	latestRecipient: string | undefined,
): `0x${string}` {
	return latestRecipient &&
		/^0x[0-9a-fA-F]{40}$/.test(latestRecipient) &&
		latestRecipient.toLowerCase() !== wallet.toLowerCase()
		? (latestRecipient as `0x${string}`)
		: OUTSIDER_FALLBACK_ADDRESS;
}

/** The key of the signed reader for one chain and wallet. */
export function readerKey(chainId: number, wallet: string): string {
	return `${chainId}:${wallet.toLowerCase()}`;
}

/**
 * The reader keys whose chain no longer has a session for that wallet: the session ended, or it
 * changed account. `accountOn` gives the account of a chain's current session, if any.
 */
export function staleReaderKeys(
	keys: Iterable<string>,
	accountOn: (chainId: number) => string | undefined,
): string[] {
	const stale: string[] = [];
	for (const key of keys) {
		const [chainId, wallet] = key.split(":");
		if (accountOn(Number(chainId))?.toLowerCase() !== wallet) stale.push(key);
	}
	return stale;
}

/**
 * The token amount typed in the card, in base units. An empty field is 0. Throws for a value that is
 * not a decimal number, has more decimal places than the token, is negative, or does not fit a
 * uint256. `parseUnits` alone would round extra decimal places, and send another amount.
 */
export function parseAmount(amount: string, decimals: number): bigint {
	const value = amount.trim() || "0";
	const places = (value.split(".")[1] ?? "").replace(/0+$/, "").length;
	if (places > decimals)
		throw new Error(
			`the amount ${amount} has more than ${decimals} decimal places`,
		);
	const units = parseUnits(value, decimals);
	if (units < 0n) throw new Error(`the amount ${amount} is negative`);
	if (units > maxUint256)
		throw new Error(`the amount ${amount} does not fit a uint256`);
	return units;
}

/**
 * The latest confirmed private token transfer by this wallet on this chain, from the ledger: an entry
 * whose request decodes as an ERC-20 `transfer`. The label is display text and is not read. The
 * ledger is restored from localStorage without a check of each field, so an entry whose fields have
 * the wrong type is skipped: it must not take the Tokens tab down.
 */
export function findLatestTransfer(
	entries: readonly LedgerEntry[],
	chainId: number,
	account: string | undefined,
): { txHash: Hex; recipient: string } | undefined {
	if (!account) return undefined;
	for (const entry of entries) {
		if (
			entry.section !== "private-token" ||
			entry.chainId !== chainId ||
			typeof entry.account !== "string" ||
			entry.account.toLowerCase() !== account.toLowerCase() ||
			entry.status !== "confirmed" ||
			typeof entry.txHash !== "string" ||
			!entry.txHash ||
			(entry.params != null && !Array.isArray(entry.params))
		)
			continue;
		const [request] = (entry.params ?? []) as unknown[];
		const data =
			request && typeof request === "object"
				? (request as { data?: unknown }).data
				: undefined;
		const recipient = transferRecipient(data);
		if (recipient) return { txHash: entry.txHash as Hex, recipient };
	}
	return undefined;
}

/** The recipient of an ERC-20 `transfer` call, or undefined for any other data. */
function transferRecipient(data: unknown): string | undefined {
	if (typeof data !== "string" || !data) return undefined;
	try {
		const call = decodeFunctionData({ abi: erc20Abi, data: data as Hex });
		return call.functionName === "transfer" ? call.args[0] : undefined;
	} catch {
		// not an ERC-20 call, such as the test token's mint
		return undefined;
	}
}
