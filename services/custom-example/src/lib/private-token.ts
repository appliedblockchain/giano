/**
 * The private token section's reading of what an outsider gets back (demo-dapp spec, "The section
 * shows what an outsider sees"). Kept apart from the component so the rules are tested.
 */

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

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
	/** Shown as returned. A bundle sends no value, so 0 is both the real value and the placeholder. */
	value?: string | null;
};

/** Whether an unsigned read of a bundle transaction got the RPC's placeholders instead of the real values. */
export function redactionOf(tx: TransactionView | null | undefined): Redaction {
	const calldataHidden = !tx?.input || tx.input === "0x";
	const senderHidden = !tx?.from || tx.from.toLowerCase() === ZERO_ADDRESS;
	return {
		hidden: calldataHidden && senderHidden,
		calldataHidden,
		senderHidden,
		value: tx?.value,
	};
}

/** `UCEFUnauthorizedBalanceAccess(address,address)`: the private token's refusal of a balance read. */
export const UNAUTHORIZED_BALANCE_ACCESS = "0xdb11736b";

/**
 * One line that says why a read failed. viem puts an undecoded revert's selector on the line after
 * "reverted with the following signature:", so the first line alone does not name the error.
 */
export function refusalReason(message: string): string {
	const lines = message
		.split("\n")
		.map((line) => line.trim())
		.filter(Boolean);
	if (message.includes(UNAUTHORIZED_BALANCE_ACCESS))
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
