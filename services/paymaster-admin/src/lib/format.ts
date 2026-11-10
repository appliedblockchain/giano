import { formatUnits } from "viem";
import type { NativeCurrency } from "../config";

const ETH: NativeCurrency = { symbol: "ETH", decimals: 18 };

/**
 * Money is shown to a fixed number of decimals with the exact value in the title attribute.
 *
 * Balances here are wei-precise and routinely have eighteen significant digits — a column of them
 * unrounded is unreadable, and an operator comparing two tenants ends up counting characters. The
 * rounded figure is for reading; the exact one is one hover away and is what the chain holds.
 */
export function eth(wei: bigint, decimals = 4): string {
	return amount(wei, ETH, decimals);
}

/** {@link eth} in the chain's own currency, without the symbol. */
export function amount(
	wei: bigint,
	currency: NativeCurrency,
	decimals = 4,
): string {
	const exact = formatUnits(wei, currency.decimals);
	const value = Number(exact);
	if (value === 0) return "0";
	// Anything that would round to zero is shown as a bound instead, so "0.0000" never stands in
	// for a real, non-zero balance.
	if (Math.abs(value) < 10 ** -decimals) return `<${10 ** -decimals}`;
	return value.toLocaleString(undefined, {
		minimumFractionDigits: 2,
		maximumFractionDigits: decimals,
	});
}

/** The exact wei-precision figure, for tooltips and copy buttons. */
export const exactEth = (wei: bigint): string => exactAmount(wei, ETH);

/** The exact figure with the chain's currency symbol, e.g. `0.000123456789 POL`. */
export const exactAmount = (wei: bigint, currency: NativeCurrency): string =>
	`${formatUnits(wei, currency.decimals)} ${currency.symbol}`;

/*
 * There is deliberately no address- or hash-shortening helper here.
 *
 * Operators compare on-chain identifiers whole — is this role holder the timelock, does this
 * tenant withdraw where we think it does — and `0x1234…5678` hides exactly the middle that
 * separates two addresses from the same deployer. Render them with `Copyable`, which shows the
 * full value and copies it on click.
 */

/**
 * Turns any thrown value into something worth showing a person.
 *
 * Wallets are why this is more than `error.message`. What a browser wallet rejects with has
 * crossed a process boundary and arrives as a serialised JSON-RPC error — `{ code, message, data }`,
 * a plain object and not an `Error` — so an `instanceof` test alone prints `[object Object]` over
 * the one sentence the operator needed. Some wallets, and some nodes behind them, put the useful
 * half another level down under `data`.
 */
export function describeError(error: unknown): string {
	if (typeof error === "string") return error;
	// viem's message runs to the request body, the arguments and a docs link; its short message and
	// the node's own words are what an operator reads, and fit a phone.
	const { shortMessage, details } = (error ?? {}) as {
		shortMessage?: unknown;
		details?: unknown;
	};
	if (typeof shortMessage === "string" && shortMessage) {
		// A contract's own error is what the operator needs: viem keeps the decoded name only on the
		// ContractFunctionRevertedError in the cause chain, not in the short message.
		const reverted = revertReason(error);
		const why =
			reverted ??
			(typeof details === "string" && details && !shortMessage.includes(details)
				? details
				: undefined);
		return why ? `${shortMessage.replace(/\.$/, "")}: ${why}` : shortMessage;
	}
	if (error instanceof Error && error.message) return error.message;

	if (error && typeof error === "object") {
		const { message, data } = error as { message?: unknown; data?: unknown };
		if (typeof message === "string" && message) return message;

		if (data && typeof data === "object") {
			const nested =
				(data as { message?: unknown; originalError?: { message?: unknown } })
					.message ??
				(data as { originalError?: { message?: unknown } }).originalError
					?.message;
			if (typeof nested === "string" && nested) return nested;
		}
	}

	return "Unknown error";
}

/** The longest decoded revert arguments shown; past it, only the error's name. */
const MAX_REVERT_ARGS = 200;

/**
 * The decoded revert of the first ContractFunctionRevertedError in `error`'s cause chain: the
 * custom error's name and its arguments when short (`AccessControlUnauthorizedAccount(0x…, 0x…)`),
 * or the revert string. Undefined when the chain holds none.
 */
function revertReason(error: unknown): string | undefined {
	let current: unknown = error;
	for (
		let depth = 0;
		current && typeof current === "object" && depth < 8;
		depth++
	) {
		const { name, data, reason, cause } = current as {
			name?: unknown;
			data?: { errorName?: unknown; args?: readonly unknown[] };
			reason?: unknown;
			cause?: unknown;
		};
		if (name === "ContractFunctionRevertedError") {
			if (typeof data?.errorName === "string") {
				const args = (data.args ?? []).map((arg) =>
					typeof arg === "bigint" ? arg.toString() : String(arg),
				);
				const shown = `${data.errorName}(${args.join(", ")})`;
				return shown.length <= MAX_REVERT_ARGS ? shown : data.errorName;
			}
			if (typeof reason === "string" && reason) return reason;
			return undefined;
		}
		current = cause;
	}
	return undefined;
}
