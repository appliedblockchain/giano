import {
	type Address,
	getAddress,
	type Hex,
	isAddress,
	parseUnits,
} from "viem";
import type { NativeCurrency } from "../config";
import { exactAmount } from "./format";

/**
 * What an input field makes of its text (openspec D7).
 *
 * Three outcomes, not two: an empty field is neither valid nor wrong — it says nothing until the
 * operator has typed — so it has no `error` and no `value`. A form submits only with a `value`.
 */
export type Parsed<T> =
	| { value: T; error?: never }
	| { value?: never; error?: string };

const EMPTY = {} as const;

/**
 * `0x` and 40 hex characters. Mixed case is a checksum and must match: a mistyped character in a
 * checksummed address is exactly what the checksum exists to catch. All lowercase or all uppercase
 * is accepted because it carries none (EIP-55).
 */
export function parseAddress(text: string): Parsed<Address> {
	const trimmed = text.trim();
	if (!trimmed) return EMPTY;
	if (trimmed.startsWith("0X"))
		return { error: "An address starts with 0x, with a lowercase x." };
	if (!trimmed.startsWith("0x")) return { error: "An address starts with 0x." };
	const hex = trimmed.slice(2);
	if (/[^0-9a-fA-F]/.test(hex))
		return { error: "An address has only hex characters (0–9, a–f) after 0x." };
	if (hex.length !== 40)
		return {
			error: `This address has ${hex.length} hex character${hex.length === 1 ? "" : "s"} instead of 40.`,
		};
	const uncased = hex === hex.toLowerCase() || hex === hex.toUpperCase();
	if (!uncased && !isAddress(trimmed, { strict: true }))
		return {
			error: "The checksum does not match: one character is probably mistyped.",
		};
	return { value: getAddress(trimmed) };
}

export type AmountLimits = {
	currency: NativeCurrency;
	/** The most this amount may be, in the smallest unit; e.g. the treasury when withdrawing it. */
	max?: bigint;
	/** Says what `max` is, e.g. "the treasury". */
	maxLabel?: string;
	/**
	 * Whether 0 is a value rather than a mistake. A fee of 0 is free sponsorship and legitimate;
	 * funding, withdrawing or staking 0 does nothing and is refused.
	 */
	allowZero?: boolean;
};

/** A decimal in the chain's native currency, above 0 unless allowed, returned in its smallest unit (wei). */
export function parseAmount(
	text: string,
	limits: AmountLimits,
): Parsed<bigint> {
	const { currency, max, maxLabel } = limits;
	const trimmed = text.trim();
	if (!trimmed) return EMPTY;
	if (!/^(\d+\.?\d*|\.\d+)$/.test(trimmed))
		return { error: `Type an amount in ${currency.symbol}, e.g. 0.5.` };
	const decimals = trimmed.split(".")[1]?.length ?? 0;
	if (decimals > currency.decimals)
		return {
			error: `${currency.symbol} has ${currency.decimals} decimal places; this has ${decimals}.`,
		};
	const value = parseUnits(trimmed, currency.decimals);
	if (value === 0n && !limits.allowZero)
		return { error: "The amount must be more than 0." };
	if (max !== undefined && value > max)
		return {
			error: `That is more than ${maxLabel ?? "the maximum"} (${exactAmount(max, currency)}).`,
		};
	return { value };
}

/** A non-negative whole number: gas, seconds, basis points. */
export function parseWholeNumber(
	text: string,
	limits: { max?: bigint; unit?: string } = {},
): Parsed<bigint> {
	const trimmed = text.trim();
	if (!trimmed) return EMPTY;
	if (!/^\d+$/.test(trimmed))
		return {
			error: `Type a whole number${limits.unit ? ` of ${limits.unit}` : ""}, with no sign, decimals or units.`,
		};
	const value = BigInt(trimmed);
	if (limits.max !== undefined && value > limits.max)
		return {
			error: `The most this can be is ${limits.max}${limits.unit ? ` ${limits.unit}` : ""}.`,
		};
	return { value };
}

/** The paymaster refuses a penalty above 50% (`MAX_PENALTY_BPS`). */
export const MAX_PENALTY_BPS = 5000n;

export const parsePenaltyBps = (text: string): Parsed<bigint> =>
	parseWholeNumber(text, { max: MAX_PENALTY_BPS, unit: "basis points" });

/** Calldata: `0x` and whole bytes of hex. Empty is no call. */
export function parseCalldata(text: string): Parsed<Hex> {
	const trimmed = text.trim();
	if (!trimmed) return EMPTY;
	if (!/^0x[0-9a-fA-F]*$/.test(trimmed))
		return { error: "Calldata is 0x followed by hex characters." };
	if (trimmed.length % 2 !== 0)
		return {
			error: "Calldata is whole bytes: an even number of hex characters.",
		};
	return { value: trimmed.toLowerCase() as Hex };
}

/** The largest value a `uint32` parameter takes: the post-op gas allowance, the unstake delay. */
export const MAX_UINT32 = 4_294_967_295n;
