import { formatEther } from 'viem';

/**
 * Money is shown to a fixed number of decimals with the exact value in the title attribute.
 *
 * Balances here are wei-precise and routinely have eighteen significant digits — a column of them
 * unrounded is unreadable, and an operator comparing two tenants ends up counting characters. The
 * rounded figure is for reading; the exact one is one hover away and is what the chain holds.
 */
export function eth(wei: bigint, decimals = 4): string {
  const exact = formatEther(wei);
  const value = Number(exact);
  if (value === 0) return '0';
  // Anything that would round to zero is shown as a bound instead, so "0.0000" never stands in
  // for a real, non-zero balance.
  if (Math.abs(value) < 10 ** -decimals) return `<${10 ** -decimals}`;
  return value.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: decimals });
}

/** The exact wei-precision figure, for tooltips and copy buttons. */
export const exactEth = (wei: bigint): string => `${formatEther(wei)} ETH`;

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
  if (typeof error === 'string') return error;
  if (error instanceof Error && error.message) return error.message;

  if (error && typeof error === 'object') {
    const { message, data } = error as { message?: unknown; data?: unknown };
    if (typeof message === 'string' && message) return message;

    if (data && typeof data === 'object') {
      const nested = (data as { message?: unknown; originalError?: { message?: unknown } }).message ?? (data as { originalError?: { message?: unknown } }).originalError?.message;
      if (typeof nested === 'string' && nested) return nested;
    }
  }

  return 'Unknown error';
}
