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

/** Turns any thrown value into something worth showing a person. */
export function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  return 'Unknown error';
}
