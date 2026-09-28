import { formatEther, formatUnits } from 'viem';

export type Address = `0x${string}`;
export type Hex = `0x${string}`;

/** 0x1234…abcd */
export function shortHex(value?: string | null, head = 6, tail = 4): string {
  if (!value) return '';
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function formatEth(wei: bigint | undefined | null, digits = 4): string {
  if (wei === undefined || wei === null) return '—';
  const [whole, fraction = ''] = formatEther(wei).split('.');
  return `${whole}.${fraction.padEnd(digits, '0').slice(0, digits)} ETH`;
}

export function formatToken(amount: bigint | undefined | null, decimals: number, symbol: string): string {
  if (amount === undefined || amount === null) return '—';
  return `${formatUnits(amount, decimals)} ${symbol}`;
}

export function formatDuration(ms: number | undefined): string {
  if (ms === undefined) return '';
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export function formatTime(iso: string): string {
  const date = new Date(iso);
  return date.toLocaleTimeString(undefined, { hour12: false });
}

/** JSON.stringify that survives bigint and undefined, for the ledger and the code blocks. */
export function toJson(value: unknown, space = 2): string {
  return JSON.stringify(
    value,
    (_key, v) => {
      if (typeof v === 'bigint') return `${v.toString()}n`;
      if (v === undefined) return null;
      return v;
    },
    space,
  );
}

export function hexToBigInt(value: unknown): bigint | undefined {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(value);
  if (typeof value === 'string' && /^0x[0-9a-fA-F]+$/.test(value)) return BigInt(value);
  if (typeof value === 'string' && /^\d+$/.test(value)) return BigInt(value);
  return undefined;
}

export const ZERO_ADDRESS: Address = '0x0000000000000000000000000000000000000000';
