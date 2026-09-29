import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

export const SELECTOR_RE = /^0x[0-9a-fA-F]{8}$/;
export const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
export const HEX_RE = /^0x([0-9a-fA-F]{2})*$/;

export function isSelector(value: string): boolean {
  return SELECTOR_RE.test(value);
}

export function isAddress(value: unknown): value is string {
  return typeof value === 'string' && ADDRESS_RE.test(value);
}

export function keccakHex(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? utf8ToBytes(input) : input;
  return `0x${bytesToHex(keccak_256(bytes))}`;
}

/**
 * Strips parameter names from a human-readable signature so it can be hashed:
 * `transfer(address to, uint256 value)` → `transfer(address,uint256)`. Handles tuples and
 * arrays: `swap((address a, uint256 b)[] items, bytes data)` → `swap((address,uint256)[],bytes)`.
 * Throws on anything that is not `name(...)`.
 */
export function canonicalSignature(signature: string): string {
  const trimmed = signature.trim().replace(/^function\s+/, '');
  const open = trimmed.indexOf('(');
  if (open <= 0 || !trimmed.endsWith(')')) throw new Error(`not a function signature: ${signature}`);
  const name = trimmed.slice(0, open).trim();
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) throw new Error(`not a function signature: ${signature}`);
  const params = trimmed.slice(open + 1, -1);
  return `${name}(${canonicalParams(params)})`;
}

function canonicalParams(params: string): string {
  const parts = splitTopLevel(params);
  return parts.map(canonicalParam).join(',');
}

function canonicalParam(param: string): string {
  const p = param.trim();
  if (p === '') throw new Error('empty parameter');
  if (p.startsWith('(')) {
    // tuple, possibly with array suffix and a name: "(address a, uint256 b)[] items"
    const close = matchingParen(p, 0);
    const inner = p.slice(1, close);
    const rest = p.slice(close + 1).trim();
    const suffix = rest.match(/^((?:\[\d*\])*)/)?.[1] ?? '';
    return `(${canonicalParams(inner)})${suffix}`;
  }
  // "uint256 indexed value", "address to", "uint256" — the type is the first token
  const tokens = p.split(/\s+/);
  const type = tokens[0]!;
  if (!/^[a-z][a-z0-9]*(\[\d*\])*$/.test(type)) throw new Error(`not a solidity type: ${type}`);
  return type === 'uint' ? 'uint256' : type === 'int' ? 'int256' : type;
}

function splitTopLevel(input: string): string[] {
  if (input.trim() === '') return [];
  const out: string[] = [];
  let depth = 0;
  let current = '';
  for (const ch of input) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === ',' && depth === 0) {
      out.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out;
}

function matchingParen(input: string, openIndex: number): number {
  let depth = 0;
  for (let i = openIndex; i < input.length; i++) {
    if (input[i] === '(') depth++;
    if (input[i] === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  throw new Error(`unbalanced parentheses in ${input}`);
}

/**
 * Normalises a format key — a raw selector or a human-readable signature — to a lowercase
 * 4-byte selector. Throws when it is neither.
 */
export function functionSelector(signatureOrSelector: string): string {
  if (isSelector(signatureOrSelector)) return signatureOrSelector.toLowerCase();
  return keccakHex(canonicalSignature(signatureOrSelector)).slice(0, 10);
}

/** EIP-55 checksum. Accepts any 20-byte hex address; throws otherwise. */
export function checksumAddress(address: string): string {
  if (!isAddress(address)) throw new Error(`not an address: ${address}`);
  const lower = address.slice(2).toLowerCase();
  const hash = bytesToHex(keccak_256(utf8ToBytes(lower)));
  let out = '0x';
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(hash[i]!, 16) >= 8 ? lower[i]!.toUpperCase() : lower[i]!;
  }
  return out;
}

/** `0x1234…abcd` — the first six and last four characters of a checksummed address. */
export function shortAddress(address: string): string {
  const full = checksumAddress(address);
  return `${full.slice(0, 6)}…${full.slice(-4)}`;
}

/** Scales an integer amount by `decimals`, trimming trailing zeros: 10500000 / 6 → "10.5". */
export function formatUnits(amount: bigint, decimals: number): string {
  const negative = amount < 0n;
  const abs = negative ? -amount : amount;
  const s = abs.toString().padStart(decimals + 1, '0');
  const whole = s.slice(0, s.length - decimals) || '0';
  const fraction = decimals === 0 ? '' : s.slice(s.length - decimals).replace(/0+$/, '');
  return `${negative ? '-' : ''}${whole}${fraction ? `.${fraction}` : ''}`;
}

/** Parses a bigint-ish value: bigint, number, decimal string or 0x-hex string. Throws otherwise. */
export function toBigInt(value: unknown): bigint {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) throw new Error(`not an integer amount: ${value}`);
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const v = value.trim();
    if (/^0x[0-9a-fA-F]*$/.test(v)) return v.length === 2 ? 0n : BigInt(v);
    if (/^[0-9]+$/.test(v)) return BigInt(v);
  }
  throw new Error(`not an amount: ${String(value)}`);
}
