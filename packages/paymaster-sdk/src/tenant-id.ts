import type { Hex } from 'viem';
import { PaymasterSdkError } from './errors';

/**
 * Tenant identifiers.
 *
 * The contract keys tenants by a raw 16-byte value; Giano's `tenants.id` is a UUID, which is
 * already immutable, already unique and never reused, so it is used directly rather than
 * introducing a second identifier that would then have to be kept in step. Every caller therefore
 * has to move between the two spellings of the same number, and doing that by hand is exactly the
 * kind of thing that silently funds the wrong tenant — so it lives here, once.
 *
 * `0x` + 32 hex characters is the on-chain spelling; `8-4-4-4-12` is the human one.
 */

/** A tenant id in the contract's spelling: `0x` followed by exactly 32 hex characters. */
export type TenantIdHex = Hex;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const BYTES16_PATTERN = /^0x[0-9a-f]{32}$/;

/**
 * Normalises any accepted spelling of a tenant id to `bytes16`.
 *
 * Accepts a UUID (with or without dashes) or an already-normalised `0x…` 16-byte string, in any
 * case. Rejects everything else loudly: a mistyped id that happened to parse would address a
 * different tenant, and the contract would report it only as `UnknownTenant`.
 */
export function toTenantId(id: string): TenantIdHex {
  const trimmed = id.trim().toLowerCase();

  if (BYTES16_PATTERN.test(trimmed)) return trimmed as TenantIdHex;

  const undashed = trimmed.replace(/-/g, '');
  if (/^[0-9a-f]{32}$/.test(undashed)) return `0x${undashed}`;

  throw new PaymasterSdkError(`"${id}" is not a tenant id: expected a UUID or a 16-byte hex string (0x + 32 hex characters)`);
}

/**
 * Renders a `bytes16` tenant id as a UUID, which is how it appears everywhere outside the chain —
 * the backend's tenant table, dashboards, support tickets.
 */
export function toTenantUuid(id: TenantIdHex): string {
  const hex = id.trim().toLowerCase();
  if (!BYTES16_PATTERN.test(hex)) {
    throw new PaymasterSdkError(`"${id}" is not a 16-byte hex string, so it cannot be rendered as a UUID`);
  }
  const body = hex.slice(2);
  return `${body.slice(0, 8)}-${body.slice(8, 12)}-${body.slice(12, 16)}-${body.slice(16, 20)}-${body.slice(20)}`;
}

/** True when `value` is a UUID in the canonical dashed form. */
export function isTenantUuid(value: string): boolean {
  return UUID_PATTERN.test(value.trim().toLowerCase());
}

/** True when `value` is already a `bytes16` tenant id. */
export function isTenantIdHex(value: string): boolean {
  return BYTES16_PATTERN.test(value.trim().toLowerCase());
}
