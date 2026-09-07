import { describe, expect, it } from 'vitest';
import { PaymasterSdkError } from '../src/errors';
import { isTenantIdHex, isTenantUuid, toTenantId, toTenantUuid } from '../src/tenant-id';

const UUID = '3f2504e0-4f89-11d3-9a0c-0305e82c3301';
const HEX = '0x3f2504e04f8911d39a0c0305e82c3301';

describe('toTenantId', () => {
  it('converts a canonical UUID', () => {
    expect(toTenantId(UUID)).toBe(HEX);
  });

  it('accepts an undashed UUID', () => {
    expect(toTenantId(UUID.replace(/-/g, ''))).toBe(HEX);
  });

  it('accepts an already-normalised id unchanged', () => {
    expect(toTenantId(HEX)).toBe(HEX);
  });

  it('normalises case and surrounding whitespace', () => {
    expect(toTenantId(`  ${UUID.toUpperCase()}  `)).toBe(HEX);
    expect(toTenantId(HEX.toUpperCase().replace('0X', '0x'))).toBe(HEX);
  });

  // A mistyped id that parsed would address a different tenant, and the contract would report
  // that only as `UnknownTenant` — so every near-miss has to fail here instead.
  it.each([
    ['too short', '0x3f2504e04f8911d39a0c0305e82c33'],
    ['too long', '0x3f2504e04f8911d39a0c0305e82c3301ff'],
    ['non-hex characters', '0x3f2504e04f8911d39a0c0305e82c33zz'],
    ['an address rather than a tenant id', '0x0000000071727De22E5E9d8BAf0edAc6f37da032'],
    ['empty', ''],
    ['a slug', 'tenant-a'],
  ])('rejects %s', (_label, value) => {
    expect(() => toTenantId(value)).toThrow(PaymasterSdkError);
  });
});

describe('toTenantUuid', () => {
  it('renders the UUID spelling', () => {
    expect(toTenantUuid(HEX)).toBe(UUID);
  });

  it('round-trips', () => {
    expect(toTenantId(toTenantUuid(HEX))).toBe(HEX);
    expect(toTenantUuid(toTenantId(UUID))).toBe(UUID);
  });

  it('refuses a value that is not 16 bytes', () => {
    expect(() => toTenantUuid('0xdead')).toThrow(PaymasterSdkError);
  });
});

describe('predicates', () => {
  it('recognises each spelling', () => {
    expect(isTenantUuid(UUID)).toBe(true);
    expect(isTenantUuid(HEX)).toBe(false);
    expect(isTenantIdHex(HEX)).toBe(true);
    expect(isTenantIdHex(UUID)).toBe(false);
  });
});
