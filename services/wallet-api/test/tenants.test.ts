import { describe, expect, it } from 'vitest';
import { mergePolicy, tenantsSeedSchema, validateTenantSeed } from '../src/services/tenants.js';

/**
 * The RP/origin invariant (specs/DEVELOPER-GUIDE.md §1) is enforced on the
 * tenant WRITE path — a row that violates it must be impossible to create. These are
 * pure validator tests; the seed-upsert immutability half lives in api.test.ts.
 */
describe('tenant seed validation (V11)', () => {
  const base = {
    slug: 'acme',
    walletOrigin: 'https://wallet.acme.app',
    rpName: 'Acme Wallet',
    openRegistration: true,
  };

  it('accepts a minimal tenant and derives rpId from the wallet origin host', () => {
    const tenant = validateTenantSeed(base);
    expect(tenant.rpId).toBe('wallet.acme.app');
    // walletOrigin is auto-included in expectedOrigins
    expect(tenant.expectedOrigins).toContain('https://wallet.acme.app');
  });

  it('rejects an expectedOrigins entry whose host is not at-or-under the rpId', () => {
    expect(() =>
      validateTenantSeed({ ...base, expectedOrigins: ['https://evil.example.com'] }),
    ).toThrow(/not valid for rpId/);
  });

  it('accepts subdomain expectedOrigins', () => {
    const tenant = validateTenantSeed({ ...base, expectedOrigins: ['https://pay.wallet.acme.app'] });
    expect(tenant.expectedOrigins).toEqual(expect.arrayContaining(['https://wallet.acme.app', 'https://pay.wallet.acme.app']));
  });

  it('rejects an rpId that is not the wallet origin host (D1: wallet-host rule)', () => {
    expect(() => validateTenantSeed({ ...base, rpId: 'acme.app' })).toThrow(/must equal the walletOrigin host/);
  });

  it('rejects a walletOrigin that is not a bare origin', () => {
    expect(() => validateTenantSeed({ ...base, walletOrigin: 'https://wallet.acme.app/path' })).toThrow(/bare origin/);
  });

  it('requires admin keys when registration is closed', () => {
    expect(() => validateTenantSeed({ ...base, openRegistration: false })).toThrow(/adminKeys is required/);
    expect(() => validateTenantSeed({ ...base, openRegistration: false, adminKeys: ['long-enough-admin-key'] })).not.toThrow();
  });

  it('rejects unknown policy fields and malformed bigint strings', () => {
    expect(() => validateTenantSeed({ ...base, policy: { maxCallGas: '0x123' } })).toThrow(/decimal string/);
    expect(() => validateTenantSeed({ ...base, policy: { totallyUnknown: true } })).toThrow();
  });

  it('rejects duplicate slugs, origins and admin keys across the seed array', () => {
    const other = { ...base, slug: 'other', walletOrigin: 'https://wallet.other.app' };
    expect(tenantsSeedSchema.safeParse([base, { ...other, slug: 'acme' }]).success).toBe(false);
    expect(tenantsSeedSchema.safeParse([base, { ...other, walletOrigin: base.walletOrigin }]).success).toBe(false);
    const sharedKey = 'shared-key-16-chars-min';
    expect(
      tenantsSeedSchema.safeParse([
        { ...base, adminKeys: [sharedKey] },
        { ...other, adminKeys: [sharedKey] },
      ]).success,
    ).toBe(false);
  });
});

describe('mergePolicy', () => {
  const defaults = {
    maxCallGas: 5_000_000n,
    maxVerificationGas: 5_000_000n,
    maxFeePerGas: 500_000_000_000n,
    maxPriorityFeePerGas: 500_000_000_000n,
    allowedTargets: [] as string[],
    allowedPaymasters: [] as string[],
  };

  it('overrides only the fields present in the tenant policy', () => {
    const merged = mergePolicy(defaults, { maxCallGas: '1000000' }, 31337);
    expect(merged.maxCallGas).toBe(1_000_000n);
    expect(merged.maxVerificationGas).toBe(5_000_000n);
    expect(merged.allowedTargets).toEqual([]);
  });

  it('address-valued policy resolves from perChain[chainId] only — never across chains (MC-61)', () => {
    const policy = {
      perChain: {
        '31337': { allowedPaymasters: ['0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'], maxCallGas: '777' },
        '31338': { allowedTargets: ['0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'] },
      },
    };
    const onA = mergePolicy(defaults, policy, 31337);
    expect(onA.allowedPaymasters).toEqual(['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']); // lowercased
    expect(onA.allowedTargets).toEqual([]); // 31338's targets do NOT leak to 31337
    expect(onA.maxCallGas).toBe(777n);
    const onB = mergePolicy(defaults, policy, 31338);
    expect(onB.allowedTargets).toEqual(['0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']);
    expect(onB.allowedPaymasters).toEqual([]); // 31337's paymasters do NOT leak to 31338
    expect(onB.maxCallGas).toBe(5_000_000n); // numeric caps fall back per chain
  });

  it('the schema cannot express a chain-agnostic address allowlist (S6)', () => {
    // allowedTargets at the tenant BASE level is rejected outright — the violation is
    // unrepresentable rather than prevented by a resolution rule.
    const merged = mergePolicy(defaults, { allowedTargets: ['0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'] }, 31337);
    expect(merged.allowedTargets).toEqual([]); // unparseable → fail safe to defaults
  });

  it('falls back to the defaults for an empty or unparseable stored policy', () => {
    expect(mergePolicy(defaults, {}, 31337)).toMatchObject({ maxCallGas: 5_000_000n });
    expect(mergePolicy(defaults, { maxCallGas: 12345 }, 31337)).toMatchObject({ maxCallGas: 5_000_000n }); // wrong type → fail safe
    expect(mergePolicy(defaults, null, 31337)).toMatchObject({ maxCallGas: 5_000_000n });
  });

  it('surfaces the per-tenant relay rate limit override — shared across chains (MC-63)', () => {
    expect(mergePolicy(defaults, { relayRateLimitPerMinute: 7 }, 31337).relayRateLimitPerMinute).toBe(7);
    expect(mergePolicy(defaults, {}, 31337).relayRateLimitPerMinute).toBeUndefined();
  });
});

describe('pinned tenant ids', () => {
  /**
   * The tenant id is not purely internal: the paymaster keys per-tenant gas balances on its 16
   * bytes. A deployment that pre-registers a tenant on chain has to be able to make the database
   * agree, or every sponsorship for that tenant is refused as "unknown tenant".
   */
  it('accepts a pinned uuid', () => {
    const seed = validateTenantSeed({
      id: '11111111-1111-4111-8111-111111111111',
      slug: 'pinned',
      walletOrigin: 'https://wallet.pinned.example',
      rpName: 'Pinned',
      openRegistration: true,
    });
    expect(seed.id).toBe('11111111-1111-4111-8111-111111111111');
  });

  it('rejects anything that is not a uuid', () => {
    expect(() =>
      validateTenantSeed({ id: 'not-a-uuid', slug: 'bad', walletOrigin: 'https://w.example', rpName: 'B', openRegistration: true }),
    ).toThrow(/id/);
  });

  it('leaves the id to the database when unset, as it always did', () => {
    const seed = validateTenantSeed({ slug: 'unpinned', walletOrigin: 'https://w2.example', rpName: 'U', openRegistration: true });
    expect(seed.id).toBeUndefined();
  });

  it('rejects two tenants pinning the same id', () => {
    const result = tenantsSeedSchema.safeParse([
      { id: '11111111-1111-4111-8111-111111111111', slug: 'a', walletOrigin: 'https://a.example', rpName: 'A', openRegistration: true },
      { id: '11111111-1111-4111-8111-111111111111', slug: 'b', walletOrigin: 'https://b.example', rpName: 'B', openRegistration: true },
    ]);
    expect(result.success).toBe(false);
  });
});
