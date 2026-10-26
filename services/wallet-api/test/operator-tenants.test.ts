import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app.js';
import { paymasterState, paymasterTenants, sessions, sponsorshipReservations, tenantAdminKeys, tenantHistory, tenants, users } from '../src/db/schema.js';
import {
  OPERATOR,
  OPERATOR_ENV,
  operatorSignIn,
  SECOND_OPERATOR,
  startSponsorshipStack,
  stopTestStack,
  TENANT_A,
  TENANT_B,
  TEST_PAYMASTER_ADDRESS,
  type SponsorshipTestContext,
} from './setup.js';
import { createAuthenticator, makeRegistrationResponse } from './webauthn-fixtures.js';

/**
 * The operator tenant registry (specs/OPERATOR-ADMIN-SPECS.md §5, §7; specs tenant-administration
 * and tenant-lifecycle). Runs against a sponsoring stack, so delete meets a real ledger. The mock
 * chain reports head block 0, so a paymaster_state row synced at block 0 is a fresh ledger.
 */
let ctx: SponsorshipTestContext;
let token: string;
const CHAIN_ID = 31337;
const ACTOR = `operator:ops-test:${OPERATOR.address.toLowerCase()}`;

type InjectOptions = { payload?: unknown; headers?: Record<string, string>; as?: string; app?: SponsorshipTestContext['app'] };
const op = (method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string, { payload, headers = {}, as = token, app = ctx.app }: InjectOptions = {}) =>
  app.inject({ method, url, payload: payload as never, headers: { authorization: `Bearer ${as}`, ...headers } });

let counter = 0;
/** A fresh operator tenant on its own origin; open registration unless keys are asked for. */
const createTenant = async (overrides: Record<string, unknown> = {}) => {
  const slug = (overrides.slug as string) ?? `t${++counter}-${Date.now() % 100000}`;
  const res = await op('POST', '/v1/operator/tenants', {
    payload: { slug, walletOrigin: `http://wallet-${slug}.localhost`, rpName: slug, openRegistration: true, ...overrides },
  });
  expect(res.statusCode, res.body).toBe(201);
  return res.json() as { tenant: { id: string; slug: string; version: number; walletOrigin: string; rpId: string }; adminKeys: { id: string; label: string; key: string }[] };
};
const suspend = (slug: string) => op('POST', `/v1/operator/tenants/${slug}/suspend`, { payload: { reason: 'test' } });
const remove = (slug: string, app = ctx.app) => op('DELETE', `/v1/operator/tenants/${slug}`, { app });
const historyOf = async (tenantId: string) =>
  ctx.db.select().from(tenantHistory).where(eq(tenantHistory.tenantId, tenantId)).orderBy(tenantHistory.createdAt);

beforeAll(async () => {
  ctx = await startSponsorshipStack(OPERATOR_ENV);
  token = await operatorSignIn(ctx.app);
}, 120_000);

afterAll(async () => {
  if (ctx) await stopTestStack(ctx);
});

describe('access', () => {
  it('requires an operator session and refuses an Origin on tenant routes', async () => {
    expect((await ctx.app.inject({ method: 'GET', url: '/v1/operator/tenants' })).statusCode).toBe(401);
    const withOrigin = await op('GET', '/v1/operator/tenants', { headers: { origin: 'https://evil.example' } });
    expect(withOrigin.statusCode).toBe(403);
    expect(withOrigin.json().error).toBe('operator-origin-refused');
  });
});

describe('create', () => {
  it('creates an active operator-managed tenant that resolves on the next request, with no restart', async () => {
    const created = await createTenant({ slug: 'runtime', adminKeys: [{ label: 'ops' }] });
    expect(created.tenant).toMatchObject({ slug: 'runtime', status: 'active', managedBy: 'operator', version: 1, rpId: 'wallet-runtime.localhost' });
    expect(created.adminKeys).toEqual([{ id: expect.any(String), label: 'ops', key: expect.stringMatching(/^gak_[A-Za-z0-9_-]{43}$/) }]);

    const wellKnown = await ctx.app.inject({ method: 'GET', url: '/.well-known/webauthn', headers: { host: 'wallet-runtime.localhost' } });
    expect(wellKnown.statusCode).toBe(200);
    const options = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/options',
      headers: { origin: 'http://wallet-runtime.localhost' },
      payload: { externalUserId: 'runtime-user' },
    });
    expect(options.statusCode).toBe(200);
    // the issued key authorises the tenant's own admin routes
    const admin = await ctx.app.inject({ method: 'GET', url: '/v1/admin/ror-origins', headers: { authorization: `Bearer ${created.adminKeys[0].key}` } });
    expect(admin.statusCode).toBe(200);
  });

  it('shows keys once: reads list them by id, label and hash prefix, never as plaintext', async () => {
    const created = await createTenant({ adminKeys: [{ label: 'backend' }] });
    const detail = await op('GET', `/v1/operator/tenants/${created.tenant.slug}`);
    expect(detail.statusCode).toBe(200);
    expect(detail.headers.etag).toBe('"1"');
    expect(detail.json().adminKeys).toEqual([{ id: created.adminKeys[0].id, label: 'backend', hashPrefix: expect.stringMatching(/^[0-9a-f]{8}$/), createdBy: ACTOR, createdAt: expect.any(String) }]);
    expect(detail.body).not.toContain(created.adminKeys[0].key);
  });

  it('records the create, attributed to the operator and the session', async () => {
    const created = await createTenant({ adminKeys: [{ label: 'x' }] });
    const [entry] = await historyOf(created.tenant.id);
    expect(entry).toMatchObject({ action: 'create', actor: ACTOR, operatorSessionId: expect.any(String), before: null });
    expect(JSON.stringify(entry)).not.toContain(created.adminKeys[0].key);
  });

  it('applies the invariants: a bad rpId, an origin outside it, a closed tenant without keys, an unknown field', async () => {
    const base = { slug: 'bad', walletOrigin: 'http://wallet-bad.localhost', rpName: 'Bad' };
    const cases = [
      [{ ...base, rpId: 'localhost' }, '/rpId'],
      [{ ...base, expectedOrigins: ['http://evil.localhost'] }, '/expectedOrigins'],
      [{ ...base, openRegistration: false }, '/adminKeys'],
    ] as const;
    for (const [payload, path] of cases) {
      const res = await op('POST', '/v1/operator/tenants', { payload });
      expect(res.statusCode).toBe(400);
      expect(res.json().issues.map((issue: { path: string }) => issue.path)).toContain(path);
    }
    expect((await op('POST', '/v1/operator/tenants', { payload: { ...base, rpname: 'typo' } })).statusCode).toBe(400);
    expect((await ctx.db.select().from(tenants).where(eq(tenants.slug, 'bad'))).length).toBe(0);
  });

  it('refuses a duplicate slug, and an origin another tenant claims', async () => {
    const dupSlug = await op('POST', '/v1/operator/tenants', { payload: { slug: TENANT_A.slug, walletOrigin: 'http://wallet-other.localhost', rpName: 'x', openRegistration: true } });
    expect(dupSlug.statusCode).toBe(409);
    expect(dupSlug.json()).toMatchObject({ error: 'conflict', field: 'slug' });
    const claimed = await op('POST', '/v1/operator/tenants', { payload: { slug: 'copycat', walletOrigin: TENANT_A.walletOrigin, rpName: 'x', openRegistration: true } });
    expect(claimed.statusCode).toBe(409);
    expect(claimed.json()).toMatchObject({ error: 'origin-claimed', origin: TENANT_A.walletOrigin, slug: TENANT_A.slug });
  });

  it('lets exactly one of two concurrent creates claiming one origin win', async () => {
    const payload = (slug: string) => ({ slug, walletOrigin: 'http://wallet-contested.localhost', rpName: slug, openRegistration: true });
    const results = await Promise.all([op('POST', '/v1/operator/tenants', { payload: payload('one') }), op('POST', '/v1/operator/tenants', { payload: payload('two') })]);
    expect(results.map((res) => res.statusCode).sort()).toEqual([201, 409]);
    expect(results.find((res) => res.statusCode === 409)!.json().error).toBe('origin-claimed');
  });

  it('lets two tenants share a CORS origin', async () => {
    await createTenant({ corsOrigins: ['https://shared-dapp.example'] });
    await createTenant({ corsOrigins: ['https://shared-dapp.example'] });
  });
});

describe('read', () => {
  it('lists newest first, hides deleted tenants unless asked for, and 404s an unknown slug', async () => {
    const list = (await op('GET', '/v1/operator/tenants')).json().tenants as { slug: string; createdAt: string; status: string; users: number }[];
    expect(list.map((t) => t.slug)).toEqual(expect.arrayContaining([TENANT_A.slug, TENANT_B.slug, 'runtime']));
    const times = list.map((t) => Date.parse(t.createdAt));
    expect([...times].sort((a, b) => b - a)).toEqual(times);
    expect(list.every((t) => t.status !== 'deleted')).toBe(true);
    expect((await op('GET', '/v1/operator/tenants/nope')).statusCode).toBe(404);
  });
});

describe('update', () => {
  it('requires If-Match, refuses a stale version with the current one, and bumps the version', async () => {
    const { tenant } = await createTenant();
    const url = `/v1/operator/tenants/${tenant.slug}`;
    expect((await op('PATCH', url, { payload: { rpName: 'New' } })).statusCode).toBe(428);
    const stale = await op('PATCH', url, { payload: { rpName: 'New' }, headers: { 'if-match': '"7"' } });
    expect(stale.statusCode).toBe(412);
    expect(stale.json()).toMatchObject({ error: 'version-mismatch', version: 1 });
    const ok = await op('PATCH', url, { payload: { rpName: 'New', corsOrigins: ['https://dapp.example'] }, headers: { 'if-match': '"1"' } });
    expect(ok.statusCode).toBe(200);
    expect(ok.headers.etag).toBe('"2"');
    expect(ok.json()).toMatchObject({ rpName: 'New', corsOrigins: ['https://dapp.example'], version: 2 });
    const entries = await historyOf(tenant.id);
    expect(entries.at(-1)).toMatchObject({ action: 'update', before: expect.objectContaining({ rpName: tenant.slug }), after: expect.objectContaining({ rpName: 'New' }) });
  });

  it('gives one of two concurrent edits at the same version a 412', async () => {
    const { tenant } = await createTenant();
    const edit = (rpName: string) => op('PATCH', `/v1/operator/tenants/${tenant.slug}`, { payload: { rpName }, headers: { 'if-match': '"1"' } });
    const results = await Promise.all([edit('A'), edit('B')]);
    expect(results.map((res) => res.statusCode).sort()).toEqual([200, 412]);
  });

  it('refuses identity fields with 422 and invariant violations of the merged result with 400', async () => {
    const { tenant } = await createTenant();
    const url = `/v1/operator/tenants/${tenant.slug}`;
    const immutable = await op('PATCH', url, { payload: { walletOrigin: 'http://elsewhere.localhost' }, headers: { 'if-match': '"1"' } });
    expect(immutable.statusCode).toBe(422);
    expect(immutable.json()).toMatchObject({ error: 'immutable-field', fields: ['walletOrigin'] });
    const keyless = await op('PATCH', url, { payload: { openRegistration: false }, headers: { 'if-match': '"1"' } });
    expect(keyless.statusCode).toBe(400);
    expect(keyless.json().issues).toEqual([expect.objectContaining({ path: '/adminKeys' })]);
    const [row] = await ctx.db.select().from(tenants).where(eq(tenants.id, tenant.id));
    expect(row).toMatchObject({ openRegistration: true, version: 1 });
  });

  it('refuses an edit claiming an origin another tenant holds', async () => {
    const { tenant } = await createTenant({ slug: 'claimer' });
    // a second tenant whose wallet origin sits under the first tenant's rpId
    await createTenant({ slug: 'holder', walletOrigin: 'http://pay.wallet-claimer.localhost' });
    const res = await op('PATCH', '/v1/operator/tenants/claimer', {
      payload: { expectedOrigins: ['http://pay.wallet-claimer.localhost'] },
      headers: { 'if-match': `"${tenant.version}"` },
    });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ error: 'origin-claimed', origin: 'http://pay.wallet-claimer.localhost', slug: 'holder' });
  });
});

describe('seed-managed tenants', () => {
  it('refuse every write except suspend and resume', async () => {
    const url = `/v1/operator/tenants/${TENANT_B.slug}`;
    const [beta] = await ctx.db.select().from(tenants).where(eq(tenants.slug, TENANT_B.slug));
    const [key] = await ctx.db.select().from(tenantAdminKeys).where(eq(tenantAdminKeys.tenantId, beta.id));
    const writes = [
      await op('PATCH', url, { payload: { rpName: 'x' }, headers: { 'if-match': `"${beta.version}"` } }),
      await op('POST', `${url}/admin-keys`, { payload: { label: 'x' } }),
      await op('DELETE', `${url}/admin-keys/${key.id}`),
    ];
    for (const res of writes) expect(res.json().error).toBe('seed-managed');
    expect((await suspend(TENANT_B.slug)).statusCode).toBe(200);
    expect((await remove(TENANT_B.slug)).json().error).toBe('seed-managed');
    expect((await op('POST', `${url}/resume`)).statusCode).toBe(200);
  });

  it('cannot be adopted while still in TENANTS_SEED, and can once it has left', async () => {
    expect((await op('POST', `/v1/operator/tenants/${TENANT_A.slug}/adopt`)).json().error).toBe('still-seeded');
    // a seed-managed tenant whose slug has left the seed
    await ctx.db.insert(tenants).values({ slug: 'legacy', walletOrigin: 'http://wallet-legacy.localhost', rpId: 'wallet-legacy.localhost', rpName: 'Legacy', expectedOrigins: ['http://wallet-legacy.localhost'], openRegistration: true });
    const adopted = await op('POST', '/v1/operator/tenants/legacy/adopt');
    expect(adopted.statusCode).toBe(200);
    expect(adopted.json()).toMatchObject({ managedBy: 'operator', version: 2 });
    expect((await op('PATCH', '/v1/operator/tenants/legacy', { payload: { rpName: 'Adopted' }, headers: { 'if-match': '"2"' } })).statusCode).toBe(200);
  });
});

describe('lifecycle', () => {
  it('suspends with a required reason, refuses impossible transitions, and serialises concurrent ones', async () => {
    const { tenant } = await createTenant();
    expect((await op('POST', `/v1/operator/tenants/${tenant.slug}/suspend`, { payload: {} })).statusCode).toBe(400);
    expect((await op('POST', `/v1/operator/tenants/${tenant.slug}/resume`)).json().error).toBe('invalid-transition');
    const results = await Promise.all([suspend(tenant.slug), suspend(tenant.slug)]);
    expect(results.map((res) => res.statusCode).sort()).toEqual([200, 409]);
    const entries = await historyOf(tenant.id);
    expect(entries.at(-1)).toMatchObject({ action: 'suspend', actor: ACTOR, detail: { reason: 'test' } });
  });

  it('refuses to delete an active tenant', async () => {
    const { tenant } = await createTenant();
    expect((await remove(tenant.slug)).json().error).toBe('tenant-not-suspended');
  });

  it('refuses to trust a ledger that was never synced', async () => {
    const { tenant } = await createTenant();
    await suspend(tenant.slug);
    const res = await remove(tenant.slug);
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ error: 'ledger-stale', chains: [{ chainId: CHAIN_ID, headBlock: '0', lastSyncedBlock: null }] });
  });

  describe('with a synced ledger', () => {
    beforeAll(async () => {
      await ctx.db.insert(paymasterState).values({ chainId: CHAIN_ID, paymasterAddress: TEST_PAYMASTER_ADDRESS.toLowerCase(), lastSyncedBlock: 0n }).onConflictDoNothing();
    });

    it('refuses while the tenant has funds, with the figures', async () => {
      const { tenant } = await createTenant();
      await suspend(tenant.slug);
      await ctx.db.insert(paymasterTenants).values({ tenantId: tenant.id, chainId: CHAIN_ID, paymasterAddress: TEST_PAYMASTER_ADDRESS.toLowerCase(), balanceWei: '100', lastSyncedBlock: 0n });
      const res = await remove(tenant.slug);
      expect(res.statusCode).toBe(409);
      expect(res.json()).toMatchObject({ error: 'tenant-has-funds', chains: [{ chainId: CHAIN_ID, balanceWei: '100', deficitWei: '0', lastSyncedBlock: '0' }] });
    });

    it('refuses while a reservation is open, and ignores one that expired unswept', async () => {
      const { tenant } = await createTenant();
      await suspend(tenant.slug);
      const reservation = {
        tenantId: tenant.id,
        chainId: CHAIN_ID,
        sender: '0x1111111111111111111111111111111111111111',
        nonce: '0',
        maxCostWei: '1',
        feeWei: '0',
        overheadWei: '0',
        totalWei: '1',
        state: 'reserved' as const,
      };
      const [open] = await ctx.db.insert(sponsorshipReservations).values({ ...reservation, expiresAt: new Date(Date.now() + 60_000) }).returning();
      expect((await remove(tenant.slug)).json().error).toBe('tenant-has-reservations');
      // still 'reserved' — no watcher swept it — but past its expiry
      await ctx.db.update(sponsorshipReservations).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(sponsorshipReservations.id, open.id));
      expect((await remove(tenant.slug)).statusCode).toBe(204);
    });

    it('tombstones: sessions and keys go, users stay, and the identity is never reusable', async () => {
      const { tenant, adminKeys } = await createTenant({ adminKeys: [{ label: 'k' }] });
      // a user with a live session on the tenant
      const auth = createAuthenticator();
      const options = await ctx.app.inject({ method: 'POST', url: '/v1/webauthn/options', headers: { origin: tenant.walletOrigin }, payload: { externalUserId: 'doomed-user', kind: 'registration' } });
      const registered = await ctx.app.inject({
        method: 'POST',
        url: '/v1/webauthn/registration/verify',
        headers: { origin: tenant.walletOrigin },
        payload: { externalUserId: 'doomed-user', response: makeRegistrationResponse(auth, { challenge: options.json().challenge, origin: tenant.walletOrigin, rpId: tenant.rpId }) },
      });
      expect(registered.statusCode).toBe(200);

      await suspend(tenant.slug);
      expect((await remove(tenant.slug)).statusCode).toBe(204);

      const [user] = await ctx.db.select().from(users).where(eq(users.tenantId, tenant.id));
      expect(user).toBeDefined();
      expect(await ctx.db.select().from(sessions).where(eq(sessions.userId, user.id))).toEqual([]);
      expect(await ctx.db.select().from(tenantAdminKeys).where(eq(tenantAdminKeys.tenantId, tenant.id))).toEqual([]);
      expect((await ctx.app.inject({ method: 'GET', url: '/v1/admin/ror-origins', headers: { authorization: `Bearer ${adminKeys[0].key}` } })).statusCode).toBe(401);

      const listed = (await op('GET', '/v1/operator/tenants')).json().tenants.map((t: { slug: string }) => t.slug);
      expect(listed).not.toContain(tenant.slug);
      const deleted = (await op('GET', '/v1/operator/tenants?status=deleted')).json().tenants.map((t: { slug: string }) => t.slug);
      expect(deleted).toContain(tenant.slug);

      const again = (payload: Record<string, unknown>) => op('POST', '/v1/operator/tenants', { payload: { rpName: 'again', openRegistration: true, ...payload } });
      expect((await again({ slug: tenant.slug, walletOrigin: 'http://wallet-fresh.localhost' })).json()).toMatchObject({ error: 'conflict', field: 'slug' });
      expect((await again({ slug: 'fresh-origin-reuse', walletOrigin: tenant.walletOrigin })).json()).toMatchObject({ error: 'origin-claimed', slug: tenant.slug });
      expect((await again({ slug: 'fresh-id-reuse', walletOrigin: 'http://wallet-fresh-id.localhost', id: tenant.id })).json()).toMatchObject({ error: 'conflict', field: 'id' });
      expect((await op('POST', `/v1/operator/tenants/${tenant.slug}/resume`)).json().error).toBe('invalid-transition');

      const entries = await historyOf(tenant.id);
      expect(entries.at(-1)).toMatchObject({ action: 'delete', actor: ACTOR, detail: { removed: expect.objectContaining({ sessions: 1 }) } });
    });
  });

  it('deletes a never-sponsored tenant on a deployment that does not sponsor', async () => {
    const { tenant } = await createTenant();
    await suspend(tenant.slug);
    const unsponsored = await buildApp({ config: { ...ctx.config, SPONSORSHIP_ENABLED: false }, db: ctx.db });
    try {
      expect((await remove(tenant.slug, unsponsored)).statusCode).toBe(204);
    } finally {
      await unsponsored.close();
    }
  });
});

describe('admin keys', () => {
  it('issues and revokes keys, never the last key of a closed tenant', async () => {
    const { tenant, adminKeys } = await createTenant({ openRegistration: false, adminKeys: [{ label: 'only' }] });
    const url = `/v1/operator/tenants/${tenant.slug}/admin-keys`;
    const last = await op('DELETE', `${url}/${adminKeys[0].id}`);
    expect(last.statusCode).toBe(409);
    expect(last.json().error).toBe('last-admin-key');
    expect((await ctx.app.inject({ method: 'GET', url: '/v1/admin/ror-origins', headers: { authorization: `Bearer ${adminKeys[0].key}` } })).statusCode).toBe(200);

    const issued = await op('POST', url, { payload: { label: 'second' } });
    expect(issued.statusCode).toBe(201);
    expect(issued.json().key).toMatch(/^gak_/);
    expect((await op('DELETE', `${url}/${adminKeys[0].id}`)).statusCode).toBe(204);
    expect((await ctx.app.inject({ method: 'GET', url: '/v1/admin/ror-origins', headers: { authorization: `Bearer ${adminKeys[0].key}` } })).statusCode).toBe(401);
    expect((await op('DELETE', `${url}/00000000-0000-4000-8000-000000000000`)).statusCode).toBe(404);

    const actions = (await historyOf(tenant.id)).map((entry) => entry.action);
    expect(actions).toEqual(['create', 'admin-key-issue', 'admin-key-revoke']);
  });

  it('issues no key for a suspended tenant', async () => {
    const { tenant } = await createTenant();
    await suspend(tenant.slug);
    expect((await op('POST', `/v1/operator/tenants/${tenant.slug}/admin-keys`, { payload: { label: 'x' } })).json().error).toBe('invalid-transition');
  });
});

describe('history', () => {
  it('pages newest first, 50 at a time', async () => {
    const { tenant } = await createTenant();
    for (let i = 0; i < 30; i++) {
      await suspend(tenant.slug);
      await op('POST', `/v1/operator/tenants/${tenant.slug}/resume`);
    }
    const first = (await op('GET', `/v1/operator/tenants/${tenant.slug}/history`)).json();
    expect(first.entries).toHaveLength(50);
    expect(first.entries[0].action).toBe('resume');
    expect(first.next).toBe(first.entries[49].id);
    const second = (await op('GET', `/v1/operator/tenants/${tenant.slug}/history?before=${first.next}`)).json();
    expect(second.entries).toHaveLength(11);
    expect(second.entries.at(-1).action).toBe('create');
    expect(second.next).toBeNull();
  });
});

describe('rate limit', () => {
  it('limits each operator session, leaving another operator unaffected', async () => {
    const limited = await buildApp({ config: { ...ctx.config, OPERATOR_RATE_LIMIT_PER_MINUTE: 3 }, db: ctx.db });
    try {
      const first = await operatorSignIn(limited);
      const codes = [];
      for (let i = 0; i < 4; i++) codes.push((await op('GET', '/v1/operator/tenants', { as: first, app: limited })).statusCode);
      expect(codes).toEqual([200, 200, 200, 429]);
      const second = await operatorSignIn(limited, SECOND_OPERATOR);
      expect((await op('GET', '/v1/operator/tenants', { as: second, app: limited })).statusCode).toBe(200);
    } finally {
      await limited.close();
    }
  });
});

describe('the seed takes over at boot', () => {
  it('a seed entry matching an operator tenant takes it over; the operator-issued key stops working', async () => {
    const { tenant, adminKeys } = await createTenant({ slug: 'acme-takeover', adminKeys: [{ label: 'ops' }] });
    const { seedTenants, validateTenantSeed } = await import('../src/services/tenants.js');
    await seedTenants(ctx.db, [validateTenantSeed({ slug: 'acme-takeover', walletOrigin: tenant.walletOrigin, rpName: 'Seeded', adminKeys: ['seeded-admin-key-001'] })], { warn: () => {} });
    const [row] = await ctx.db.select().from(tenants).where(and(eq(tenants.id, tenant.id)));
    expect(row).toMatchObject({ managedBy: 'seed', rpName: 'Seeded' });
    expect((await ctx.app.inject({ method: 'GET', url: '/v1/admin/ror-origins', headers: { authorization: `Bearer ${adminKeys[0].key}` } })).statusCode).toBe(401);
    const count = await ctx.db.execute(sql`SELECT count(*)::int AS n FROM tenant_history WHERE tenant_id = ${tenant.id} AND action = 'seed-takeover'`);
    expect(count.rows[0]).toEqual({ n: 1 });
  });
});
