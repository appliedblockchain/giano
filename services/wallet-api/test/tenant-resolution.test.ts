import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { tenants } from '../src/db/schema.js';
import { startTestStack, stopTestStack, TENANT_A, TENANT_B, type TestContext } from './setup.js';
import { createAuthenticator, makeRegistrationResponse } from './webauthn-fixtures.js';

/**
 * Only an active tenant resolves (specs/PLATFORM-ADMIN-SPECS.md §8): a suspended tenant must be
 * indistinguishable from an unknown one on every path that attributes a request to a tenant —
 * Origin, Host, admin key, session and CORS — and resume must restore it with no restart.
 */
let ctx: TestContext;
let sessionToken: string;

const setStatus = (slug: string, status: 'active' | 'suspended') => ctx.db.update(tenants).set({ status }).where(eq(tenants.slug, slug));

beforeAll(async () => {
  ctx = await startTestStack();
  const auth = createAuthenticator();
  const options = await ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/options',
    headers: { origin: TENANT_A.walletOrigin },
    payload: { externalUserId: 'lifecycle-user', kind: 'registration' },
  });
  const verify = await ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/registration/verify',
    headers: { origin: TENANT_A.walletOrigin },
    payload: {
      externalUserId: 'lifecycle-user',
      response: makeRegistrationResponse(auth, { challenge: options.json().challenge, origin: TENANT_A.walletOrigin, rpId: TENANT_A.rpId }),
    },
  });
  expect(verify.statusCode).toBe(200);
  sessionToken = verify.json().session.token;
}, 120_000);

afterAll(async () => {
  if (ctx) await stopTestStack(ctx);
});

describe('a suspended tenant resolves nowhere', () => {
  beforeAll(async () => {
    await setStatus(TENANT_A.slug, 'suspended');
  });

  it('refuses its Origin on ceremonies as an unknown tenant', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/options',
      headers: { origin: TENANT_A.walletOrigin },
      payload: { externalUserId: 'someone-new' },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe('unknown-tenant');
  });

  it('serves no /.well-known/webauthn for its Host', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/.well-known/webauthn', headers: { host: 'localhost:4000' } });
    expect(res.statusCode).toBe(404);
  });

  it('refuses its admin key', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/v1/admin/ror-origins', headers: { authorization: `Bearer ${TENANT_A.adminKey}` } });
    expect(res.statusCode).toBe(401);
  });

  it('refuses an existing user session, with and without an Origin, with the invalid-session body', async () => {
    const bare = await ctx.app.inject({ method: 'GET', url: '/v1/me', headers: { authorization: `Bearer ${sessionToken}` } });
    expect(bare.statusCode).toBe(401);
    expect(bare.json()).toEqual({ error: 'unauthorized', message: 'invalid or expired session' });
    const withOrigin = await ctx.app.inject({
      method: 'GET',
      url: '/v1/me',
      headers: { authorization: `Bearer ${sessionToken}`, origin: TENANT_A.walletOrigin },
    });
    expect(withOrigin.statusCode).toBe(401);
  });

  it('grants its wallet origin no CORS', async () => {
    const res = await ctx.app.inject({
      method: 'OPTIONS',
      url: '/v1/webauthn/options',
      headers: { origin: TENANT_A.walletOrigin, 'access-control-request-method': 'POST' },
    });
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('leaves every other tenant untouched', async () => {
    const wellKnown = await ctx.app.inject({ method: 'GET', url: '/.well-known/webauthn', headers: { host: 'wallet-b.localhost:4100' } });
    expect(wellKnown.statusCode).toBe(200);
    const admin = await ctx.app.inject({ method: 'GET', url: '/v1/admin/ror-origins', headers: { authorization: `Bearer ${TENANT_B.adminKey}` } });
    expect(admin.statusCode).toBe(200);
  });
});

describe('resume', () => {
  it('restores the tenant on the next request, including sessions issued before the suspension', async () => {
    await setStatus(TENANT_A.slug, 'active');
    const me = await ctx.app.inject({ method: 'GET', url: '/v1/me', headers: { authorization: `Bearer ${sessionToken}` } });
    expect(me.statusCode).toBe(200);
    const wellKnown = await ctx.app.inject({ method: 'GET', url: '/.well-known/webauthn', headers: { host: 'localhost:4000' } });
    expect(wellKnown.statusCode).toBe(200);
    const cors = await ctx.app.inject({
      method: 'OPTIONS',
      url: '/v1/webauthn/options',
      headers: { origin: TENANT_A.walletOrigin, 'access-control-request-method': 'POST' },
    });
    expect(cors.headers['access-control-allow-origin']).toBe(TENANT_A.walletOrigin);
  });
});
