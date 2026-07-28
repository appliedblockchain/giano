import { encodeFunctionData } from 'viem';
import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { seedTenants, validateTenantSeed } from '../src/services/tenants.js';
import {
  ADMIN_KEY,
  startTestStack,
  stopTestStack,
  TENANT_A,
  TENANT_B,
  TEST_ORIGIN,
  TEST_RP_ID,
  type TestContext,
} from './setup.js';
import { createAuthenticator, makeAuthenticationResponse, makeRegistrationResponse, type TestAuthenticator } from './webauthn-fixtures.js';

let ctx: TestContext;

beforeAll(async () => {
  ctx = await startTestStack();
}, 120_000);

afterAll(async () => {
  if (ctx) await stopTestStack(ctx);
});

type Tenant = typeof TENANT_A;

/** Ceremony calls carry the tenant's Origin header — that is what resolves the tenant. */
const getOptions = async (externalUserId: string, kind?: string, tenant: Tenant = TENANT_A, adminKey?: string) => {
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/options',
    headers: { origin: tenant.walletOrigin, ...(adminKey ? { authorization: `Bearer ${adminKey}` } : {}) },
    payload: { externalUserId, ...(kind ? { kind } : {}) },
  });
  expect(res.statusCode).toBe(200);
  return res.json() as { kind: string; challenge: string; credentialIds: string[]; userExists: boolean };
};

const register = async (externalUserId: string, auth: TestAuthenticator, tenant: Tenant = TENANT_A, adminKey?: string) => {
  const options = await getOptions(externalUserId, 'registration', tenant, adminKey);
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/registration/verify',
    headers: { origin: tenant.walletOrigin },
    payload: {
      externalUserId,
      response: makeRegistrationResponse(auth, { challenge: options.challenge, origin: tenant.walletOrigin, rpId: tenant.rpId }),
    },
  });
  expect(res.statusCode).toBe(200);
  return res.json() as { verified: boolean; walletAddress: string; credentialId: string; session: { token: string } };
};

describe('health', () => {
  it('healthz and readyz are green', async () => {
    expect((await ctx.app.inject({ method: 'GET', url: '/healthz' })).statusCode).toBe(200);
    const ready = await ctx.app.inject({ method: 'GET', url: '/readyz' });
    expect(ready.statusCode).toBe(200);
    expect(ready.json()).toEqual({ status: 'ready' });
  });
});

describe('admin + well-known', () => {
  it('rejects ROR admin calls without the admin key', async () => {
    const res = await ctx.app.inject({ method: 'POST', url: '/v1/admin/ror-origins', payload: { origin: 'https://dapp.example.com' } });
    expect(res.statusCode).toBe(401);
  });

  it('manages ROR origins and serves them on /.well-known/webauthn by Host', async () => {
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/v1/admin/ror-origins',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { origin: 'https://dapp.example.com' },
    });
    expect(created.statusCode).toBe(201);

    // resolved by Host header → tenant A (rp_id 'localhost')
    const wellKnown = await ctx.app.inject({ method: 'GET', url: '/.well-known/webauthn', headers: { host: 'localhost:4000' } });
    expect(wellKnown.statusCode).toBe(200);
    expect(wellKnown.json()).toEqual({ origins: ['https://dapp.example.com'] });

    const deleted = await ctx.app.inject({
      method: 'DELETE',
      url: `/v1/admin/ror-origins/${(created.json() as { id: string }).id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(deleted.statusCode).toBe(204);
  });

  it('serves 404 for a Host that is no tenant rp_id', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/.well-known/webauthn', headers: { host: 'unknown.example.com' } });
    expect(res.statusCode).toBe(404);
  });
});

describe('registration ceremony', () => {
  it('registers a passkey, computes the wallet address and issues a session', async () => {
    const body = await register('user-1', createAuthenticator());
    expect(body.verified).toBe(true);
    expect(body.walletAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(body.session.token).toBeTruthy();

    // session gates /v1/me
    const me = await ctx.app.inject({ method: 'GET', url: '/v1/me', headers: { authorization: `Bearer ${body.session.token}` } });
    expect(me.statusCode).toBe(200);
    expect((me.json() as { externalUserId: string }).externalUserId).toBe('user-1');
  });

  it('rejects ceremony calls without a resolvable tenant Origin', async () => {
    const noOrigin = await ctx.app.inject({ method: 'POST', url: '/v1/webauthn/options', payload: { externalUserId: 'x' } });
    expect(noOrigin.statusCode).toBe(403);
    expect((noOrigin.json() as { error: string }).error).toBe('unknown-tenant');

    const unknownOrigin = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/options',
      headers: { origin: 'https://not-a-tenant.example.com' },
      payload: { externalUserId: 'x' },
    });
    expect(unknownOrigin.statusCode).toBe(403);
  });

  it('rejects challenge replay', async () => {
    const auth = createAuthenticator();
    const options = await getOptions('user-replay', 'registration');
    const payload = {
      externalUserId: 'user-replay',
      response: makeRegistrationResponse(auth, { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
    };
    const headers = { origin: TEST_ORIGIN };
    expect((await ctx.app.inject({ method: 'POST', url: '/v1/webauthn/registration/verify', headers, payload })).statusCode).toBe(200);

    // same challenge again — different credential, same clientData challenge
    const replayed = {
      externalUserId: 'user-replay-2',
      response: makeRegistrationResponse(createAuthenticator(), { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
    };
    const res = await ctx.app.inject({ method: 'POST', url: '/v1/webauthn/registration/verify', headers, payload: replayed });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('bad-challenge');
  });

  it('rejects expired challenges', async () => {
    const options = await getOptions('user-expired', 'registration');
    await ctx.db.execute(sql`UPDATE challenges SET expires_at = now() - interval '1 minute' WHERE challenge = ${options.challenge}`);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
      headers: { origin: TEST_ORIGIN },
      payload: {
        externalUserId: 'user-expired',
        response: makeRegistrationResponse(createAuthenticator(), { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
      },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('bad-challenge');
  });

  it('rejects a response from the wrong origin', async () => {
    const options = await getOptions('user-origin', 'registration');
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
      headers: { origin: TEST_ORIGIN },
      payload: {
        externalUserId: 'user-origin',
        response: makeRegistrationResponse(createAuthenticator(), { challenge: options.challenge, origin: 'https://evil.test', rpId: TEST_RP_ID }),
      },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('verification-failed');
  });

  it('rejects a response bound to the wrong RP ID', async () => {
    const options = await getOptions('user-rpid', 'registration');
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
      headers: { origin: TEST_ORIGIN },
      payload: {
        externalUserId: 'user-rpid',
        response: makeRegistrationResponse(createAuthenticator(), { challenge: options.challenge, origin: TEST_ORIGIN, rpId: 'evil.test' }),
      },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('verification-failed');
  });

  it('rejects a challenge bound to a different user (challenge-user-mismatch)', async () => {
    // 'user-1' exists, so a registration challenge for them is user-bound
    const options = await getOptions('user-1', 'registration');
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
      headers: { origin: TEST_ORIGIN },
      payload: {
        externalUserId: 'someone-else-entirely',
        response: makeRegistrationResponse(createAuthenticator(), { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
      },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('challenge-user-mismatch');
  });

  it("requires the tenant's own admin key for options when open_registration is false", async () => {
    // tenant B runs with closed registration on the shared stack — no second app needed
    const anonymous = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/options',
      headers: { origin: TENANT_B.walletOrigin },
      payload: { externalUserId: 'x' },
    });
    expect(anonymous.statusCode).toBe(401);

    const admin = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/options',
      headers: { origin: TENANT_B.walletOrigin, authorization: `Bearer ${TENANT_B.adminKey}` },
      payload: { externalUserId: 'x' },
    });
    expect(admin.statusCode).toBe(200);
  });
});

describe('authentication ceremony', () => {
  it('signs in with an existing passkey and issues a fresh session', async () => {
    const auth = createAuthenticator();
    const registered = await register('user-auth', auth);

    const options = await getOptions('user-auth');
    expect(options.kind).toBe('authentication');
    expect(options.credentialIds).toContain(auth.credentialId.toString('base64url'));

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/authentication/verify',
      headers: { origin: TEST_ORIGIN },
      payload: { response: makeAuthenticationResponse(auth, { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }) },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { externalUserId: string; walletAddress: string; session: { token: string } };
    expect(body.externalUserId).toBe('user-auth');
    expect(body.walletAddress).toBe(registered.walletAddress);

    const logout = await ctx.app.inject({
      method: 'POST',
      url: '/v1/sessions/logout',
      headers: { authorization: `Bearer ${body.session.token}` },
    });
    expect(logout.statusCode).toBe(200);
    const afterLogout = await ctx.app.inject({ method: 'GET', url: '/v1/me', headers: { authorization: `Bearer ${body.session.token}` } });
    expect(afterLogout.statusCode).toBe(401);
  });

  it('rejects an assertion whose challenge was never issued', async () => {
    const auth = createAuthenticator();
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/authentication/verify',
      headers: { origin: TEST_ORIGIN },
      payload: {
        response: makeAuthenticationResponse(auth, { challenge: 'bm90LWEtcmVhbC1jaGFsbGVuZ2U', origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
      },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('userop relay', () => {
  let sessionToken: string;
  let walletAddress: string;
  const target = '0x3333333333333333333333333333333333333333';

  const makeOp = (nonce: number, overrides: Record<string, string> = {}) => ({
    sender: walletAddress,
    nonce: `0x${nonce.toString(16)}`,
    callData: encodeFunctionData({ abi: gianoSmartWalletAbi, functionName: 'execute', args: [target, 0n, '0x'] }),
    callGasLimit: '0x30000',
    verificationGasLimit: '0x30000',
    preVerificationGas: '0x10000',
    maxFeePerGas: '0x3b9aca00',
    maxPriorityFeePerGas: '0x3b9aca00',
    signature: '0x1234',
    ...overrides,
  });

  beforeAll(async () => {
    const registered = await register('userop-user', createAuthenticator());
    sessionToken = registered.session.token;
    walletAddress = registered.walletAddress;
  });

  it('requires a session', async () => {
    const res = await ctx.app.inject({ method: 'POST', url: '/v1/userops', payload: { userOperation: makeOp(1) } });
    expect(res.statusCode).toBe(401);
  });

  it('relays a compliant op to the bundler with the SERVER EntryPoint', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { userOperation: makeOp(1) },
    });
    expect(res.statusCode).toBe(200);
    const { userOperationHash } = res.json() as { userOperationHash: string };
    expect(userOperationHash).toMatch(/^0x[0-9a-f]{64}$/);

    const send = ctx.bundlerCalls.find((c) => c.method === 'eth_sendUserOperation');
    expect(send).toBeTruthy();
    // EntryPoint param comes from server config, never the request
    expect(send!.params[1]).toBe('0x0000000071727De22E5E9d8BAf0edAc6f37da032');

    // status endpoint sees it under the server-computed hash
    const opRow = await ctx.app.inject({
      method: 'GET',
      url: `/v1/userops/${userOperationHash}`,
      headers: { authorization: `Bearer ${sessionToken}` },
    });
    expect(opRow.statusCode).toBe(200);
    expect((opRow.json() as { status: string }).status).toBe('submitted');
  });

  it('is idempotent for duplicate submissions', async () => {
    const op = makeOp(2);
    const first = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { userOperation: op },
    });
    expect(first.statusCode).toBe(200);
    const second = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { userOperation: op },
    });
    expect(second.statusCode).toBe(200);
    expect((second.json() as { duplicate?: boolean }).duplicate).toBe(true);
  });

  it('rejects sender mismatch with a per-rule audit trail', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { userOperation: makeOp(3, { sender: '0x9999999999999999999999999999999999999999' }) },
    });
    expect(res.statusCode).toBe(403);
    const body = res.json() as { error: string; policy: { rule: string; passed: boolean }[] };
    expect(body.error).toBe('policy-rejected');
    expect(body.policy.find((r) => r.rule === 'sender-binding')!.passed).toBe(false);
    expect(body.policy.length).toBeGreaterThan(1);
  });

  it('rejects over-cap gas', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { userOperation: makeOp(4, { callGasLimit: '0x4c4b4000' }) }, // 1.28B gas
    });
    expect(res.statusCode).toBe(403);
    expect((res.json() as { message: string }).message).toContain('call-gas-cap');
  });

  it('never accepts an entryPoint from the request body', async () => {
    const op = { ...makeOp(5), account: { entryPoint: { address: '0x9999999999999999999999999999999999999999' } } };
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${sessionToken}` },
      payload: { userOperation: op },
    });
    expect(res.statusCode).toBe(200);
    const send = ctx.bundlerCalls.filter((c) => c.method === 'eth_sendUserOperation').at(-1)!;
    expect(send.params[1]).toBe('0x0000000071727De22E5E9d8BAf0edAc6f37da032');
  });

  it('serves receipts publicly (read-only)', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: `/v1/userops/0x${'ab'.repeat(32)}/receipt` });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveProperty('receipt');
  });
});

/**
 * Negative matrix from docs/MULTI-TENANCY-GAPS.md §10. Every gap stays open until one
 * of these fails without its fix.
 */
describe('tenant isolation', () => {
  const scrapeMetrics = async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/metrics' });
    expect(res.statusCode).toBe(200);
    return res.body;
  };

  it('V1: the same externalUserId on two tenants yields two users and two wallets', async () => {
    const onA = await register('shared-user-1', createAuthenticator(), TENANT_A);
    const onB = await register('shared-user-1', createAuthenticator(), TENANT_B, TENANT_B.adminKey);

    const rows = (await ctx.db.execute(sql`SELECT count(*)::int AS count FROM users WHERE external_id = 'shared-user-1'`)).rows as [
      { count: number },
    ];
    expect(rows[0].count).toBe(2); // pre-fix: onConflictDoUpdate silently merged them into one
    expect(onB.walletAddress).not.toBe(onA.walletAddress);
    expect(onB.credentialId).not.toBe(onA.credentialId);
  });

  it("V2: tenant A's credential replayed on tenant B is rejected by OUR tenant check (not rpIdHash)", async () => {
    const auth = createAuthenticator();
    await register('v2-victim', auth, TENANT_A);

    // build an assertion that would pass B's WebAuthn checks (B's origin and RP ID),
    // so the only thing standing is the server-side tenant scoping
    const options = await getOptions('v2-attacker', 'authentication', TENANT_B, TENANT_B.adminKey);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/authentication/verify',
      headers: { origin: TENANT_B.walletOrigin },
      payload: { response: makeAuthenticationResponse(auth, { challenge: options.challenge, origin: TENANT_B.walletOrigin, rpId: TENANT_B.rpId }) },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('unknown-credential');

    // the alertable counter proves the rejection came from the tenant guard
    const metrics = await scrapeMetrics();
    expect(metrics).toMatch(/giano_cross_tenant_rejections_total\{(?=[^}]*kind="credential")(?=[^}]*tenant="beta")[^}]*\} [1-9]/);
  });

  it("V3: a challenge issued on tenant A cannot be consumed on tenant B", async () => {
    const options = await getOptions('v3-user', 'registration', TENANT_A);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
      headers: { origin: TENANT_B.walletOrigin },
      payload: {
        externalUserId: 'v3-user',
        response: makeRegistrationResponse(createAuthenticator(), { challenge: options.challenge, origin: TENANT_B.walletOrigin, rpId: TENANT_B.rpId }),
      },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('bad-challenge');

    const metrics = await scrapeMetrics();
    expect(metrics).toMatch(/giano_cross_tenant_rejections_total\{(?=[^}]*kind="challenge")(?=[^}]*tenant="beta")[^}]*\} [1-9]/);
  });

  it("V4: tenant A's admin key does not authorize tenant B's options, and discloses nothing", async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/options',
      headers: { origin: TENANT_B.walletOrigin, authorization: `Bearer ${TENANT_A.adminKey}` },
      payload: { externalUserId: 'shared-user-1' },
    });
    expect(res.statusCode).toBe(401);
    expect(res.body).not.toContain('credentialIds');
  });

  it("V5: tenant A's session token is rejected when presented from tenant B's origin", async () => {
    const registered = await register('v5-user', createAuthenticator(), TENANT_A);

    const meOnB = await ctx.app.inject({
      method: 'GET',
      url: '/v1/me',
      headers: { authorization: `Bearer ${registered.session.token}`, origin: TENANT_B.walletOrigin },
    });
    expect(meOnB.statusCode).toBe(401);

    // same token is fine on its own tenant (and with no Origin — server-to-server)
    const meOnA = await ctx.app.inject({
      method: 'GET',
      url: '/v1/me',
      headers: { authorization: `Bearer ${registered.session.token}`, origin: TENANT_A.walletOrigin },
    });
    expect(meOnA.statusCode).toBe(200);
  });

  it('V6: one tenant\'s admin key cannot delete another tenant\'s ROR origin', async () => {
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/v1/admin/ror-origins',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { origin: 'https://v6.example.com' },
    });
    expect(created.statusCode).toBe(201);
    const id = (created.json() as { id: string }).id;

    const foreignDelete = await ctx.app.inject({
      method: 'DELETE',
      url: `/v1/admin/ror-origins/${id}`,
      headers: { authorization: `Bearer ${TENANT_B.adminKey}` },
    });
    expect(foreignDelete.statusCode).toBe(404); // indistinguishable from missing

    const ownDelete = await ctx.app.inject({
      method: 'DELETE',
      url: `/v1/admin/ror-origins/${id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(ownDelete.statusCode).toBe(204);
  });

  it('V7: /.well-known/webauthn is Host-scoped — each tenant sees only its own origins', async () => {
    const seedRor = async (adminKey: string, origin: string) => {
      const res = await ctx.app.inject({ method: 'POST', url: '/v1/admin/ror-origins', headers: { authorization: `Bearer ${adminKey}` }, payload: { origin } });
      expect(res.statusCode).toBe(201);
    };
    await seedRor(TENANT_A.adminKey, 'https://ror-alpha.example.com');
    await seedRor(TENANT_B.adminKey, 'https://ror-beta.example.com');

    const onA = await ctx.app.inject({ method: 'GET', url: '/.well-known/webauthn', headers: { host: 'localhost:4000' } });
    const originsA = (onA.json() as { origins: string[] }).origins;
    expect(originsA).toContain('https://ror-alpha.example.com');
    expect(originsA).not.toContain('https://ror-beta.example.com');

    const onB = await ctx.app.inject({ method: 'GET', url: '/.well-known/webauthn', headers: { host: 'wallet-b.localhost:4100' } });
    const originsB = (onB.json() as { origins: string[] }).origins;
    expect(originsB).toContain('https://ror-beta.example.com');
    expect(originsB).not.toContain('https://ror-alpha.example.com');
  });

  it("V9: a duplicate userop hash from another tenant never leaks `duplicate: true`", async () => {
    // the SAME authenticator (same P-256 key) on both tenants — the one legitimate way
    // to construct one wallet address, hence one userop hash, across two tenants
    const auth = createAuthenticator();
    const onA = await register('v9-user', auth, TENANT_A);
    const onB = await register('v9-user', auth, TENANT_B, TENANT_B.adminKey);
    expect(onB.walletAddress).toBe(onA.walletAddress); // address derivation is tenant-agnostic by construction

    const op = {
      sender: onA.walletAddress,
      nonce: '0x99',
      callData: encodeFunctionData({ abi: gianoSmartWalletAbi, functionName: 'execute', args: ['0x3333333333333333333333333333333333333333', 0n, '0x'] }),
      callGasLimit: '0x30000',
      verificationGasLimit: '0x30000',
      preVerificationGas: '0x10000',
      maxFeePerGas: '0x3b9aca00',
      maxPriorityFeePerGas: '0x3b9aca00',
      signature: '0x1234',
    };

    const first = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${onA.session.token}` },
      payload: { userOperation: op },
    });
    expect(first.statusCode).toBe(200);

    // byte-identical op via tenant B's session: same hash, different tenant → generic 409
    const fromB = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${onB.session.token}` },
      payload: { userOperation: op },
    });
    expect(fromB.statusCode).toBe(409);
    expect(fromB.body).not.toContain('duplicate": true');

    // while the original submitter still gets the idempotent answer
    const fromAAgain = await ctx.app.inject({
      method: 'POST',
      url: '/v1/userops',
      headers: { authorization: `Bearer ${onA.session.token}` },
      payload: { userOperation: op },
    });
    expect(fromAAgain.statusCode).toBe(200);
    expect((fromAAgain.json() as { duplicate?: boolean }).duplicate).toBe(true);
  });

  it('V11 (write path): re-seeding a tenant with a different rp_id is rejected', async () => {
    await expect(
      seedTenants(ctx.db, [
        validateTenantSeed({
          slug: TENANT_A.slug,
          walletOrigin: 'http://other.localhost:5000',
          rpName: 'Mutated',
          openRegistration: true,
        }),
      ]),
    ).rejects.toThrow(/rp_id is immutable/);
  });
});
