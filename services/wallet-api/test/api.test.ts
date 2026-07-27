import { encodeFunctionData } from 'viem';
import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import {
  ADMIN_KEY,
  createMockBundlerFetch,
  startTestStack,
  stopTestStack,
  TEST_ORIGIN,
  TEST_RP_ID,
  TEST_WALLET_ADDRESS,
  type TestContext,
} from './setup.js';
import { createAuthenticator, makeAuthenticationResponse, makeRegistrationResponse } from './webauthn-fixtures.js';

let ctx: TestContext;

beforeAll(async () => {
  ctx = await startTestStack();
}, 120_000);

afterAll(async () => {
  if (ctx) await stopTestStack(ctx);
});

const getOptions = async (externalUserId: string, kind?: string) => {
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/options',
    payload: { externalUserId, ...(kind ? { kind } : {}) },
  });
  expect(res.statusCode).toBe(200);
  return res.json() as { kind: string; challenge: string; credentialIds: string[]; userExists: boolean };
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

  it('manages ROR origins and serves them on /.well-known/webauthn', async () => {
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/v1/admin/ror-origins',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { origin: 'https://dapp.example.com' },
    });
    expect(created.statusCode).toBe(201);

    const wellKnown = await ctx.app.inject({ method: 'GET', url: '/.well-known/webauthn' });
    expect(wellKnown.statusCode).toBe(200);
    expect(wellKnown.json()).toEqual({ origins: ['https://dapp.example.com'] });

    const deleted = await ctx.app.inject({
      method: 'DELETE',
      url: `/v1/admin/ror-origins/${(created.json() as { id: string }).id}`,
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(deleted.statusCode).toBe(204);
  });
});

describe('registration ceremony', () => {
  it('registers a passkey, computes the wallet address and issues a session', async () => {
    const auth = createAuthenticator();
    const options = await getOptions('user-1');
    expect(options.kind).toBe('registration');
    expect(options.userExists).toBe(false);

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
      payload: {
        externalUserId: 'user-1',
        response: makeRegistrationResponse(auth, { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
      },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { verified: boolean; walletAddress: string; session: { token: string } };
    expect(body.verified).toBe(true);
    expect(body.walletAddress).toBe(TEST_WALLET_ADDRESS);
    expect(body.session.token).toBeTruthy();

    // session gates /v1/me
    const me = await ctx.app.inject({ method: 'GET', url: '/v1/me', headers: { authorization: `Bearer ${body.session.token}` } });
    expect(me.statusCode).toBe(200);
    expect((me.json() as { externalUserId: string }).externalUserId).toBe('user-1');
  });

  it('rejects challenge replay', async () => {
    const auth = createAuthenticator();
    const options = await getOptions('user-replay', 'registration');
    const payload = {
      externalUserId: 'user-replay',
      response: makeRegistrationResponse(auth, { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
    };
    expect((await ctx.app.inject({ method: 'POST', url: '/v1/webauthn/registration/verify', payload })).statusCode).toBe(200);

    // same challenge again — different credential, same clientData challenge
    const replayed = {
      externalUserId: 'user-replay-2',
      response: makeRegistrationResponse(createAuthenticator(), { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
    };
    const res = await ctx.app.inject({ method: 'POST', url: '/v1/webauthn/registration/verify', payload: replayed });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('bad-challenge');
  });

  it('rejects expired challenges', async () => {
    const options = await getOptions('user-expired', 'registration');
    await ctx.db.execute(sql`UPDATE challenges SET expires_at = now() - interval '1 minute' WHERE challenge = ${options.challenge}`);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
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
      payload: {
        externalUserId: 'user-rpid',
        response: makeRegistrationResponse(createAuthenticator(), { challenge: options.challenge, origin: TEST_ORIGIN, rpId: 'evil.test' }),
      },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('verification-failed');
  });

  it('requires an admin key for options when OPEN_REGISTRATION=false', async () => {
    const config = loadConfig({
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      DATABASE_URL: ctx.container.getConnectionUri(),
      RP_ID: TEST_RP_ID,
      EXPECTED_ORIGINS: TEST_ORIGIN,
      CHAIN_ID: '31337',
      RPC_URL: ctx.rpc.url,
      BUNDLER_URL: 'http://bundler.test',
      ENTRYPOINT_ADDRESS: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
      FACTORY_ADDRESS: '0x2222222222222222222222222222222222222222',
      OPEN_REGISTRATION: 'false',
      ADMIN_API_KEYS: ADMIN_KEY,
    } as NodeJS.ProcessEnv);
    const closedApp = await buildApp({ config, db: ctx.db, fetchImpl: createMockBundlerFetch().fetchImpl });
    try {
      const anonymous = await closedApp.inject({ method: 'POST', url: '/v1/webauthn/options', payload: { externalUserId: 'x' } });
      expect(anonymous.statusCode).toBe(401);
      const admin = await closedApp.inject({
        method: 'POST',
        url: '/v1/webauthn/options',
        headers: { authorization: `Bearer ${ADMIN_KEY}` },
        payload: { externalUserId: 'x' },
      });
      expect(admin.statusCode).toBe(200);
    } finally {
      await closedApp.close();
    }
  });
});

describe('authentication ceremony', () => {
  it('signs in with an existing passkey and issues a fresh session', async () => {
    const auth = createAuthenticator();
    const reg = await getOptions('user-auth', 'registration');
    const registered = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
      payload: {
        externalUserId: 'user-auth',
        response: makeRegistrationResponse(auth, { challenge: reg.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
      },
    });
    expect(registered.statusCode).toBe(200);

    const options = await getOptions('user-auth');
    expect(options.kind).toBe('authentication');
    expect(options.credentialIds).toContain(auth.credentialId.toString('base64url'));

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/authentication/verify',
      payload: { response: makeAuthenticationResponse(auth, { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }) },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { externalUserId: string; walletAddress: string; session: { token: string } };
    expect(body.externalUserId).toBe('user-auth');
    expect(body.walletAddress).toBe(TEST_WALLET_ADDRESS);

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
      payload: {
        response: makeAuthenticationResponse(auth, { challenge: 'bm90LWEtcmVhbC1jaGFsbGVuZ2U', origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
      },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('userop relay', () => {
  let sessionToken: string;
  const target = '0x3333333333333333333333333333333333333333';

  const makeOp = (nonce: number, overrides: Record<string, string> = {}) => ({
    sender: TEST_WALLET_ADDRESS,
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
    const auth = createAuthenticator();
    const options = await getOptions('userop-user', 'registration');
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/webauthn/registration/verify',
      payload: {
        externalUserId: 'userop-user',
        response: makeRegistrationResponse(auth, { challenge: options.challenge, origin: TEST_ORIGIN, rpId: TEST_RP_ID }),
      },
    });
    sessionToken = (res.json() as { session: { token: string } }).session.token;
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
