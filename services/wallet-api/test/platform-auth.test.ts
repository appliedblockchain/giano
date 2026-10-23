import { eq, sql } from 'drizzle-orm';
import { createSiweMessage, generateSiweNonce } from 'viem/siwe';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { platformAdminChallenges, platformAdmins, platformAdminSessions } from '../src/db/schema.js';
import { resolveEnvironment } from '../src/environments.js';
import { ADMIN_KEY, ADMIN, PLATFORM_ENV, SECOND_ADMIN, startTestStack, STRANGER, stopTestStack, type AdminAccount, type TestContext } from './setup.js';

/**
 * Platform admin sign-in (specs/PLATFORM-ADMIN-SPECS.md §4, spec platform admin-authentication): who an
 * platform admin is, how they prove it, and that every failure looks the same from outside.
 */

let ctx: TestContext;

beforeAll(async () => {
  ctx = await startTestStack(PLATFORM_ENV);
}, 120_000);

afterAll(async () => {
  if (ctx) await stopTestStack(ctx);
});

type Account = AdminAccount;

const challenge = async (account: Account, chainId = 31337) => {
  const res = await ctx.app.inject({ method: 'POST', url: '/v1/platform/auth/challenge', payload: { address: account.address, chainId } });
  expect(res.statusCode).toBe(200);
  return res.json().message as string;
};

const verify = (message: string, signature: string, app = ctx.app) => app.inject({ method: 'POST', url: '/v1/platform/auth/verify', payload: { message, signature } });

const signIn = async (account: Account = ADMIN) => {
  const message = await challenge(account);
  const res = await verify(message, await account.signMessage({ message }));
  expect(res.statusCode).toBe(200);
  return res.json() as { token: string; expiresAt: string; admin: { id: string; address: string } };
};

const logout = (token: string, headers: Record<string, string> = {}) =>
  ctx.app.inject({ method: 'POST', url: '/v1/platform/auth/logout', headers: { authorization: `Bearer ${token}`, ...headers } });

const UNAUTHORIZED = { error: 'unauthorized', message: 'platform admin session required' };

describe('challenge', () => {
  it('issues a server-written EIP-4361 message for a listed admin and stores its exact text', async () => {
    const message = await challenge(ADMIN);
    expect(message).toMatch(/^paymaster\.localhost wants you to sign in with your Ethereum account:\n0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n/);
    expect(message).toContain('URI: http://paymaster.localhost');
    expect(message).toContain('Chain ID: 31337');
    expect(message).toContain('for 30 minutes');
    const [row] = await ctx.db.select().from(platformAdminChallenges).where(eq(platformAdminChallenges.message, message));
    expect(row.address).toBe(ADMIN.address.toLowerCase());
  });

  it('answers an unlisted address with the same shape and stores nothing', async () => {
    const before = await ctx.db.execute(sql`SELECT count(*)::int AS n FROM platform_admin_challenges`);
    const message = await challenge(STRANGER);
    expect(message).toMatch(/wants you to sign in with your Ethereum account:\n0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC\n/);
    const after = await ctx.db.execute(sql`SELECT count(*)::int AS n FROM platform_admin_challenges`);
    expect(after.rows[0]).toEqual(before.rows[0]);
  });
});

describe('verify', () => {
  it('turns the issued message, signed by its admin, into a gps_ session', async () => {
    const session = await signIn();
    expect(session.token).toMatch(/^gps_[A-Za-z0-9_-]{43}$/);
    expect(session.admin).toEqual({ id: 'admin-test', address: ADMIN.address.toLowerCase() });
    const minutes = (new Date(session.expiresAt).getTime() - Date.now()) / 60_000;
    expect(minutes).toBeGreaterThan(29);
    expect(minutes).toBeLessThanOrEqual(30);
    // only the hash is stored
    const rows = await ctx.db.select({ tokenHash: platformAdminSessions.tokenHash }).from(platformAdminSessions);
    expect(JSON.stringify(rows)).not.toContain(session.token);
  });

  const alterations: [string, (message: string) => string][] = [
    ['domain', (m) => m.replace(/^paymaster\.localhost/, 'evil.example')],
    ['uri', (m) => m.replace('URI: http://paymaster.localhost', 'URI: http://evil.example')],
    ['version', (m) => m.replace('Version: 1', 'Version: 2')],
    ['chainId', (m) => m.replace('Chain ID: 31337', 'Chain ID: 1')],
    ['issuedAt', (m) => m.replace(/Issued At: \S+/, 'Issued At: 2030-01-01T00:00:00.000Z')],
    ['expirationTime', (m) => m.replace(/Expiration Time: \S+/, 'Expiration Time: 2099-01-01T00:00:00.000Z')],
    ['statement', (m) => m.replace('Sign in to the Giano platform console.', 'Sign in.')],
  ];

  it.each(alterations)('refuses the issued message with %s changed and re-signed by the same key', async (_field, alter) => {
    const altered = alter(await challenge(ADMIN));
    const res = await verify(altered, await ADMIN.signMessage({ message: altered }));
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual(UNAUTHORIZED);
  });

  it('refuses a replay, an expired challenge, a wrong signer, an unlisted address and a message it never issued — all with one body', async () => {
    const message = await challenge(ADMIN);
    const signature = await ADMIN.signMessage({ message });
    expect((await verify(message, signature)).statusCode).toBe(200);
    const replay = await verify(message, signature);

    const stale = await challenge(ADMIN);
    await ctx.db.update(platformAdminChallenges).set({ expiresAt: new Date(Date.now() - 1000) }).where(eq(platformAdminChallenges.message, stale));
    const expired = await verify(stale, await ADMIN.signMessage({ message: stale }));

    const forAdmin = await challenge(ADMIN);
    const wrongSigner = await verify(forAdmin, await STRANGER.signMessage({ message: forAdmin }));

    const forStranger = await challenge(STRANGER);
    const unlisted = await verify(forStranger, await STRANGER.signMessage({ message: forStranger }));

    const forged = createSiweMessage({
      domain: 'paymaster.localhost',
      uri: 'http://paymaster.localhost',
      address: ADMIN.address,
      version: '1',
      chainId: 31337,
      nonce: generateSiweNonce(),
      issuedAt: new Date(),
      expirationTime: new Date(Date.now() + 60_000),
    });
    const notIssued = await verify(forged, await ADMIN.signMessage({ message: forged }));

    for (const res of [replay, expired, wrongSigner, unlisted, notIssued]) {
      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual(UNAUTHORIZED);
    }
    const failures = await ctx.app.metrics.platformAuthFailures.get();
    const reasons = failures.values.map((value) => value.labels.reason);
    expect(reasons).toEqual(expect.arrayContaining(['challenge-invalid', 'bad-signature', 'not-admin']));
  });

  it('refuses a malformed message and a malformed signature with the same body', async () => {
    const message = await challenge(ADMIN);
    for (const res of [await verify('not a sign-in message', '0x1234'), await verify(message, '0x1234')]) {
      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual(UNAUTHORIZED);
    }
  });

  it('yields exactly one session for two concurrent verifies of one nonce', async () => {
    const message = await challenge(ADMIN);
    const signature = await ADMIN.signMessage({ message });
    const results = await Promise.all([verify(message, signature), verify(message, signature)]);
    expect(results.map((res) => res.statusCode).sort()).toEqual([200, 401]);
  });
});

describe('the guard', () => {
  it('refuses any request carrying an Origin with 403, on every admin route, even with a valid session', async () => {
    const { token } = await signIn();
    const origin = { origin: 'https://evil.example' };
    const challengeRes = await ctx.app.inject({ method: 'POST', url: '/v1/platform/auth/challenge', headers: origin, payload: { address: ADMIN.address, chainId: 1 } });
    const verifyRes = await ctx.app.inject({ method: 'POST', url: '/v1/platform/auth/verify', headers: origin, payload: { message: 'x', signature: '0x00' } });
    const logoutRes = await logout(token, origin);
    // a registered tenant origin is refused too — CORS grants it, the platform tier does not
    const tenantOrigin = await logout(token, { origin: 'http://localhost:4000' });
    for (const res of [challengeRes, verifyRes, logoutRes, tenantOrigin]) {
      expect(res.statusCode).toBe(403);
      expect(res.json().error).toBe('platform-origin-refused');
    }
    // the session survived: the refusals never reached it
    expect((await logout(token)).statusCode).toBe(204);
  });

  it('refuses a tenant admin key on an admin route, and an admin session on an admin route', async () => {
    const adminKeyOnPlatformRoute = await logout(ADMIN_KEY);
    expect(adminKeyOnPlatformRoute.statusCode).toBe(401);
    expect(adminKeyOnPlatformRoute.json()).toEqual(UNAUTHORIZED);
    const { token } = await signIn();
    const sessionOnAdmin = await ctx.app.inject({ method: 'GET', url: '/v1/admin/ror-origins', headers: { authorization: `Bearer ${token}` } });
    expect(sessionOnAdmin.statusCode).toBe(401);
  });

  it('refuses a missing, an unknown and an expired session with one body', async () => {
    const { token } = await signIn();
    await ctx.db.update(platformAdminSessions).set({ expiresAt: new Date(Date.now() - 1000) }).where(sql`true`);
    const results = [
      await ctx.app.inject({ method: 'POST', url: '/v1/platform/auth/logout' }),
      await logout('gps_unknown'),
      await logout(token),
    ];
    for (const res of results) {
      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual(UNAUTHORIZED);
    }
  });

  it('ends a session on logout', async () => {
    const { token } = await signIn();
    expect((await logout(token)).statusCode).toBe(204);
    const again = await logout(token);
    expect(again.statusCode).toBe(401);
    expect(again.json()).toEqual(UNAUTHORIZED);
  });

  it('refuses a session whose admin has been removed, on the very next request', async () => {
    const { token } = await signIn(SECOND_ADMIN);
    await ctx.db.delete(platformAdmins).where(eq(platformAdmins.id, 'admin-second'));
    try {
      const res = await logout(token);
      expect(res.statusCode).toBe(401);
    } finally {
      await ctx.db.insert(platformAdmins).values({ id: 'admin-second', address: SECOND_ADMIN.address.toLowerCase(), addedBy: 'test' });
    }
  });
});

describe('configuration', () => {
  it('registers no admin route where the environment has no sign-in domain', async () => {
    const disabled = await buildApp({ config: { ...ctx.config, ENVIRONMENT: resolveEnvironment('reference') }, db: ctx.db });
    try {
      const res = await disabled.inject({ method: 'POST', url: '/v1/platform/auth/challenge', payload: { address: ADMIN.address, chainId: 1 } });
      expect(res.statusCode).toBe(404);
    } finally {
      await disabled.close();
    }
  });

  const baseEnv = {
    NODE_ENV: 'test',
    GIANO_DEPLOYMENT_CLASS: 'development',
    GIANO_ENVIRONMENT: 'test',
    DATABASE_URL: 'postgres://u:p@localhost:5432/db',
    CHAIN_ID: '31337',
    RPC_URL: 'http://localhost:8545',
    BUNDLER_URL: 'http://localhost:4337',
    ENTRYPOINT_ADDRESS: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
    FACTORY_ADDRESS: '0x2222222222222222222222222222222222222222',
  };
  const load = (env: Record<string, string>) => () => loadConfig({ ...baseEnv, ...env } as NodeJS.ProcessEnv);

  it('refuses to boot without a known GIANO_ENVIRONMENT', () => {
    expect(load({ GIANO_ENVIRONMENT: '' })).toThrow(/GIANO_ENVIRONMENT/);
    expect(load({ GIANO_ENVIRONMENT: 'staging' })).toThrow(/GIANO_ENVIRONMENT/);
  });

  it("takes the sign-in domain from the environment map, defaulting the uri to https on it", () => {
    expect(load({ GIANO_ENVIRONMENT: 'dev' })().ENVIRONMENT).toMatchObject({
      siweDomain: 'paymaster.dev.giano.appliedblockchain.dev',
      siweUri: 'https://paymaster.dev.giano.appliedblockchain.dev',
    });
    expect(load({ GIANO_ENVIRONMENT: 'e2e' })().ENVIRONMENT.siweUri).toBe('http://paymaster.localhost');
  });

  it('ignores the retired OPERATOR_* variables', () => {
    const config = load({ OPERATOR_ADDRESSES: '[]', OPERATOR_SIWE_DOMAIN: 'evil.example' })();
    expect(config.ENVIRONMENT.siweDomain).toBe('paymaster.localhost');
  });

  it('refuses a delete lag threshold the watcher can never meet', () => {
    expect(load({ TENANT_DELETE_MAX_LEDGER_LAG_BLOCKS: '1', PAYMASTER_WATCHER_CONFIRMATIONS: '1' })).toThrow(/must exceed PAYMASTER_WATCHER_CONFIRMATIONS/);
  });
});

describe('sign-in rate limit', () => {
  it('limits challenges per address, leaving other addresses unaffected', async () => {
    const limited = await buildApp({ config: { ...ctx.config, PLATFORM_RATE_LIMIT_PER_MINUTE: 2 }, db: ctx.db });
    try {
      const ask = (address: string) => limited.inject({ method: 'POST', url: '/v1/platform/auth/challenge', payload: { address, chainId: 1 } });
      const codes = [];
      for (let i = 0; i < 3; i++) codes.push((await ask(ADMIN.address)).statusCode);
      expect(codes).toEqual([200, 200, 429]);
      expect((await ask(SECOND_ADMIN.address)).statusCode).toBe(200);
    } finally {
      await limited.close();
    }
  });
});
