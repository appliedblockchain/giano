import * as http from 'node:http';
import { expect, test } from '@playwright/test';
import { privateKeyToAccount } from 'viem/accounts';
import { loopbackOf } from '../origins.mjs';
import { connectWallet, TENANTS } from './helpers';

/**
 * The operator tier against the real two-tenant stack (specs/OPERATOR-ADMIN-SPECS.md §14.2):
 * a tenant suspended at runtime stops resolving through the real proxies and comes back on
 * resume, and a tenant created at runtime resolves with no container restarted. The API-level
 * matrix lives in the wallet-api vitest suite; this proves the same thing end to end.
 *
 * Operator calls go server-to-server to wallet-api's loopback port, the way the console's proxy
 * will, so they carry no Origin — operator routes refuse any request that does.
 */

// anvil's account 3, bootstrapped as ops-e2e for the e2e environment (services/wallet-api/src/environments.ts)
const OPERATOR = privateKeyToAccount('0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6');
const API = loopbackOf('api');

/** A raw request, so the Host header can name a tenant the way a browser on its origin would. */
function call(method: string, path: string, { body, headers = {} }: { body?: unknown; headers?: Record<string, string> } = {}) {
  const url = new URL(path, API);
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise<{ status: number; json: () => any }>((resolve, reject) => {
    const request = http.request(
      url,
      { method, headers: { ...(payload ? { 'content-type': 'application/json' } : {}), ...headers } },
      (response) => {
        let text = '';
        response.on('data', (chunk) => (text += chunk));
        response.on('end', () => resolve({ status: response.statusCode ?? 0, json: () => JSON.parse(text) }));
      },
    );
    request.on('error', reject);
    request.end(payload);
  });
}

async function signIn(): Promise<string> {
  const challenge = await call('POST', '/v1/operator/auth/challenge', { body: { address: OPERATOR.address, chainId: 31337 } });
  expect(challenge.status).toBe(200);
  const { message } = challenge.json();
  const verify = await call('POST', '/v1/operator/auth/verify', { body: { message, signature: await OPERATOR.signMessage({ message }) } });
  expect(verify.status).toBe(200);
  return verify.json().token;
}

test.describe('operator tenant administration', () => {
  let token: string;
  const asOperator = (method: string, path: string, body?: unknown) => call(method, path, { body, headers: { authorization: `Bearer ${token}` } });

  test.beforeAll(async () => {
    token = await signIn();
  });

  test('a suspended tenant stops resolving through its own wallet origin and returns on resume', async ({ page }) => {
    expect((await asOperator('POST', `/v1/operator/tenants/${TENANTS.byo.slug}/suspend`, { reason: 'e2e' })).status).toBe(200);
    try {
      // the BYO wallet's /api proxy, with the Origin a real browser on that origin sends
      await page.goto(TENANTS.byo.walletUrl);
      const refused = await page.evaluate(async () => {
        const res = await fetch('/api/v1/webauthn/options', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ externalUserId: 'suspended-probe' }),
        });
        return res.status;
      });
      expect(refused).toBe(403);
      expect((await call('GET', '/.well-known/webauthn', { headers: { host: 'wallet-byo.localhost' } })).status).toBe(404);

      // the other tenant is untouched throughout
      await connectWallet(page, TENANTS.stock);
    } finally {
      expect((await asOperator('POST', `/v1/operator/tenants/${TENANTS.byo.slug}/resume`)).status).toBe(200);
    }
    await connectWallet(page, TENANTS.byo);
  });

  test('a tenant created at runtime resolves with no container restarted', async () => {
    // a deleted slug is never reusable and this stack's database may outlive a run, so each run takes a fresh one
    const slug = `runtime-${Date.now()}`;
    const walletOrigin = `http://wallet-${slug}.localhost`;
    const created = await asOperator('POST', '/v1/operator/tenants', { slug, walletOrigin, rpName: 'Runtime E2E', openRegistration: true });
    expect(created.status).toBe(201);
    expect(created.json().tenant).toMatchObject({ slug, status: 'active' });

    const wellKnown = await call('GET', '/.well-known/webauthn', { headers: { host: `wallet-${slug}.localhost` } });
    expect(wellKnown.status).toBe(200);
    const options = await call('POST', '/v1/webauthn/options', { body: { externalUserId: 'runtime-user' }, headers: { origin: walletOrigin } });
    expect(options.status).toBe(200);

    // and it leaves no trace: suspend and delete (the stack's ledger is synced by its watcher)
    expect((await asOperator('POST', `/v1/operator/tenants/${slug}/suspend`, { reason: 'e2e cleanup' })).status).toBe(200);
    expect((await asOperator('DELETE', `/v1/operator/tenants/${slug}`)).status).toBe(204);
  });
});
