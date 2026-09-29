import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { tenantTxMappings, tenantTxMappingsHistory, tenants } from '../src/db/schema.js';
import { sha256hex } from '../src/services/tenants.js';
import { startTestStack, stopTestStack, TENANT_A, TENANT_B, type TestContext } from './setup.js';

/**
 * Transaction display mappings through the HTTP surface: the admin CRUD a tenant drives with its
 * key, and the read the wallet performs at review time. The stack serves one chain (31337), so
 * `chainId` is implied on every request (MC-53); the per-chain cases pin it explicitly.
 */

const USDC = '0x1111111111111111111111111111111111111111';
const OTHER = '0x4444444444444444444444444444444444444444';
const CHAIN = 31337;

const erc20Abi = [
  { type: 'function', name: 'transfer', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }], outputs: [{ name: '', type: 'bool' }] },
];

const descriptorFor = (address: string, chainId = CHAIN, intent = 'Send USDC') => ({
  $schema: 'https://eips.ethereum.org/assets/eip-7730/erc7730-v1.schema.json',
  context: { contract: { deployments: [{ chainId, address }], abi: erc20Abi } },
  metadata: { owner: 'Acme', contractName: 'USD Coin' },
  display: {
    formats: {
      'transfer(address to, uint256 value)': {
        intent,
        interpolatedIntent: 'Send {value} to {to}',
        fields: [
          { path: 'value', label: 'Amount', format: 'tokenAmount', params: { tokenPath: '@.to' } },
          { path: 'to', label: 'Recipient', format: 'addressName' },
        ],
      },
    },
  },
});

let ctx: TestContext;
let tenantAId: string;

const admin = (key: string) => ({ authorization: `Bearer ${key}` });

beforeAll(async () => {
  ctx = await startTestStack();
  const rows = await ctx.db.select({ id: tenants.id, slug: tenants.slug }).from(tenants);
  tenantAId = rows.find((r) => r.slug === TENANT_A.slug)!.id;
}, 180_000);

afterAll(async () => {
  if (ctx) await stopTestStack(ctx);
});

beforeEach(async () => {
  await ctx.db.delete(tenantTxMappingsHistory);
  await ctx.db.delete(tenantTxMappings);
});

describe('admin: write and read back', () => {
  it('stores a valid descriptor and returns it with updatedAt', async () => {
    const put = await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC) });
    expect(put.statusCode, put.body).toBe(200);
    const body = put.json() as { contract: string; descriptor: unknown; updatedAt: string; valid: boolean };
    expect(body.contract).toBe(USDC);
    expect(body.valid).toBe(true);
    expect(new Date(body.updatedAt).getTime()).toBeGreaterThan(0);
    expect(body.descriptor).toEqual(descriptorFor(USDC));

    const get = await ctx.app.inject({ method: 'GET', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey) });
    expect(get.statusCode).toBe(200);
    expect((get.json() as { descriptor: unknown }).descriptor).toEqual(descriptorFor(USDC));
  });

  it('normalises the contract address to lowercase', async () => {
    const mixed = '0x1111111111111111111111111111111111111111'.replace('0x1111', '0x1111').toUpperCase().replace('0X', '0x');
    const put = await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${mixed}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(mixed) });
    expect(put.statusCode, put.body).toBe(200);
    expect((put.json() as { contract: string }).contract).toBe(USDC);
  });

  it('refuses a descriptor that does not bind the requested contract, storing nothing', async () => {
    const res = await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(OTHER) });
    expect(res.statusCode).toBe(400);
    const body = res.json() as { error: string; issues: Array<{ path: string; message: string }> };
    expect(body.error).toBe('validation');
    expect(body.issues[0]?.path).toBe('context.contract.deployments');
    expect(body.issues[0]?.message).toContain(`contract ${USDC}`);
    expect(await ctx.db.select().from(tenantTxMappings)).toHaveLength(0);
  });

  it('refuses a descriptor bound to the same contract on another chain only', async () => {
    const res = await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC, 8453) });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { issues: Array<{ path: string }> }).issues[0]?.path).toBe('context.contract.deployments');
  });

  it('refuses an invalid descriptor with the issue path', async () => {
    const bad = descriptorFor(USDC) as { display: { formats: Record<string, { fields: Array<{ path: string }> }> } };
    bad.display.formats['transfer(address to, uint256 value)']!.fields[1]!.path = 'recipient';
    const res = await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: bad });
    expect(res.statusCode).toBe(400);
    const body = res.json() as { issues: Array<{ path: string; message: string }> };
    expect(body.issues[0]).toEqual({
      path: 'display.formats.transfer(address to, uint256 value).fields[1].path',
      message: '"recipient" does not name an input of transfer(address,uint256) (inputs: to, value)',
    });
    expect(await ctx.db.select().from(tenantTxMappings)).toHaveLength(0);
  });

  it('refuses a body over 64 KiB', async () => {
    const huge = descriptorFor(USDC) as { metadata: Record<string, unknown> };
    huge.metadata.padding = 'x'.repeat(70 * 1024);
    const res = await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: huge });
    expect(res.statusCode).toBe(413);
    expect(await ctx.db.select().from(tenantTxMappings)).toHaveLength(0);
  });

  it('refuses a malformed contract parameter', async () => {
    const res = await ctx.app.inject({ method: 'PUT', url: '/v1/admin/tx-mappings/not-an-address', headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC) });
    expect(res.statusCode).toBe(400);
  });

  it('replaces atomically and keeps the previous descriptor in history', async () => {
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC, CHAIN, 'First') });
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC, CHAIN, 'Second') });

    const rows = await ctx.db.select().from(tenantTxMappings).where(eq(tenantTxMappings.tenantId, tenantAId));
    expect(rows).toHaveLength(1);
    expect((rows[0]!.descriptor as ReturnType<typeof descriptorFor>).display.formats['transfer(address to, uint256 value)']!.intent).toBe('Second');

    const history = await ctx.app.inject({ method: 'GET', url: '/v1/admin/tx-mappings/history', headers: admin(TENANT_A.adminKey) });
    const revisions = (history.json() as { revisions: Array<{ action: string; descriptor: ReturnType<typeof descriptorFor> | null }> }).revisions;
    expect(revisions.map((r) => r.action)).toEqual(['put', 'put']);
    expect(revisions[1]!.descriptor!.display.formats['transfer(address to, uint256 value)']!.intent).toBe('First');
  });
});

describe('admin: list, delete, history, isolation', () => {
  it('lists per chain and deletes with 204 then 404', async () => {
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC) });
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${OTHER}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(OTHER) });

    const list = await ctx.app.inject({ method: 'GET', url: `/v1/admin/tx-mappings?chainId=${CHAIN}`, headers: admin(TENANT_A.adminKey) });
    expect(list.statusCode).toBe(200);
    expect((list.json() as { mappings: Array<{ contract: string }> }).mappings.map((m) => m.contract)).toEqual([USDC, OTHER]);

    const otherChain = await ctx.app.inject({ method: 'GET', url: '/v1/admin/tx-mappings?chainId=8453', headers: admin(TENANT_A.adminKey) });
    expect(otherChain.statusCode).toBe(400); // not served by this deployment: unsupported-chain, never another chain's rows

    const del = await ctx.app.inject({ method: 'DELETE', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey) });
    expect(del.statusCode).toBe(204);
    const again = await ctx.app.inject({ method: 'DELETE', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey) });
    expect(again.statusCode).toBe(404);
    const get = await ctx.app.inject({ method: 'GET', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey) });
    expect(get.statusCode).toBe(404);

    const after = await ctx.app.inject({ method: 'GET', url: '/v1/admin/tx-mappings', headers: admin(TENANT_A.adminKey) });
    expect((after.json() as { mappings: Array<{ contract: string }> }).mappings.map((m) => m.contract)).toEqual([OTHER]);
  });

  it('records write, replace and delete in history, newest first, attributed by key hash', async () => {
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC, CHAIN, 'First') });
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC, CHAIN, 'Second') });
    await ctx.app.inject({ method: 'DELETE', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey) });

    const res = await ctx.app.inject({ method: 'GET', url: '/v1/admin/tx-mappings/history', headers: admin(TENANT_A.adminKey) });
    const revisions = (res.json() as { revisions: Array<{ action: string; contract: string; descriptor: ReturnType<typeof descriptorFor> | null; createdByKeyHash: string | null }> }).revisions;
    expect(revisions.map((r) => r.action)).toEqual(['delete', 'put', 'put']);
    expect(revisions[0]!.descriptor).toBeNull();
    expect(revisions[1]!.descriptor!.display.formats['transfer(address to, uint256 value)']!.intent).toBe('Second');
    expect(revisions[2]!.descriptor!.display.formats['transfer(address to, uint256 value)']!.intent).toBe('First');
    for (const r of revisions) {
      expect(r.contract).toBe(USDC);
      expect(r.createdByKeyHash).toBe(sha256hex(TENANT_A.adminKey));
    }
  });

  it("cannot read or delete another tenant's mapping (404, unchanged)", async () => {
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC) });

    const get = await ctx.app.inject({ method: 'GET', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_B.adminKey) });
    expect(get.statusCode).toBe(404);
    const del = await ctx.app.inject({ method: 'DELETE', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_B.adminKey) });
    expect(del.statusCode).toBe(404);
    const list = await ctx.app.inject({ method: 'GET', url: '/v1/admin/tx-mappings', headers: admin(TENANT_B.adminKey) });
    expect((list.json() as { mappings: unknown[] }).mappings).toEqual([]);

    const still = await ctx.app.inject({ method: 'GET', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey) });
    expect(still.statusCode).toBe(200);
  });

  it('requires an admin key', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/v1/admin/tx-mappings' });
    expect(res.statusCode).toBe(401);
  });
});

describe('wallet read', () => {
  it('serves the tenant\'s valid descriptors by Origin with a cache header', async () => {
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC) });

    const res = await ctx.app.inject({ method: 'GET', url: `/v1/tx-mappings?chainId=${CHAIN}`, headers: { origin: TENANT_A.walletOrigin } });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.headers['cache-control']).toBe('private, max-age=60');
    const body = res.json() as { chainId: number; mappings: unknown[]; updatedAt: string | null };
    expect(body.chainId).toBe(CHAIN);
    expect(body.mappings).toEqual([descriptorFor(USDC)]);
    expect(body.updatedAt).not.toBeNull();
  });

  it('resolves the tenant by Host when there is no Origin (a same-origin GET through the wallet\'s proxy)', async () => {
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC) });
    // inject() sets Host to localhost:80 by default; tenant A's rpId is `localhost`, so this is the
    // request nginx forwards from the stock wallet origin: no Origin, Host = the wallet's hostname.
    const res = await ctx.app.inject({ method: 'GET', url: '/v1/tx-mappings', headers: { host: 'localhost:4000' } });
    expect(res.statusCode, res.body).toBe(200);
    expect((res.json() as { mappings: unknown[] }).mappings).toEqual([descriptorFor(USDC)]);
    // Origin wins when both are present and disagree — it is what WebAuthn itself trusts.
    const byOrigin = await ctx.app.inject({ method: 'GET', url: '/v1/tx-mappings', headers: { host: 'localhost:4000', origin: TENANT_B.walletOrigin } });
    expect((byOrigin.json() as { mappings: unknown[] }).mappings).toEqual([]);
  });

  it('refuses an unknown Origin, or no Origin and an unknown Host, with 403 and discloses nothing', async () => {
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC) });
    const none = await ctx.app.inject({ method: 'GET', url: '/v1/tx-mappings', headers: { host: 'api.internal:8080' } });
    expect(none.statusCode).toBe(403);
    expect((none.json() as { error: string }).error).toBe('unknown-tenant');
    const unknown = await ctx.app.inject({ method: 'GET', url: '/v1/tx-mappings', headers: { host: 'api.internal:8080', origin: 'http://evil.example' } });
    expect(unknown.statusCode).toBe(403);
    expect(unknown.body).not.toContain('formats');
  });

  it('returns an empty list, not 404, when the tenant has nothing', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/v1/tx-mappings', headers: { origin: TENANT_B.walletOrigin, host: 'wallet-b.localhost:4100' } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ chainId: CHAIN, mappings: [], updatedAt: null });
  });

  it('does not serve another tenant\'s mappings', async () => {
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC) });
    const res = await ctx.app.inject({ method: 'GET', url: '/v1/tx-mappings', headers: { origin: TENANT_B.walletOrigin } });
    expect((res.json() as { mappings: unknown[] }).mappings).toEqual([]);
  });

  it('skips a stored descriptor that no longer validates and flags it for the admin', async () => {
    await ctx.app.inject({ method: 'PUT', url: `/v1/admin/tx-mappings/${USDC}`, headers: admin(TENANT_A.adminKey), payload: descriptorFor(USDC) });
    // A row written under rules that have since tightened: valid at the time, not now.
    const stale = descriptorFor(OTHER) as { display: { formats: Record<string, unknown> } };
    stale.display.formats = {};
    await ctx.db.insert(tenantTxMappings).values({ tenantId: tenantAId, chainId: CHAIN, contract: OTHER, descriptor: stale });

    const served = await ctx.app.inject({ method: 'GET', url: '/v1/tx-mappings', headers: { origin: TENANT_A.walletOrigin } });
    expect((served.json() as { mappings: unknown[] }).mappings).toEqual([descriptorFor(USDC)]);

    const listed = await ctx.app.inject({ method: 'GET', url: '/v1/admin/tx-mappings', headers: admin(TENANT_A.adminKey) });
    const mappings = (listed.json() as { mappings: Array<{ contract: string; valid: boolean; issues: Array<{ path: string }> }> }).mappings;
    expect(mappings.map((m) => [m.contract, m.valid])).toEqual([[USDC, true], [OTHER, false]]);
    expect(mappings[1]!.issues[0]!.path).toBe('display.formats');
  });
});
