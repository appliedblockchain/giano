import { gianoSmartWalletAbi } from '@appliedblockchain/giano-contracts';
import { eq } from 'drizzle-orm';
import type { Address, Hex } from 'viem';
import { encodeFunctionData } from 'viem';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { paymasterTenants, sponsorshipDecisions, sponsorshipReservations, tenantSponsorship, tenants } from '../src/db/schema.js';
import { ADMIN_KEY, startSponsorshipStack, stopTestStack, TENANT_A, TENANT_B, type SponsorshipTestContext } from './setup.js';
import { createAuthenticator, makeRegistrationResponse } from './webauthn-fixtures.js';

/**
 * The ERC-7677 sponsorship service, end to end through the HTTP surface.
 *
 * Every refusal reason gets its own case, because the whole point of the typed reasons is that the
 * wallet can tell them apart — "this app doesn't support that contract" and "this app has run out
 * of gas credit" have to reach the user as different sentences.
 */

const TOKEN = '0x3333333333333333333333333333333333333333' as Address;
const OTHER = '0x4444444444444444444444444444444444444444' as Address;
const TRANSFER = '0xa9059cbb' as Hex;
const APPROVE = '0x095ea7b3' as Hex;
const ENTRY_POINT = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

let ctx: SponsorshipTestContext;
let tenantAId: string;
let tenantBId: string;

beforeAll(async () => {
  // Generous, so scenarios whose subject is not the wallet-management cap never trip it. The cap
  // itself is exercised by narrowing it in the one test that is about it.
  ctx = await startSponsorshipStack({ SPONSORSHIP_WALLET_MANAGEMENT_CAP_WEI: (10n ** 18n).toString() });
  const rows = await ctx.db.select({ id: tenants.id, slug: tenants.slug }).from(tenants);
  tenantAId = rows.find((r) => r.slug === TENANT_A.slug)!.id;
  tenantBId = rows.find((r) => r.slug === TENANT_B.slug)!.id;
}, 180_000);

afterAll(async () => {
  if (ctx) await stopTestStack(ctx);
});

// ── helpers ───────────────────────────────────────────────────────────────────

async function newSession(externalUserId: string): Promise<{ token: string; walletAddress: Address }> {
  const auth = createAuthenticator();
  const options = await ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/options',
    headers: { origin: TENANT_A.walletOrigin },
    payload: { externalUserId, kind: 'registration' },
  });
  const verified = await ctx.app.inject({
    method: 'POST',
    url: '/v1/webauthn/registration/verify',
    headers: { origin: TENANT_A.walletOrigin },
    payload: {
      externalUserId,
      response: makeRegistrationResponse(auth, {
        challenge: (options.json() as { challenge: string }).challenge,
        origin: TENANT_A.walletOrigin,
        rpId: TENANT_A.rpId,
      }),
    },
  });
  const body = verified.json() as { walletAddress: Address; session: { token: string } };
  return { token: body.session.token, walletAddress: body.walletAddress };
}

const execute = (target: Address, data: Hex = '0x'): Hex =>
  encodeFunctionData({ abi: gianoSmartWalletAbi, functionName: 'execute', args: [target, 0n, data] });

type RpcResult = {
  result?: { paymaster: string; paymasterData: string; paymasterVerificationGasLimit: string; paymasterPostOpGasLimit: string };
  error?: { code: number; message: string; data?: { reason: string; retryable: boolean; ruleResults: Array<{ rule: string; passed: boolean }> } };
};

async function rpc(
  token: string,
  method: 'pm_getPaymasterStubData' | 'pm_getPaymasterData',
  op: Record<string, unknown>,
  overrides: { entryPoint?: string; chainId?: string; context?: unknown } = {},
): Promise<RpcResult> {
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/v1/paymaster',
    headers: { authorization: `Bearer ${token}`, origin: TENANT_A.walletOrigin },
    payload: {
      jsonrpc: '2.0',
      id: 1,
      method,
      params: [op, overrides.entryPoint ?? ENTRY_POINT, overrides.chainId ?? '0x7a69', overrides.context ?? {}],
    },
  });
  return res.json() as RpcResult;
}

function candidateOp(sender: Address, callData: Hex, extra: Record<string, unknown> = {}) {
  return {
    sender,
    nonce: '0x0',
    callData,
    callGasLimit: '0x30d40', // 200_000
    verificationGasLimit: '0x7a120', // 500_000
    preVerificationGas: '0xc350', // 50_000
    maxFeePerGas: '0x77359400', // 2 gwei
    maxPriorityFeePerGas: '0x3b9aca00', // 1 gwei
    paymasterVerificationGasLimit: '0x249f0', // 150_000
    paymasterPostOpGasLimit: '0x186a0', // 100_000
    ...extra,
  };
}

async function setConfig(adminKey: string, config: Record<string, unknown>) {
  return ctx.app.inject({
    method: 'PUT',
    url: '/v1/admin/sponsorship',
    headers: { authorization: `Bearer ${adminKey}` },
    payload: config,
  });
}

/** Registers and funds a tenant on the fake chain, and mirrors it into the ledger cache. */
async function fund(tenantId: string, balanceWei: bigint, deficitWei = 0n) {
  const bytes16 = `0x${tenantId.replace(/-/g, '')}`;
  ctx.paymasterState.registered.add(bytes16);
  ctx.paymasterState.tenantBalances.set(bytes16, balanceWei);
  ctx.paymasterState.tenantDeficits.set(bytes16, deficitWei);

  await ctx.db
    .insert(paymasterTenants)
    .values({
      tenantId,
      chainId: 31337,
      paymasterAddress: '0x15a2075f2407427c5dd0bde9d1966c48bd70e2f2',
      balanceWei: balanceWei.toString(),
      deficitWei: deficitWei.toString(),
    })
    .onConflictDoUpdate({
      target: [paymasterTenants.tenantId, paymasterTenants.chainId],
      set: { balanceWei: balanceWei.toString(), deficitWei: deficitWei.toString() },
    });
}

const generousConfig = {
  enabled: true,
  maxCostPerTxWei: (10n ** 17n).toString(),
  allowlist: [{ contract: TOKEN, functions: [TRANSFER] }],
};

beforeEach(async () => {
  // Reservations outlive a request by design, so they must be cleared here too — otherwise one
  // test's authorisation counts against the next test's balance.
  await ctx.db.delete(sponsorshipDecisions);
  await ctx.db.delete(sponsorshipReservations);
  await ctx.db.delete(tenantSponsorship);
  await ctx.db.delete(paymasterTenants);
  ctx.paymasterState.unreachable = false;
  ctx.paymasterState.feeOverrides.clear();
});

// ── authentication and binding ────────────────────────────────────────────────

describe('authentication', () => {
  it('refuses an unauthenticated request', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/paymaster',
      headers: { origin: TENANT_A.walletOrigin },
      payload: { jsonrpc: '2.0', id: 1, method: 'pm_getPaymasterStubData', params: [candidateOp(TOKEN, '0x'), ENTRY_POINT, '0x7a69', {}] },
    });
    expect(res.statusCode).toBe(401);
  });

  // R-12: the response must not reveal whether the other tenant exists, so it is the same generic
  // 401 an invalid token gets.
  it('refuses a session used against another tenant, without saying so', async () => {
    const session = await newSession('cross-tenant-user');
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/v1/paymaster',
      headers: { authorization: `Bearer ${session.token}`, origin: TENANT_B.walletOrigin },
      payload: { jsonrpc: '2.0', id: 1, method: 'pm_getPaymasterStubData', params: [candidateOp(TOKEN, '0x'), ENTRY_POINT, '0x7a69', {}] },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ error: 'unauthorized', message: 'invalid or expired session' });
  });

  it("refuses sponsorship for a wallet the session does not own", async () => {
    const session = await newSession('binding-user');
    await setConfig(ADMIN_KEY, generousConfig);
    await fund(tenantAId, 10n ** 18n);

    const body = await rpc(session.token, 'pm_getPaymasterData', candidateOp(OTHER, execute(TOKEN, TRANSFER)));
    expect(body.error?.data?.reason).toBe('not-your-wallet');
  });
});

// ── R-14: chain and EntryPoint are validated, not trusted ─────────────────────

describe('request validation', () => {
  it('refuses an EntryPoint that is not the configured one', async () => {
    const session = await newSession('ep-user');
    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)), {
      entryPoint: '0x1234567890123456789012345678901234567890',
    });
    expect(body.error?.data?.reason).toBe('chain-or-entrypoint-mismatch');
  });

  it('refuses a chain id that is not the configured one', async () => {
    const session = await newSession('chain-user');
    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)), {
      chainId: '0x1',
    });
    expect(body.error?.data?.reason).toBe('chain-or-entrypoint-mismatch');
  });

  // A tenant that came to depend on a field we silently ignored would break the day we honoured it.
  it('rejects unknown context keys rather than dropping them', async () => {
    const session = await newSession('ctx-user');
    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)), {
      context: { sponsorEverything: true },
    });
    expect(body.error?.code).toBe(-32602);
  });

  it('accepts the documented pre-flight hint', async () => {
    const session = await newSession('preflight-user');
    await setConfig(ADMIN_KEY, generousConfig);
    await fund(tenantAId, 10n ** 18n);

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)), {
      context: { preflight: true },
    });
    expect(body.result?.paymaster).toBeTruthy();
  });
});

// ── deny by default ───────────────────────────────────────────────────────────

describe('deny by default', () => {
  it('refuses a tenant that has never configured sponsorship', async () => {
    const session = await newSession('unconfigured-user');
    await fund(tenantAId, 10n ** 18n);

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));
    expect(body.error?.data?.reason).toBe('sponsorship-disabled');
    expect(body.result).toBeUndefined();
  });

  // R-10 in the storage layer: a value that no longer validates must degrade to no sponsorship,
  // never to permissive.
  it('refuses when the stored configuration no longer validates', async () => {
    const session = await newSession('broken-config-user');
    await fund(tenantAId, 10n ** 18n);
    await ctx.db.insert(tenantSponsorship).values({ tenantId: tenantAId, chainId: 31337, config: { enabled: true, allowlist: 'everything' } });

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));
    expect(body.error?.data?.reason).toBe('no-sponsorship-config');
  });

  it('refuses a tenant that switched sponsorship off', async () => {
    const session = await newSession('switched-off-user');
    await fund(tenantAId, 10n ** 18n);
    await setConfig(ADMIN_KEY, { enabled: false });

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));
    expect(body.error?.data?.reason).toBe('sponsorship-disabled');
  });
});

// ── the rules, each with its own reason ───────────────────────────────────────

describe('rule refusals', () => {
  beforeEach(async () => {
    await setConfig(ADMIN_KEY, generousConfig);
    await fund(tenantAId, 10n ** 18n);
  });

  it('sponsors an allowed contract and function', async () => {
    const session = await newSession(`allowed-${Math.random()}`);
    const body = await rpc(session.token, 'pm_getPaymasterData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));

    expect(body.error).toBeUndefined();
    expect(body.result?.paymaster.toLowerCase()).toBe('0x15a2075f2407427c5dd0bde9d1966c48bd70e2f2');
    // 130 bytes: the fixed header plus a 65-byte ECDSA signature.
    expect((body.result!.paymasterData.length - 2) / 2).toBe(130);
  });

  it('refuses a contract that is not allow-listed', async () => {
    const session = await newSession(`contract-${Math.random()}`);
    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(OTHER, TRANSFER)));
    expect(body.error?.data?.reason).toBe('contract-not-allowed');
    expect(body.error?.code).toBe(-32003);
  });

  it('refuses a function that is not allowed, distinguishably from the contract case', async () => {
    const session = await newSession(`function-${Math.random()}`);
    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, APPROVE)));
    expect(body.error?.data?.reason).toBe('function-not-allowed');
    expect(body.error?.code).toBe(-32004);
  });

  it('refuses a transaction above the tenant\'s cost cap', async () => {
    const session = await newSession(`cap-${Math.random()}`);
    await setConfig(ADMIN_KEY, { ...generousConfig, maxCostPerTxWei: '1' });

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));
    expect(body.error?.data?.reason).toBe('cost-exceeds-cap');
  });

  it('names exhaustion rather than failing generically when the balance is empty', async () => {
    const session = await newSession(`balance-${Math.random()}`);
    await fund(tenantAId, 1n);

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));
    expect(body.error?.data?.reason).toBe('insufficient-balance');
    expect(body.error?.data?.retryable).toBe(false);
  });

  it('reports an outstanding deficit as its own reason', async () => {
    const session = await newSession(`deficit-${Math.random()}`);
    await fund(tenantAId, 10n ** 18n, 1n);

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));
    expect(body.error?.data?.reason).toBe('tenant-in-deficit');
  });

  // A user adding a passkey on a new device holds no native token, so this has to work with
  // nothing about the wallet in the tenant's allowlist — a tenant that forgot to list something
  // must not be able to break its own users' account recovery.
  it('sponsors wallet management with nothing about the wallet allow-listed', async () => {
    const session = await newSession(`wallet-mgmt-${Math.random()}`);
    const selfCall = execute(session.walletAddress, '0x0f0f3f95');
    await setConfig(ADMIN_KEY, generousConfig);

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, selfCall));
    expect(body.error).toBeUndefined();
  });

  it('refuses wallet management only after the tenant explicitly opts out', async () => {
    const session = await newSession(`wallet-mgmt-off-${Math.random()}`);
    const selfCall = execute(session.walletAddress, '0x0f0f3f95');

    await setConfig(ADMIN_KEY, { ...generousConfig, walletManagement: { enabled: false } });

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, selfCall));
    expect(body.error?.data?.reason).toBe('wallet-management-not-sponsored');
  });

  it('refuses a wallet-management operation above the tenant\'s lowered cap, even under a generous tenant cap', async () => {
    const session = await newSession(`wallet-mgmt-cap-${Math.random()}`);
    const selfCall = execute(session.walletAddress, '0x0f0f3f95');

    await setConfig(ADMIN_KEY, { ...generousConfig, walletManagement: { enabled: true, maxCostPerTxWei: '1' } });

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, selfCall));
    expect(body.error?.data?.reason).toBe('cost-exceeds-cap');
  });

  // Platform policy, not the tenant's: a tenant may lower the cap and never raise it.
  it('rejects a tenant wallet-management cap above the platform cap at write time', async () => {
    const response = await ctx.app.inject({
      method: 'PUT',
      url: '/v1/admin/sponsorship',
      headers: { authorization: `Bearer ${ADMIN_KEY}`, origin: TENANT_A.walletOrigin },
      payload: { ...generousConfig, walletManagement: { enabled: true, maxCostPerTxWei: (10n ** 19n).toString() } },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json().issues[0].path).toBe('walletManagement.maxCostPerTxWei');
  });

  it('carries the rule-by-rule results so the wallet can log which rule failed', async () => {
    const session = await newSession(`rules-${Math.random()}`);
    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(OTHER, TRANSFER)));

    const rules = body.error!.data!.ruleResults;
    expect(rules.find((r) => r.rule === 'contract-allowlist')?.passed).toBe(false);
    expect(rules.find((r) => r.rule === 'sponsorship-enabled')?.passed).toBe(true);
  });
});

// ── R-21: an outage must not look like a refusal ──────────────────────────────

describe('availability', () => {
  it('reports an unreachable chain as an outage, not as a rule refusal', async () => {
    const session = await newSession('outage-user');
    await setConfig(ADMIN_KEY, generousConfig);
    await fund(tenantAId, 10n ** 18n);
    ctx.paymasterState.unreachable = true;

    const body = await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));
    expect(body.error?.data?.reason).toBe('temporarily-unavailable');
    expect(body.error?.data?.retryable).toBe(true);
  });
});

// ── the stub/data split ───────────────────────────────────────────────────────

describe('stub versus data', () => {
  beforeEach(async () => {
    await setConfig(ADMIN_KEY, generousConfig);
    await fund(tenantAId, 10n ** 18n);
  });

  /**
   * The split is the point. The stub call runs during estimation, possibly repeatedly, and is also
   * what the wallet's review screen calls before it renders an approve button — so it must not
   * reserve, or the ledger would fill with claims for operations nobody approved.
   */
  it('reserves nothing on a stub call and reserves on a data call', async () => {
    const session = await newSession(`split-${Math.random()}`);
    const op = candidateOp(session.walletAddress, execute(TOKEN, TRANSFER));

    await rpc(session.token, 'pm_getPaymasterStubData', op);
    await rpc(session.token, 'pm_getPaymasterStubData', op);

    const afterStubs = await ctx.app.inject({
      method: 'GET',
      url: '/v1/admin/sponsorship/balance',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect((afterStubs.json() as { reservedWei: string }).reservedWei).toBe('0');

    await rpc(session.token, 'pm_getPaymasterData', op);

    const afterData = await ctx.app.inject({
      method: 'GET',
      url: '/v1/admin/sponsorship/balance',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(BigInt((afterData.json() as { reservedWei: string }).reservedWei)).toBeGreaterThan(0n);
  });

  it('returns a stub whose signature is the same length as a real one', async () => {
    const session = await newSession(`stublen-${Math.random()}`);
    const op = candidateOp(session.walletAddress, execute(TOKEN, TRANSFER));

    const stub = await rpc(session.token, 'pm_getPaymasterStubData', op);
    const real = await rpc(session.token, 'pm_getPaymasterData', op);
    expect(stub.result!.paymasterData.length).toBe(real.result!.paymasterData.length);
    expect(stub.result!.paymasterData).not.toBe(real.result!.paymasterData);
  });

  // The chain enforces one operation per (sender, nonce); the ledger must not reserve twice for it.
  it('refuses a second authorisation for the same operation', async () => {
    const session = await newSession(`double-${Math.random()}`);
    const op = candidateOp(session.walletAddress, execute(TOKEN, TRANSFER));

    expect((await rpc(session.token, 'pm_getPaymasterData', op)).error).toBeUndefined();
    const second = await rpc(session.token, 'pm_getPaymasterData', op);
    expect(second.error?.data?.reason).toBe('insufficient-balance');
  });

  /**
   * D5's scenario at the HTTP boundary. Several authorisations requested in parallel against a
   * balance that covers only some: the overdrawing ones must be refused *before* a signature
   * exists, because the chain cannot undo a settlement.
   */
  it('refuses concurrently requested authorisations that would collectively overdraw', async () => {
    const session = await newSession(`concurrent-${Math.random()}`);

    // The charge per operation, computed the way the service does: gas prefund + pinned fee +
    // overhead bound. Funding 2.5× it means exactly two of the three can be authorised.
    const gasPrefund = 2_000_000_000n * (50_000n + 500_000n + 150_000n + 100_000n + 200_000n);
    const feeWei = 100_000_000_000_000n;
    const overheadWei = 2_000_000_000n * (40_000n + ((200_000n + 100_000n) * 1000n) / 10_000n);
    const singleCharge = gasPrefund + feeWei + overheadWei;

    await setConfig(ADMIN_KEY, { ...generousConfig, maxCostPerTxWei: (singleCharge * 2n).toString() });
    await fund(tenantAId, (singleCharge * 5n) / 2n);

    const results = await Promise.all([
      rpc(session.token, 'pm_getPaymasterData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER), { nonce: '0x1' })),
      rpc(session.token, 'pm_getPaymasterData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER), { nonce: '0x2' })),
      rpc(session.token, 'pm_getPaymasterData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER), { nonce: '0x3' })),
    ]);

    // Two signed, one refused before a signature existed — which is the only order in which the
    // chain cannot be left settling more than the tenant holds.
    expect(results.filter((r) => r.result)).toHaveLength(2);
    const refused = results.filter((r) => r.error);
    expect(refused).toHaveLength(1);
    expect(refused[0].error?.data?.reason).toBe('insufficient-balance');
  });
});

// ── R-06: the audit trail ─────────────────────────────────────────────────────

describe('decision records', () => {
  it('records both allowed and refused decisions, including pre-flight ones', async () => {
    const session = await newSession(`audit-${Math.random()}`);
    await setConfig(ADMIN_KEY, generousConfig);
    await fund(tenantAId, 10n ** 18n);

    await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));
    await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(OTHER, TRANSFER)));

    const res = await ctx.app.inject({
      method: 'GET',
      url: '/v1/admin/sponsorship/decisions',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    const decisions = (res.json() as { decisions: Array<{ outcome: string; reason: string | null; method: string }> }).decisions;

    expect(decisions.some((d) => d.outcome === 'allowed' && d.method === 'stub')).toBe(true);
    // The record stores the *stable* reason, so a dashboard can group by it; the human-readable
    // detail lives in the rule results alongside it.
    const refusal = decisions.find((d) => d.outcome === 'refused');
    expect(refusal?.reason).toBe('contract-not-allowed');
  });

  it('keeps one tenant\'s decisions out of another\'s view', async () => {
    const session = await newSession(`isolation-${Math.random()}`);
    await setConfig(ADMIN_KEY, generousConfig);
    await fund(tenantAId, 10n ** 18n);
    await rpc(session.token, 'pm_getPaymasterStubData', candidateOp(session.walletAddress, execute(TOKEN, TRANSFER)));

    const res = await ctx.app.inject({
      method: 'GET',
      url: '/v1/admin/sponsorship/decisions',
      headers: { authorization: `Bearer ${TENANT_B.adminKey}` },
    });
    expect((res.json() as { decisions: unknown[] }).decisions).toHaveLength(0);
  });
});

// ── the admin write path ──────────────────────────────────────────────────────

describe('tenant configuration', () => {
  it('rejects an invalid rule set with per-path messages, and stores nothing', async () => {
    const res = await setConfig(ADMIN_KEY, { enabled: true });
    expect(res.statusCode).toBe(400);
    const issues = (res.json() as { issues: Array<{ path: string }> }).issues.map((i) => i.path);
    expect(issues).toContain('maxCostPerTxWei');
    expect(issues).toContain('allowlist');

    const rows = await ctx.db.select().from(tenantSponsorship).where(eq(tenantSponsorship.tenantId, tenantAId));
    expect(rows).toHaveLength(0);
  });

  it('normalises a function signature to a selector on write', async () => {
    await setConfig(ADMIN_KEY, {
      enabled: true,
      maxCostPerTxWei: '1000',
      allowlist: [{ contract: TOKEN, functions: ['transfer(address,uint256)'] }],
    });

    const res = await ctx.app.inject({ method: 'GET', url: '/v1/admin/sponsorship', headers: { authorization: `Bearer ${ADMIN_KEY}` } });
    const config = (res.json() as { config: { allowlist: Array<{ functions: string[] }> } }).config;
    expect(config.allowlist[0].functions).toEqual([TRANSFER]);
  });

  it('records who changed the rules and when', async () => {
    await setConfig(ADMIN_KEY, generousConfig);
    await setConfig(ADMIN_KEY, { ...generousConfig, maxCostPerTxWei: '999' });

    const res = await ctx.app.inject({
      method: 'GET',
      url: '/v1/admin/sponsorship/history',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    const revisions = (res.json() as { revisions: Array<{ createdByKeyHash: string | null }> }).revisions;
    expect(revisions.length).toBeGreaterThanOrEqual(2);
    // The key's hash, never the key itself.
    expect(revisions[0].createdByKeyHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('merges a partial update and re-validates the whole thing', async () => {
    await setConfig(ADMIN_KEY, generousConfig);

    const patched = await ctx.app.inject({
      method: 'PATCH',
      url: '/v1/admin/sponsorship',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { maxCostPerTxWei: '12345' },
    });
    expect(patched.statusCode).toBe(200);
    expect((patched.json() as { config: { maxCostPerTxWei: string; allowlist: unknown[] } }).config).toMatchObject({
      maxCostPerTxWei: '12345',
    });

    // A patch must not be able to leave the rule set in a state a full replace would reject.
    const broken = await ctx.app.inject({
      method: 'PATCH',
      url: '/v1/admin/sponsorship',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
      payload: { allowlist: [] },
    });
    expect(broken.statusCode).toBe(400);
  });

  it('is scoped to the tenant whose key authorised the request', async () => {
    await setConfig(ADMIN_KEY, generousConfig);

    const other = await ctx.app.inject({
      method: 'GET',
      url: '/v1/admin/sponsorship',
      headers: { authorization: `Bearer ${TENANT_B.adminKey}` },
    });
    expect((other.json() as { configured: boolean }).configured).toBe(false);
    void tenantBId;
  });

  // D7: the balance moves only through the chain, and the fee is Giano's to set.
  it('offers no way for a tenant to set its own balance or fee', async () => {
    const res = await setConfig(ADMIN_KEY, { ...generousConfig, balanceWei: '1000000', feeWei: '0' });
    expect(res.statusCode).toBe(400);
  });
});

describe('tenant reads', () => {
  it('reports the balance, the reservations and where to fund', async () => {
    await setConfig(ADMIN_KEY, generousConfig);
    await fund(tenantAId, 5n * 10n ** 17n);

    const res = await ctx.app.inject({
      method: 'GET',
      url: '/v1/admin/sponsorship/balance',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    const body = res.json() as {
      balanceWei: string;
      availableWei: string;
      registered: boolean;
      blockNumber: string;
      fundingInstructions: { to: string; call: string; tenantId: string };
    };

    expect(body.balanceWei).toBe((5n * 10n ** 17n).toString());
    expect(body.registered).toBe(true);
    // The block height is what lets a tenant reproduce the figure from the chain.
    expect(body.blockNumber).toBe('100');
    expect(body.fundingInstructions.tenantId).toBe(`0x${tenantAId.replace(/-/g, '')}`);
    expect(body.fundingInstructions.call).toContain('depositFor');
  });

  it('reports an unreachable chain as unavailable rather than as a zero balance', async () => {
    ctx.paymasterState.unreachable = true;
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/v1/admin/sponsorship/balance',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    });
    expect(res.statusCode).toBe(503);
  });
});
