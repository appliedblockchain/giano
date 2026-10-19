import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const adminKey = 'provisioner-test-admin-key';
const paymaster = '0x1111111111111111111111111111111111111111';
const config = {
  enabled: true,
  maxCostPerTxWei: '1000',
  allowlist: [{ contract: paymaster, functions: 'all' }],
};
const json = (body: unknown) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
const run = () => import('../src/provision-sponsorship.js');

beforeEach(() => {
  vi.resetModules();
  vi.stubEnv('WALLET_API_URL', 'https://wallet.example.test/');
  vi.stubEnv('TENANT_SLUG', 'example');
  vi.stubEnv('CHAIN_ID', '84532,11155111');
  vi.stubEnv('SPONSORSHIP_CONFIG', JSON.stringify(config));
  vi.stubEnv('TENANTS_SEED', JSON.stringify([{
    slug: 'example', walletOrigin: 'https://wallet.example.test', rpName: 'Example', adminKeys: [adminKey],
  }]));
  vi.stubEnv('SPONSORSHIP_PAYMASTER_ADDRESS', paymaster);
  vi.stubEnv('SPONSORSHIP_REQUIRE_FUNDED', 'true');
  vi.spyOn(process, 'exit').mockImplementation(() => { throw new Error('exit 1'); });
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

/** Successful API responses, with individual requests overridden to exercise failures. */
function mockApi() {
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/readyz')) return json({ status: 'ok', sponsorship: 'ok' });
    if (init?.method === 'PUT') return json({ ok: true });
    if (url.includes('/balance?')) return json({
      paymasterAddress: paymaster, registered: true, balanceWei: '100', availableWei: '100', feeWei: '0',
      fundingInstructions: { to: paymaster, call: 'deposit' },
    });
    return json({ configured: true, valid: true, config });
  });
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

describe('deployable sponsorship provisioner', () => {
  it.each([
    ['http://wallet.example.test', 'WALLET_API_URL must use HTTPS'],
    ['ftp://wallet.example.test', 'WALLET_API_URL must use HTTPS'],
    ['not-a-url', 'WALLET_API_URL must be a valid HTTPS URL'],
    [undefined, 'WALLET_API_URL is required'],
  ])('rejects URL %s before any network request', async (url, message) => {
    vi.stubEnv('WALLET_API_URL', url);
    const fetch = mockApi();
    await expect(run()).rejects.toThrow('exit 1');
    expect(console.error).toHaveBeenCalledWith(message);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('provisions both chains through normalized HTTPS URLs with bounded requests and no redirects', async () => {
    const fetch = mockApi();
    await run();
    expect(fetch).toHaveBeenCalledTimes(7);
    expect(fetch.mock.calls[0]![0]).toBe('https://wallet.example.test/readyz');
    for (const [url, init] of fetch.mock.calls) {
      expect(init?.signal).toBeInstanceOf(AbortSignal);
      expect(init?.redirect).toBe('error');
      if (!url.endsWith('/readyz')) expect(init?.headers).toMatchObject({ authorization: `Bearer ${adminKey}` });
    }
    expect(process.exit).not.toHaveBeenCalled();
  });

  it.each(['PUT', 'read-back', 'balance'])('continues with the next chain after a %s transport failure', async (stage) => {
    const fetch = mockApi();
    fetch.mockImplementationOnce(async () => json({ status: 'ok', sponsorship: 'ok' }));
    if (stage !== 'PUT') fetch.mockImplementationOnce(async () => json({ ok: true }));
    if (stage === 'balance') fetch.mockImplementationOnce(async () => json({ configured: true, valid: true, config }));
    fetch.mockRejectedValueOnce(new TypeError('network unreachable'));
    await expect(run()).rejects.toThrow('exit 1');
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('example@84532: request or response failed: network unreachable'));
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining('example@11155111: sponsorship rules installed'));
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('1 of 2 chain(s)'));
  });

  it.each([
    ['<html>Bad gateway</html>', '<html>Bad gateway</html>'],
    ['service unavailable', 'service unavailable'],
    ['{"message":"tenant unavailable"}', 'tenant unavailable'],
    ['', ''],
  ])('preserves the status and message of HTTP error body %s', async (body, message) => {
    const fetch = mockApi();
    fetch.mockImplementationOnce(async () => json({ status: 'ok', sponsorship: 'ok' }));
    fetch.mockImplementationOnce(async () => new Response(body, { status: 502 }));
    await expect(run()).rejects.toThrow('exit 1');
    expect(console.error).toHaveBeenCalledWith(`  ✗ example@84532: PUT /v1/admin/sponsorship returned 502 ${message}`);
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining('example@11155111: sponsorship rules installed'));
  });

  it('times out a stalled chain and still processes the next chain', async () => {
    const timeout = AbortSignal.timeout.bind(AbortSignal);
    vi.spyOn(AbortSignal, 'timeout').mockImplementation(() => timeout(20));
    const fetch = mockApi();
    fetch.mockImplementationOnce(async () => json({ status: 'ok', sponsorship: 'ok' }));
    fetch.mockImplementationOnce((_url, init) => new Promise((_resolve, reject) => {
      init!.signal!.addEventListener('abort', () => reject(init!.signal!.reason), { once: true });
    }));
    await expect(run()).rejects.toThrow('exit 1');
    expect(AbortSignal.timeout).toHaveBeenCalledWith(10_000);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('example@84532: request or response failed:'));
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining('example@11155111: sponsorship rules installed'));
  });

  it('retries a readiness transport failure before provisioning', async () => {
    const fetch = mockApi();
    fetch.mockRejectedValueOnce(new TypeError('connection refused'));
    await run();
    expect(fetch.mock.calls.slice(0, 2).map(([url]) => url)).toEqual([
      'https://wallet.example.test/readyz', 'https://wallet.example.test/readyz',
    ]);
    expect(process.exit).not.toHaveBeenCalled();
  });
});
