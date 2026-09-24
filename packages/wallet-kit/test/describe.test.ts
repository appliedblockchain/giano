import { describe, expect, it, vi } from 'vitest';
import { resolveWalletConfig } from '../src/config';
import { createTransactionDescriber } from '../src/describe';

/**
 * The kit's side of transaction descriptions: mapping fetch, token reads, caching, degradation.
 * The library's own behaviour (selection, formatting, unknowns) is covered in
 * packages/tx-describe; here the subject is what the runtime adds and what it does when the
 * things it depends on are not there.
 */

const CHAIN = 31337;
const USDC = '0x1111111111111111111111111111111111111111' as const;
const RECIPIENT = '0x2222222222222222222222222222222222222222' as const;
const transfer = (amount: bigint) => `0xa9059cbb${RECIPIENT.slice(2).padStart(64, '0')}${amount.toString(16).padStart(64, '0')}` as `0x${string}`;

const mapping = {
  context: {
    contract: {
      deployments: [{ chainId: CHAIN, address: USDC }],
      abi: [{ type: 'function', name: 'transfer', stateMutability: 'nonpayable', inputs: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }], outputs: [] }],
    },
  },
  metadata: { contractName: 'USD Coin' },
  display: {
    formats: {
      'transfer(address to, uint256 value)': {
        intent: 'Send USDC',
        interpolatedIntent: 'Send {value} to {to}',
        fields: [
          { path: 'value', label: 'Amount', format: 'tokenAmount', params: { tokenPath: '@.to' } },
          { path: 'to', label: 'Recipient', format: 'addressName' },
        ],
      },
    },
  },
};

const okFetch = (mappings: unknown[]) =>
  vi.fn(async () => new Response(JSON.stringify({ chainId: CHAIN, mappings, updatedAt: null }), { headers: { 'content-type': 'application/json' } }));

const erc20Client = (overrides: Partial<{ symbol: () => Promise<unknown>; decimals: () => Promise<unknown> }> = {}) => ({
  readContract: vi.fn(async ({ functionName }: { functionName: string }) => {
    if (functionName === 'symbol') return overrides.symbol ? overrides.symbol() : 'USDC';
    if (functionName === 'decimals') return overrides.decimals ? overrides.decimals() : 6;
    throw new Error(`unexpected read ${functionName}`);
  }),
});

const base = (fetch: typeof globalThis.fetch, client = erc20Client(), extra: Record<string, unknown> = {}) =>
  createTransactionDescriber({
    chainId: CHAIN,
    walletApiUrl: '/api',
    publicClient: client as never,
    nativeCurrency: { symbol: 'ETH', decimals: 18 },
    fetch,
    ...extra,
  });

describe('describeTransaction on a runtime', () => {
  it('applies the tenant mapping with token metadata read from the chain', async () => {
    const fetch = okFetch([mapping]);
    const describe = base(fetch as never);
    const result = await describe({ to: USDC, data: transfer(10_500_000n), value: '0x0' });
    expect(result.kind).toBe('described');
    if (result.kind !== 'described') return;
    expect(result.intent).toBe('Send 10.5 USDC to 0x2222…2222');
    expect(result.source).toBe('mapping');
    expect(result.warnings).toEqual([]);
    expect(String(fetch.mock.calls[0]![0])).toBe(`/api/v1/tx-mappings?chainId=${CHAIN}`);
  });

  it('degrades to built-ins with a warning when the wallet service is unreachable', async () => {
    const fetch = vi.fn(async () => {
      throw new TypeError('network down');
    });
    const describe = base(fetch as never);
    const result = await describe({ to: USDC, data: transfer(1_000_000n) });
    expect(result.kind).toBe('described');
    if (result.kind !== 'described') return;
    expect(result.source).toBe('generic');
    expect(result.warnings.map((w) => w.code)).toEqual(['mappings-unavailable', 'generic-interface']);
  });

  it('degrades with a warning when the mapping fetch times out', async () => {
    const fetch = vi.fn(() => new Promise<Response>(() => undefined)); // never settles
    const describe = base(fetch as never, erc20Client(), { timeoutMs: 20 });
    const result = await describe({ to: USDC, data: transfer(1_000_000n) });
    expect(result.kind).toBe('described');
    if (result.kind !== 'described') return;
    expect(result.warnings[0]?.code).toBe('mappings-unavailable');
  });

  it('treats a non-2xx mappings response as unavailable', async () => {
    const fetch = vi.fn(async () => new Response('nope', { status: 503 }));
    const result = await base(fetch as never)({ to: USDC, data: transfer(1n) });
    expect(result.warnings[0]?.code).toBe('mappings-unavailable');
  });

  it('shows an unscaled amount with a warning when the token read fails or times out', async () => {
    const failing = erc20Client({ decimals: async () => Promise.reject(new Error('execution reverted')) });
    const failed = await base(okFetch([mapping]) as never, failing)({ to: USDC, data: transfer(10_500_000n) });
    expect(failed.kind).toBe('described');
    if (failed.kind !== 'described') return;
    expect(failed.fields[0]?.value).toBe('10500000 (token 0x1111…1111)');
    expect(failed.warnings.map((w) => w.code)).toEqual(['token-unresolved']);

    const hanging = erc20Client({ symbol: () => new Promise(() => undefined) });
    const timedOut = await base(okFetch([mapping]) as never, hanging, { timeoutMs: 20 })({ to: USDC, data: transfer(10_500_000n) });
    expect(timedOut.kind === 'described' && timedOut.warnings.map((w) => w.code)).toEqual(['token-unresolved']);
  });

  it('fetches the mapping set once within the cache window and again after it', async () => {
    let clock = 0;
    const fetch = okFetch([mapping]);
    const client = erc20Client();
    const describe = base(fetch as never, client, { now: () => clock, mappingsTtlMs: 60_000 });
    await describe({ to: USDC, data: transfer(1n) });
    await describe({ to: USDC, data: transfer(2n) });
    expect(fetch).toHaveBeenCalledTimes(1);
    // token metadata is cached alongside: one symbol read and one decimals read for two calls
    expect(client.readContract).toHaveBeenCalledTimes(2);
    clock = 61_000;
    await describe({ to: USDC, data: transfer(3n) });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('keeps serving the last good mapping set when a refresh fails', async () => {
    let clock = 0;
    let fail = false;
    const fetch = vi.fn(async () => {
      if (fail) throw new Error('down');
      return new Response(JSON.stringify({ chainId: CHAIN, mappings: [mapping] }));
    });
    const describe = base(fetch as never, erc20Client(), { now: () => clock });
    await describe({ to: USDC, data: transfer(1n) });
    clock = 61_000;
    fail = true;
    const result = await describe({ to: USDC, data: transfer(1n) });
    expect(result.kind === 'described' && result.source).toBe('mapping');
    expect(result.warnings).toEqual([]);
  });

  it('names the chain\'s own currency for native value', async () => {
    const describe = createTransactionDescriber({
      chainId: CHAIN,
      walletApiUrl: '/api',
      publicClient: erc20Client() as never,
      nativeCurrency: { symbol: 'MATIC', decimals: 18 },
      fetch: okFetch([]) as never,
    });
    const result = await describe({ to: RECIPIENT, value: `0x${(1_500_000_000_000_000_000n).toString(16)}` as `0x${string}` });
    expect(result.kind === 'described' && result.intent).toBe('Send 1.5 MATIC to 0x2222…2222');
  });

  it('never rejects, even for garbage', async () => {
    const result = await base(okFetch([]) as never)({ to: USDC, data: '0xzz' as `0x${string}` });
    expect(result.kind).toBe('unknown');
  });
});

describe('nativeCurrency in the wallet config', () => {
  const raw = { chainId: 31337, factoryAddress: '0x1111111111111111111111111111111111111111' as const, sponsorship: 'off' as const, rpId: 'wallet.test' };

  it('defaults to ETH with 18 decimals', () => {
    expect(resolveWalletConfig({ raw }).chains[0]!.nativeCurrency).toEqual({ symbol: 'ETH', decimals: 18, name: 'Ether' });
  });

  it('accepts a well-formed currency and refuses a malformed one', () => {
    expect(resolveWalletConfig({ raw: { ...raw, nativeCurrency: { symbol: 'MATIC', decimals: 18 } } }).chains[0]!.nativeCurrency).toEqual({ symbol: 'MATIC', decimals: 18 });
    expect(() => resolveWalletConfig({ raw: { ...raw, nativeCurrency: { symbol: '', decimals: 18 } } })).toThrow(/nativeCurrency/);
    expect(() => resolveWalletConfig({ raw: { ...raw, nativeCurrency: { symbol: 'X', decimals: 1.5 } } })).toThrow(/nativeCurrency/);
  });
});
