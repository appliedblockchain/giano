import { describe, expect, it, vi } from 'vitest';
import { createErc7677PaymasterClient, SponsorshipRefusedError } from '../src';
import type { PaymasterUserOperation } from '../src/paymaster/erc7677-client';

const PAYMASTER = '0x1111111111111111111111111111111111111111' as const;
const SENDER = '0x2222222222222222222222222222222222222222' as const;

const userOperation: PaymasterUserOperation = {
  sender: SENDER,
  nonce: 7n,
  callData: '0xdeadbeef',
  callGasLimit: 200_000n,
  maxFeePerGas: 2_000_000_000n,
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function makeClient(fetchImpl: typeof fetch, token: string | null = 'session-token') {
  return createErc7677PaymasterClient({
    url: '/api/v1/paymaster',
    chainId: 31337,
    getSessionToken: () => token,
    fetchImpl,
  });
}

describe('ERC-7677 paymaster client', () => {
  /**
   * viem's `prepareUserOperation` spreads the operation's fields at the top level rather than
   * nesting them — which is how the client was originally wrong, and the failure was invisible
   * until a real bundler client drove it. A test that passes the shape the implementation expects
   * proves nothing about the shape viem actually sends, so both are asserted here.
   */
  describe('hook parameter shapes', () => {
    it('accepts the fields spread at the top level, as viem sends them', async () => {
      const fetchImpl = vi.fn(async () => jsonResponse({ result: { paymaster: PAYMASTER, paymasterData: '0x01' } }));
      const result = await makeClient(fetchImpl as unknown as typeof fetch).getPaymasterStubData({
        ...userOperation,
        chainId: 31337,
        entryPointAddress: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
      });
      expect(result.paymaster).toBe(PAYMASTER);

      const body = JSON.parse((fetchImpl.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
      expect(body.params[0].sender).toBe(SENDER);
    });

    it('accepts the operation nested, as our own review screen sends it', async () => {
      const fetchImpl = vi.fn(async () => jsonResponse({ result: { paymaster: PAYMASTER, paymasterData: '0x01' } }));
      const check = await makeClient(fetchImpl as unknown as typeof fetch).checkSponsorship({ userOperation });
      expect(check.sponsored).toBe(true);
    });

    it('says so plainly when called with neither', async () => {
      const fetchImpl = vi.fn();
      await expect(
        makeClient(fetchImpl as unknown as typeof fetch).getPaymasterStubData({ chainId: 1 } as never),
      ).rejects.toThrow(/without a user operation/);
    });
  });

  it('sends a JSON-RPC request carrying the session bearer and hex quantities', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ jsonrpc: '2.0', id: 1, result: { paymaster: PAYMASTER, paymasterData: '0xabcd' } }),
    );
    await makeClient(fetchImpl as unknown as typeof fetch).getPaymasterStubData({ userOperation });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/api/v1/paymaster');
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer session-token');

    const body = JSON.parse(init.body as string);
    expect(body.method).toBe('pm_getPaymasterStubData');
    expect(body.params[0]).toMatchObject({ sender: SENDER, nonce: '0x7', callGasLimit: '0x30d40' });
    expect(body.params[1]).toBe('0x0000000071727De22E5E9d8BAf0edAc6f37da032');
    expect(body.params[2]).toBe('0x7a69'); // 31337
  });

  it('omits gas fields the caller did not supply rather than sending them as zero', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ result: { paymaster: PAYMASTER, paymasterData: '0x' } }));
    await makeClient(fetchImpl as unknown as typeof fetch).getPaymasterStubData({
      userOperation: { sender: SENDER, nonce: 0n, callData: '0x' },
    });

    const body = JSON.parse((fetchImpl.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
    expect(body.params[0]).not.toHaveProperty('callGasLimit');
    expect(body.params[0]).not.toHaveProperty('maxFeePerGas');
  });

  it('decodes the gas limits the service returns', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({
        result: {
          paymaster: PAYMASTER,
          paymasterData: '0xabcd',
          paymasterVerificationGasLimit: '0x30d40',
          paymasterPostOpGasLimit: '0x186a0',
        },
      }),
    );
    const result = await makeClient(fetchImpl as unknown as typeof fetch).getPaymasterData({ userOperation });

    expect(result).toEqual({
      paymaster: PAYMASTER,
      paymasterData: '0xabcd',
      paymasterVerificationGasLimit: 200_000n,
      paymasterPostOpGasLimit: 100_000n,
    });
  });

  it('does not spend a round trip when there is no session', async () => {
    const fetchImpl = vi.fn();
    await expect(
      makeClient(fetchImpl as unknown as typeof fetch, null).getPaymasterData({ userOperation }),
    ).rejects.toBeInstanceOf(SponsorshipRefusedError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  describe('refusals', () => {
    it.each([
      [-32003, 'contract-not-allowed', false],
      [-32004, 'function-not-allowed', false],
      [-32006, 'cost-exceeds-cap', false],
      [-32007, 'insufficient-balance', true],
      [-32011, 'temporarily-unavailable', true],
    ])('maps code %i to %s', async (code, reason, retryable) => {
      const fetchImpl = vi.fn(async () => jsonResponse({ error: { code, message: 'nope' } }));
      const error = await makeClient(fetchImpl as unknown as typeof fetch)
        .getPaymasterData({ userOperation })
        .catch((e: unknown) => e as SponsorshipRefusedError);

      expect(error).toBeInstanceOf(SponsorshipRefusedError);
      expect(error.reason).toBe(reason);
      expect(error.retryable).toBe(retryable);
    });

    it('prefers data.reason over the numeric code, so the wallet never keys off prose', async () => {
      const fetchImpl = vi.fn(async () =>
        jsonResponse({ error: { code: -32000, message: 'x', data: { reason: 'cost-exceeds-cap' } } }),
      );
      const error = await makeClient(fetchImpl as unknown as typeof fetch)
        .getPaymasterData({ userOperation })
        .catch((e: unknown) => e as SponsorshipRefusedError);
      expect(error.reason).toBe('cost-exceeds-cap');
    });

    it('carries the rule-by-rule results through, so the console log can say which rule failed', async () => {
      const ruleResults = [
        { rule: 'contract-allowlist', passed: false, detail: '0xabc is not allow-listed' },
        { rule: 'max-cost', passed: true },
      ];
      const fetchImpl = vi.fn(async () =>
        jsonResponse({ error: { code: -32003, message: 'refused', data: { reason: 'contract-not-allowed', ruleResults } } }),
      );
      const error = await makeClient(fetchImpl as unknown as typeof fetch)
        .getPaymasterData({ userOperation })
        .catch((e: unknown) => e as SponsorshipRefusedError);
      expect(error.ruleResults).toEqual(ruleResults);
    });

    // R-21: an outage must never be mistaken for a rule refusal, because the two call for
    // completely different responses from the user.
    it('reports a transport failure as an outage rather than as a refusal', async () => {
      const fetchImpl = vi.fn(async () => {
        throw new TypeError('Failed to fetch');
      });
      const error = await makeClient(fetchImpl as unknown as typeof fetch)
        .getPaymasterData({ userOperation })
        .catch((e: unknown) => e as SponsorshipRefusedError);
      expect(error.reason).toBe('temporarily-unavailable');
      expect(error.retryable).toBe(true);
    });

    it('reports a malformed response as an outage', async () => {
      const fetchImpl = vi.fn(async () => new Response('<html>502</html>', { status: 502 }));
      const error = await makeClient(fetchImpl as unknown as typeof fetch)
        .getPaymasterData({ userOperation })
        .catch((e: unknown) => e as SponsorshipRefusedError);
      expect(error.reason).toBe('temporarily-unavailable');
    });

    it('reports a rejected session distinguishably', async () => {
      const fetchImpl = vi.fn(async () => new Response('', { status: 401 }));
      const error = await makeClient(fetchImpl as unknown as typeof fetch)
        .getPaymasterData({ userOperation })
        .catch((e: unknown) => e as SponsorshipRefusedError);
      expect(error.reason).toBe('not-your-wallet');
    });
  });

  describe('checkSponsorship', () => {
    // The review screen has to know before it renders an approve button (R-15), and there a
    // refusal is an expected outcome — so it comes back as a value, not as a throw.
    it('returns a refusal as a value', async () => {
      const fetchImpl = vi.fn(async () =>
        jsonResponse({ error: { code: -32007, message: 'this app has run out of gas credit' } }),
      );
      const check = await makeClient(fetchImpl as unknown as typeof fetch).checkSponsorship({ userOperation });

      expect(check).toEqual({
        sponsored: false,
        reason: 'insufficient-balance',
        message: 'this app has run out of gas credit',
        retryable: true,
        ruleResults: [],
      });
    });

    it('returns success with the paymaster that would sponsor', async () => {
      const fetchImpl = vi.fn(async () => jsonResponse({ result: { paymaster: PAYMASTER, paymasterData: '0x00' } }));
      const check = await makeClient(fetchImpl as unknown as typeof fetch).checkSponsorship({ userOperation });
      expect(check).toEqual({ sponsored: true, paymaster: PAYMASTER });
    });

    it('uses the stub method, so a pre-flight never reserves a balance', async () => {
      const fetchImpl = vi.fn(async () => jsonResponse({ result: { paymaster: PAYMASTER, paymasterData: '0x00' } }));
      await makeClient(fetchImpl as unknown as typeof fetch).checkSponsorship({ userOperation });

      const body = JSON.parse((fetchImpl.mock.calls[0] as unknown as [string, RequestInit])[1].body as string);
      expect(body.method).toBe('pm_getPaymasterStubData');
    });
  });
});
