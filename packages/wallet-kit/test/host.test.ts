import { RPC_ERRORS } from '@appliedblockchain/giano-wallet-transport';
import { describe, expect, it, vi } from 'vitest';
import { createHostRequestHandler } from '../src/host';
import { createRequestStore } from '../src/requests';
import type { WalletRuntime, WalletRuntimes } from '../src/runtimes';

function fakeRuntime(chainId: number, { account = true }: { account?: boolean } = {}) {
  let hasAccount = account;
  const calls: { method: string; params?: unknown }[] = [];
  const runtime = {
    chainId,
    chainName: `Chain ${chainId}`,
    provider: {
      getSmartAccount: () => (hasAccount ? {} : null),
      on: vi.fn(),
      request: vi.fn(async ({ method, params }: { method: string; params?: unknown }) => {
        calls.push({ method, params });
        if (method === 'giano_restoreAccount') {
          hasAccount = true;
          return undefined;
        }
        if (method === 'eth_chainId') return `0x${chainId.toString(16)}`;
        return `result:${method}`;
      }),
    },
  } as unknown as WalletRuntime;
  return { runtime, calls };
}

function harness(chainId = 31337, options: { account?: boolean } = {}) {
  const { runtime, calls } = fakeRuntime(chainId, options);
  const runtimes: WalletRuntimes = {
    servedChainIds: [chainId],
    runtimeFor: (id) => {
      if (id !== chainId) throw new Error(`does not serve ${id}`);
      return runtime;
    },
    descriptorFor: () => ({ chainId, name: `Chain ${chainId}` }) as never,
  };
  const requests = createRequestStore();
  const handler = createHostRequestHandler({ runtimes, requests });
  const context = { dappOrigin: 'https://app.test', chainId };
  return { handler, requests, calls, context, runtime };
}

describe('the host request handler (WK-08…WK-12)', () => {
  it('refuses wallet_switchEthereumChain with the typed 4200 error (WK-11, MC-14)', async () => {
    const { handler, context } = harness();
    for (const method of ['wallet_switchEthereumChain', 'wallet_addEthereumChain']) {
      await expect(handler(method, [{ chainId: '0x1' }], context)).rejects.toMatchObject({ code: RPC_ERRORS.UNSUPPORTED_METHOD });
    }
  });

  it('forwards read methods straight to the provider, with no consent', async () => {
    const { handler, requests, context } = harness();
    const result = await handler('eth_chainId', [], context);
    expect(result).toBe('0x7a69');
    expect(requests.current).toBeNull();
  });

  it('gates eth_requestAccounts behind a connect consent naming the chain (MC-80)', async () => {
    const { handler, requests, context } = harness();
    const call = handler('eth_requestAccounts', [], context);
    expect(requests.current).toMatchObject({ kind: 'connect', chainId: 31337, chainName: 'Chain 31337', dappOrigin: 'https://app.test' });
    requests.current!.approve();
    await expect(call).resolves.toBe('result:eth_requestAccounts');
  });

  it('answers 4001 on rejection without touching the provider (WK-09)', async () => {
    const { handler, requests, calls, context } = harness();
    const call = handler('eth_sendTransaction', [{}], context);
    await Promise.resolve();
    requests.current!.reject();
    await expect(call).rejects.toMatchObject({ code: RPC_ERRORS.USER_REJECTED });
    expect(calls.map((entry) => entry.method)).not.toContain('eth_sendTransaction');
  });

  it('silently restores a lost account before asking consent, with no extra prompt (WK-12)', async () => {
    const { handler, requests, calls, context } = harness(31337, { account: false });
    const call = handler('personal_sign', ['0x68690a', '0xabc'], context);
    // wait for the async restore to run before consent appears
    await vi.waitFor(() => expect(requests.current).not.toBeNull());
    expect(calls[0]).toMatchObject({ method: 'giano_restoreAccount' });
    requests.current!.approve();
    await expect(call).resolves.toBe('result:personal_sign');
  });

  describe('giano_openWalletManagement (WM-54, WM-55)', () => {
    it('refuses parameters from the application (WM-39)', async () => {
      const { handler, context } = harness();
      await expect(handler('giano_openWalletManagement', [{ preselect: 'x' }], context)).rejects.toMatchObject({
        code: RPC_ERRORS.UNSUPPORTED_METHOD,
      });
    });

    it('surfaces a manage request and returns nothing to the dApp (WM-40)', async () => {
      const { handler, requests, context } = harness();
      const call = handler('giano_openWalletManagement', [], context);
      await vi.waitFor(() => expect(requests.current).not.toBeNull());
      expect(requests.current).toMatchObject({ kind: 'manage', params: undefined });
      requests.current!.approve(); // the user closed the management view
      await expect(call).resolves.toBeNull();
    });
  });
});
