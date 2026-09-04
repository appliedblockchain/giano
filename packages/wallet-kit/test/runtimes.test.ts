import { defineChain } from 'viem';
import { describe, expect, it } from 'vitest';
import type { WalletChainConfig, WalletConfig } from '../src/config';
import { bundlerOptions, createWalletRuntimes } from '../src/runtimes';

const chain = (chainId: number): WalletChainConfig => ({
  chainId,
  name: `Chain ${chainId}`,
  rpcUrl: `http://rpc-${chainId}.local`,
  bundlerUrl: `http://bundler-${chainId}.local`,
  factoryAddress: '0x1111111111111111111111111111111111111111',
  sponsorship: 'off',
  paymasterServiceUrl: '/api/v1/paymaster',
});

const config: WalletConfig = {
  chains: [chain(31337), chain(31338)],
  walletApiUrl: '/api',
  allowedDappOrigins: ['https://app.test'],
  rpId: 'wallet.test',
  branding: { name: 'Test Wallet' },
};

describe('createWalletRuntimes (WK-01…WK-03)', () => {
  it('resolves runtimes lazily and memoises per chain (WK-02, MC-44)', () => {
    const runtimes = createWalletRuntimes(config);
    const first = runtimes.runtimeFor(31337);
    expect(runtimes.runtimeFor(31337)).toBe(first);
    expect(runtimes.servedChainIds).toEqual([31337, 31338]);
  });

  it('shares ONE wallet-api injection across all runtimes (WK-03, MC-76)', () => {
    const runtimes = createWalletRuntimes(config);
    const a = runtimes.runtimeFor(31337);
    const b = runtimes.runtimeFor(31338);
    expect(a).not.toBe(b);
    expect(a.injection).toBe(b.injection);
    expect(a.externalUserId).toBe(b.externalUserId);
  });

  it('refuses a chain outside the served list', () => {
    const runtimes = createWalletRuntimes(config);
    expect(() => runtimes.runtimeFor(1)).toThrow(/does not serve chain 1/);
    expect(() => runtimes.descriptorFor(1)).toThrow(/does not serve chain 1/);
  });

  it('fails fatally on an empty chain list', () => {
    expect(() => createWalletRuntimes({ ...config, chains: [] })).toThrow(/at least one chain/);
  });

  it('answers not-applicable to the pre-flight when sponsorship is off (R-09)', async () => {
    const runtimes = createWalletRuntimes(config);
    await expect(runtimes.runtimeFor(31337).checkSponsorship({})).resolves.toEqual({ state: 'not-applicable' });
  });
});

describe('fee-before-paymaster is held by construction (WK-04, WK-27)', () => {
  const viemChain = defineChain({
    id: 31337,
    name: 'Devnet',
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: ['http://rpc.local'] } },
  });
  const estimate = async () => ({ maxFeePerGas: 2n, maxPriorityFeePerGas: 1n });
  const stubClient = { getPaymasterData: async () => ({}), getPaymasterStubData: async () => ({}) } as never;

  it('always wires the fee estimator into userOperation, in every sponsorship mode', async () => {
    for (const descriptor of [
      chain(31337),
      { ...chain(31337), sponsorship: 'service' as const },
      { ...chain(31337), sponsorship: 'test-paymaster' as const, testPaymasterAddress: '0x2222222222222222222222222222222222222222' as const },
    ]) {
      const options = bundlerOptions(descriptor, viemChain, estimate, descriptor.sponsorship === 'service' ? stubClient : undefined);
      // viem populates fees during prepareUserOperation via this hook — BEFORE the
      // paymaster hooks run. There is no construction path without it.
      await expect(options.userOperation.estimateFeesPerGas()).resolves.toEqual({ maxFeePerGas: 2n, maxPriorityFeePerGas: 1n });
    }
  });

  it('attaches paymaster hooks only alongside the fee hook', () => {
    const sponsored = bundlerOptions({ ...chain(31337), sponsorship: 'service' }, viemChain, estimate, stubClient);
    expect('paymaster' in sponsored && sponsored.paymaster).toBeTruthy();
    expect(sponsored.userOperation.estimateFeesPerGas).toBeTypeOf('function');

    const off = bundlerOptions(chain(31337), viemChain, estimate, undefined);
    expect('paymaster' in off).toBe(false);
  });

  it('refuses test-paymaster mode without an address', () => {
    expect(() => bundlerOptions({ ...chain(31337), sponsorship: 'test-paymaster' }, viemChain, estimate, undefined)).toThrow(
      /no testPaymasterAddress/,
    );
  });
});
