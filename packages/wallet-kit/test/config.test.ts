import { describe, expect, it } from 'vitest';
import { resolveWalletConfig, type RawWalletConfig } from '../src/config';

const chainEntry = {
  chainId: 31337,
  name: 'Devnet',
  rpcUrl: 'http://rpc.local',
  bundlerUrl: 'http://bundler.local',
  factoryAddress: '0x1111111111111111111111111111111111111111' as const,
  sponsorship: 'service' as const,
};

describe('resolveWalletConfig (WK-06)', () => {
  it('accepts the multi-chain list', () => {
    const config = resolveWalletConfig({ raw: { chains: [chainEntry], walletApiUrl: '/api', rpId: 'wallet.test' } });
    expect(config.chains).toHaveLength(1);
    expect(config.chains[0]).toMatchObject({ chainId: 31337, sponsorship: 'service', paymasterServiceUrl: '/api/v1/paymaster' });
  });

  it('accepts the single-chain top-level shorthand', () => {
    const config = resolveWalletConfig({ raw: { ...chainEntry, rpId: 'wallet.test' } });
    expect(config.chains).toHaveLength(1);
    expect(config.chains[0].chainId).toBe(31337);
  });

  it('rejects supplying both the list and the shorthand', () => {
    expect(() => resolveWalletConfig({ raw: { ...chainEntry, chains: [chainEntry] } })).toThrow(/mutually exclusive/);
  });

  it('fails fatally on a chain entry with no chainId (MC-42)', () => {
    const raw: RawWalletConfig = { chains: [{ rpcUrl: 'http://rpc' }] };
    expect(() => resolveWalletConfig({ raw })).toThrow(/must set chainId/);
  });

  it('defaults rpcUrl and bundlerUrl to the wallet-api relays for that chain — a chain needs only its id', () => {
    const config = resolveWalletConfig({
      raw: {
        chains: [{ chainId: 31337, factoryAddress: chainEntry.factoryAddress }, { ...chainEntry, chainId: 84532, rpcUrl: '', bundlerUrl: '' }],
        walletApiUrl: 'https://api.test',
      },
    });
    expect(config.chains.map((chain) => [chain.rpcUrl, chain.bundlerUrl])).toEqual([
      ['https://api.test/v1/rpc/31337', 'https://api.test/v1/bundler/31337'],
      ['https://api.test/v1/rpc/84532', 'https://api.test/v1/bundler/84532'],
    ]);
    // and the same-origin default when no walletApiUrl is given
    const sameOrigin = resolveWalletConfig({ raw: { chains: [{ chainId: 31337, factoryAddress: chainEntry.factoryAddress }] } }).chains[0];
    expect([sameOrigin.rpcUrl, sameOrigin.bundlerUrl]).toEqual(['/api/v1/rpc/31337', '/api/v1/bundler/31337']);
  });

  it('keeps explicit rpcUrl/bundlerUrl — dialling a node or bundler directly is a choice, not the default', () => {
    const chain = resolveWalletConfig({ raw: { chains: [chainEntry] } }).chains[0];
    expect([chain.rpcUrl, chain.bundlerUrl]).toEqual(['http://rpc.local', 'http://bundler.local']);
  });

  it('fails on a duplicate chainId', () => {
    expect(() => resolveWalletConfig({ raw: { chains: [chainEntry, { ...chainEntry }] } })).toThrow(/duplicate chainId 31337/);
  });

  it('fails when no factory is configured and the chain is not in the registry', () => {
    const raw: RawWalletConfig = { chains: [{ ...chainEntry, chainId: 999999, factoryAddress: undefined }] };
    expect(() => resolveWalletConfig({ raw })).toThrow(/factoryAddress required.*999999/);
  });

  it('fails on an empty chain list', () => {
    expect(() => resolveWalletConfig({ raw: { chains: [] } })).toThrow(/at least one chain/);
  });

  it('rejects an unknown sponsorship mode', () => {
    expect(() => resolveWalletConfig({ raw: { chains: [{ ...chainEntry, sponsorship: 'maybe' }] } })).toThrow(/sponsorship must be/);
  });

  it('defaults sponsorship from a configured test paymaster, falling back to the service', () => {
    const withTest = resolveWalletConfig({
      raw: { chains: [{ ...chainEntry, sponsorship: undefined, testPaymasterAddress: '0x2222222222222222222222222222222222222222' }] },
    });
    expect(withTest.chains[0].sponsorship).toBe('test-paymaster');
    const withoutTest = resolveWalletConfig({ raw: { chains: [{ ...chainEntry, sponsorship: undefined }] } });
    expect(withoutTest.chains[0].sponsorship).toBe('service');
  });

  describe('the permissive test paymaster is refused in production builds (WK-05, R-29)', () => {
    const testPaymasterRaw: RawWalletConfig = {
      chains: [{ ...chainEntry, sponsorship: 'test-paymaster', testPaymasterAddress: '0x2222222222222222222222222222222222222222' }],
    };

    it('refuses to load', () => {
      expect(() => resolveWalletConfig({ raw: testPaymasterRaw, production: true })).toThrow(/test paymaster.*production/);
    });

    it('loads with the explicit opt-in', () => {
      const config = resolveWalletConfig({ raw: { ...testPaymasterRaw, allowTestPaymaster: true }, production: true });
      expect(config.chains[0].sponsorship).toBe('test-paymaster');
    });

    it('loads in a non-production build', () => {
      expect(resolveWalletConfig({ raw: testPaymasterRaw }).chains[0].sponsorship).toBe('test-paymaster');
    });
  });

  it('refuses test-paymaster mode without a paymaster address', () => {
    expect(() => resolveWalletConfig({ raw: { chains: [{ ...chainEntry, sponsorship: 'test-paymaster' }] } })).toThrow(/no testPaymasterAddress/);
  });
});
