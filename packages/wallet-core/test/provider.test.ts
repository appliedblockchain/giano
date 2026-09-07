import { parseGwei, toHex } from 'viem';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ChainType,
  createGianoProvider,
  isChainType,
  resolveUserOpFees,
  type CreateGianoProviderParams,
  type GianoProvider,
} from '../src/provider';
import {
  FACTORY_ADDRESS,
  TEST_CHAIN_ID,
  WALLET_ADDRESS,
  createMockBundler,
  createMockInjection,
  createMockTransport,
  testChain,
  type MockClientOptions,
} from './helpers';
import { MockAuthenticator, installWebAuthnMock, type InstalledWebAuthnMock } from './webauthn-mock';

let mock: InstalledWebAuthnMock;
beforeEach(() => (mock = installWebAuthnMock()));
afterEach(() => mock.uninstall());

type BuildOptions = {
  transportOptions?: MockClientOptions;
  injection?: CreateGianoProviderParams['injection'];
  bundler?: CreateGianoProviderParams['bundler'];
  overrides?: Partial<CreateGianoProviderParams>;
};

const silentLogger = { debug: () => {}, warn: () => {}, error: () => {} };

function buildProvider(authenticator: MockAuthenticator, opts: BuildOptions = {}) {
  const { transport } = createMockTransport({ code: '0xabcd', ...opts.transportOptions });
  const { bundler, sentUserOps } = createMockBundler();
  const provider = createGianoProvider({
    initialChainId: TEST_CHAIN_ID,
    bundler: opts.bundler ?? bundler,
    chains: [testChain],
    transports: { [TEST_CHAIN_ID]: transport },
    injection: opts.injection ?? createMockInjection(authenticator),
    gianoSmartWalletFactoryAddress: FACTORY_ADDRESS,
    logger: silentLogger,
    ...opts.overrides,
  }).gianoProvider;
  return { provider, sentUserOps };
}

/** Registers a fresh passkey (create path) and connects. */
async function connect(provider: GianoProvider): Promise<string> {
  const [address] = await provider.request({ method: 'eth_requestAccounts' });
  return address;
}

describe('pure helpers', () => {
  it('resolveUserOpFees follows request > prepared > fallback precedence', () => {
    const fallback = { maxFeePerGas: 9n, maxPriorityFeePerGas: 8n };
    expect(resolveUserOpFees({ maxFeePerGas: 1n, maxPriorityFeePerGas: 2n }, {}, fallback)).toEqual({ maxFeePerGas: 1n, maxPriorityFeePerGas: 2n });
    expect(resolveUserOpFees({}, { maxFeePerGas: 3n, maxPriorityFeePerGas: 4n }, fallback)).toEqual({ maxFeePerGas: 3n, maxPriorityFeePerGas: 4n });
    expect(resolveUserOpFees({}, {}, fallback)).toEqual(fallback);
  });

  it('isChainType / ChainType', () => {
    expect(isChainType(0)).toBe(true);
    expect(isChainType(ChainType.EVM)).toBe(true);
    expect(isChainType(99)).toBe(false);
    expect(isChainType('0')).toBe(false);
    expect(ChainType.HARDHAT).toBe(ChainType.EVM);
  });
});

describe('connection', () => {
  it('registers a passkey and reports the smart-account address (create path)', async () => {
    const { provider } = buildProvider(mock.authenticator);
    const events: Record<string, unknown[]> = { connect: [], accountsChanged: [] };
    provider.on('connect', (p) => events.connect.push(p));
    provider.on('accountsChanged', (p) => events.accountsChanged.push(p));

    const address = await connect(provider);
    expect(address.toLowerCase()).toBe(WALLET_ADDRESS.toLowerCase());
    expect(events.connect).toHaveLength(1);
    expect(events.accountsChanged[0]).toEqual([address]);
    expect(provider.getSmartAccount()).not.toBeNull();
  });

  it('honours an address returned by onCredentialCreated (handler-managed deployment)', async () => {
    const handlerAddress = '0x000000000000000000000000000000000000cafe' as `0x${string}`;
    const injection = createMockInjection(mock.authenticator, { onCredentialCreated: async () => handlerAddress });
    const { provider } = buildProvider(mock.authenticator, { injection });
    const [address] = await provider.request({ method: 'eth_requestAccounts' });
    expect(address).toBe(handlerAddress);
  });

  it('signs in with an existing resident credential (sign-in path)', async () => {
    // Pre-register a passkey so a resident credential exists to select.
    const created = await mock.authenticator.create({
      publicKey: { rp: { id: 'localhost', name: 'g' }, user: { id: new Uint8Array([1]), name: 'a', displayName: 'a' }, challenge: new Uint8Array([1]), pubKeyCredParams: [{ type: 'public-key', alg: -7 }] },
    } as CredentialCreationOptions);
    const injection = createMockInjection(mock.authenticator, { credentialId: new Uint8Array(created.rawId) });
    const { provider } = buildProvider(mock.authenticator, { injection });

    const [address] = await provider.request({ method: 'eth_requestAccounts' });
    expect(address.toLowerCase()).toBe(WALLET_ADDRESS.toLowerCase());
  });

  it('returns the cached account on a second eth_requestAccounts and via eth_accounts', async () => {
    const { provider } = buildProvider(mock.authenticator);
    expect(await provider.request({ method: 'eth_accounts' })).toEqual([]);
    const address = await connect(provider);
    expect(await provider.request({ method: 'eth_requestAccounts' })).toEqual([address]);
    expect(await provider.request({ method: 'eth_accounts' })).toEqual([address]);
  });

  it('deploys a counterfactual account when not yet on-chain', async () => {
    // getCode: undeployed on the ensure-check, deployed thereafter.
    const injection = createMockInjection(mock.authenticator);
    const { provider, sentUserOps } = buildProvider(mock.authenticator, {
      injection,
      transportOptions: { code: (i) => (i === 0 ? '0x' : '0xabcd') },
    });
    await connect(provider);
    expect(sentUserOps.length).toBe(1); // deployment user op was sent
  });
});

describe('silent account restore (giano_restoreAccount)', () => {
  /** Pre-registers a resident passkey and returns its rawId for a sign-in/restore injection. */
  async function registerCredential(): Promise<Uint8Array> {
    const created = await mock.authenticator.create({
      publicKey: { rp: { id: 'localhost', name: 'g' }, user: { id: new Uint8Array([1]), name: 'a', displayName: 'a' }, challenge: new Uint8Array([1]), pubKeyCredParams: [{ type: 'public-key', alg: -7 }] },
    } as CredentialCreationOptions);
    return new Uint8Array(created.rawId);
  }

  it('rebuilds the account from a stored credential without a passkey ceremony', async () => {
    const credentialId = await registerCredential();
    const onCredentialSignedIn = vi.fn(async () => true);
    const injection = createMockInjection(mock.authenticator, { credentialId, onCredentialSignedIn });
    const { provider } = buildProvider(mock.authenticator, { injection });

    const accountsChanged: unknown[] = [];
    provider.on('accountsChanged', (p) => accountsChanged.push(p));

    const [address] = await provider.request({ method: 'giano_restoreAccount' });
    expect(address.toLowerCase()).toBe(WALLET_ADDRESS.toLowerCase());
    // No sign-in ceremony was run — the account came from the stored public key only.
    expect(onCredentialSignedIn).not.toHaveBeenCalled();
    expect(provider.getSmartAccount()).not.toBeNull();
    expect(accountsChanged).toEqual([[address]]);
  });

  it('lets a restored account send a transaction (no "not connected")', async () => {
    const credentialId = await registerCredential();
    const injection = createMockInjection(mock.authenticator, { credentialId });
    const { provider, sentUserOps } = buildProvider(mock.authenticator, { injection });

    await provider.request({ method: 'giano_restoreAccount' });
    const hash = await provider.request({ method: 'eth_sendTransaction', params: [{ to: WALLET_ADDRESS, value: '0x0', data: '0x' }] as never });
    expect(hash).toMatch(/^0x/);
    expect(sentUserOps.length).toBeGreaterThan(0);
  });

  it('returns [] when no credential is registered for the user', async () => {
    const { provider } = buildProvider(mock.authenticator); // default injection: credentialId = null
    expect(await provider.request({ method: 'giano_restoreAccount' })).toEqual([]);
    expect(provider.getSmartAccount()).toBeNull();
  });

  it('returns [] and stays disconnected when the persisted session is invalid', async () => {
    const credentialId = await registerCredential();
    const injection = createMockInjection(mock.authenticator, {
      credentialId,
      getPublicKeyByCredentialId: async () => {
        throw new Error('wallet-api /public-key failed: 401');
      },
    });
    const { provider } = buildProvider(mock.authenticator, { injection });

    expect(await provider.request({ method: 'giano_restoreAccount' })).toEqual([]);
    expect(provider.getSmartAccount()).toBeNull();
  });

  it('is idempotent — returns the cached address once connected', async () => {
    const { provider } = buildProvider(mock.authenticator);
    const address = await connect(provider);
    expect(await provider.request({ method: 'giano_restoreAccount' })).toEqual([address]);
  });
});

describe('chain management', () => {
  it('eth_chainId reflects the active chain', async () => {
    const { provider } = buildProvider(mock.authenticator);
    expect(await provider.request({ method: 'eth_chainId' })).toBe(`0x${TEST_CHAIN_ID.toString(16)}`);
  });

  it('wallet_switchEthereumChain: no-op on same chain, errors on unknown or transport-less chains', async () => {
    const { provider } = buildProvider(mock.authenticator);
    expect(await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: `0x${TEST_CHAIN_ID.toString(16)}` }] })).toBeNull();
    await expect(provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0x270f' }] })).rejects.toThrow(/Unknown chain/);
  });

  it('wallet_switchEthereumChain errors when the target chain has no transport', async () => {
    const { transport } = createMockTransport({ code: '0xabcd' });
    const otherChain = { ...testChain, id: 999 };
    const { bundler } = createMockBundler();
    const provider = createGianoProvider({
      initialChainId: TEST_CHAIN_ID,
      bundler,
      chains: [testChain, otherChain],
      transports: { [TEST_CHAIN_ID]: transport }, // no transport for 999
      injection: createMockInjection(mock.authenticator),
      gianoSmartWalletFactoryAddress: FACTORY_ADDRESS,
    }).gianoProvider;
    await expect(provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0x3e7' }] })).rejects.toThrow(/No transport/);
  });

  it('wallet_addEthereumChain is a no-op and wallet_revokePermissions disconnects', async () => {
    const { provider } = buildProvider(mock.authenticator);
    await connect(provider);
    expect(await provider.request({ method: 'wallet_addEthereumChain', params: [{ chainId: '0x1' } as never] })).toBeNull();

    const disconnects: unknown[] = [];
    provider.on('disconnect', (p) => disconnects.push(p));
    expect(await provider.request({ method: 'wallet_revokePermissions', params: [{}] as never })).toBeNull();
    expect(provider.getSmartAccount()).toBeNull();
    expect(disconnects).toHaveLength(1);
  });
});

describe('transactions & user operations', () => {
  it('eth_sendTransaction relays a user op through the bundler', async () => {
    const { provider, sentUserOps } = buildProvider(mock.authenticator);
    await connect(provider);
    const hash = await provider.request({ method: 'eth_sendTransaction', params: [{ to: '0x1111111111111111111111111111111111111111', value: '0x1', data: '0x' }] as never });
    expect(hash).toMatch(/^0x/);
    expect(sentUserOps.length).toBeGreaterThan(0);
  });

  it('eth_sendTransaction requires a connection and a `to`', async () => {
    const { provider } = buildProvider(mock.authenticator);
    await expect(provider.request({ method: 'eth_sendTransaction', params: [{ to: '0x1111111111111111111111111111111111111111' }] as never })).rejects.toThrow(/not connected/);
    await connect(provider);
    await expect(provider.request({ method: 'eth_sendTransaction', params: [{} as never] })).rejects.toThrow(/`to` field is required/);
  });

  it('routes through injection.submitUserOperation when provided', async () => {
    const submitUserOperation = vi.fn(async () => `0x${'ab'.repeat(32)}` as `0x${string}`);
    const injection = createMockInjection(mock.authenticator, { submitUserOperation });
    const { provider } = buildProvider(mock.authenticator, { injection });
    await connect(provider);
    const hash = await provider.request({ method: 'eth_sendTransaction', params: [{ to: '0x1111111111111111111111111111111111111111', value: '0x0', data: '0x' }] as never });
    expect(submitUserOperation).toHaveBeenCalledOnce();
    expect(hash).toBe(`0x${'ab'.repeat(32)}`);
  });

  it('eth_prepareUserOperation returns a prepared op with resolved fees', async () => {
    const { provider } = buildProvider(mock.authenticator);
    await connect(provider);
    const op = await provider.request({ method: 'eth_prepareUserOperation', params: [[{ to: '0x1111111111111111111111111111111111111111', value: 0n, data: '0x' }]] as never });
    expect(op).toMatchObject({ sender: expect.any(String) });
  });

  it('eth_signUserOperation and eth_sendSignedUserOperation', async () => {
    const { provider } = buildProvider(mock.authenticator);
    await connect(provider);
    const prepared = await provider.request({ method: 'eth_prepareUserOperation', params: [[{ to: '0x1111111111111111111111111111111111111111', value: 0n, data: '0x' }]] as never });
    const signature = await provider.request({ method: 'eth_signUserOperation', params: [prepared] as never });
    expect(signature).toMatch(/^0x/);
    const hash = await provider.request({ method: 'eth_sendSignedUserOperation', params: [prepared] as never });
    expect(hash).toMatch(/^0x/);
  });

  it('waitForUserOperationReceipt delegates to the bundler', async () => {
    const { provider } = buildProvider(mock.authenticator);
    const receipt = await provider.request({ method: 'waitForUserOperationReceipt', params: [`0x${'11'.repeat(32)}`] as never });
    expect(receipt).toMatchObject({ success: true });
  });

  it('the userop methods require a connection', async () => {
    const { provider } = buildProvider(mock.authenticator);
    await expect(provider.request({ method: 'eth_signUserOperation', params: [{}] as never })).rejects.toThrow(/not connected/);
    await expect(provider.request({ method: 'eth_prepareUserOperation', params: [[]] as never })).rejects.toThrow(/not connected/);
    await expect(provider.request({ method: 'eth_sendSignedUserOperation', params: [{}] as never })).rejects.toThrow(/not connected/);
  });
});

describe('message signing', () => {
  it('personal_sign signs plain and hex messages for the connected account', async () => {
    const { provider } = buildProvider(mock.authenticator);
    const address = await connect(provider);
    expect(await provider.request({ method: 'personal_sign', params: ['hello', address] as never })).toMatch(/^0x/);
    expect(await provider.request({ method: 'personal_sign', params: [toHex('hi'), address] as never })).toMatch(/^0x/);
  });

  it('personal_sign rejects when disconnected or on address mismatch', async () => {
    const { provider } = buildProvider(mock.authenticator);
    await expect(provider.request({ method: 'personal_sign', params: ['hi', WALLET_ADDRESS] as never })).rejects.toThrow(/not connected/);
    await connect(provider);
    await expect(provider.request({ method: 'personal_sign', params: ['hi', '0x00000000000000000000000000000000deadbeef'] as never })).rejects.toThrow(/Address mismatch/);
  });

  it('eth_sign signs with reversed [address, message] argument order', async () => {
    const { provider } = buildProvider(mock.authenticator);
    const address = await connect(provider);
    expect(await provider.request({ method: 'eth_sign', params: [address, `0x${'ab'.repeat(32)}`] as never })).toMatch(/^0x/);
    await expect(provider.request({ method: 'eth_sign', params: ['0x00000000000000000000000000000000deadbeef', '0x00'] as never })).rejects.toThrow(/Address mismatch/);
  });

  it('eth_signTypedData_v4 accepts a JSON string or an object', async () => {
    const { provider } = buildProvider(mock.authenticator);
    const address = await connect(provider);
    const typedData = {
      domain: { name: 'X', version: '1', chainId: TEST_CHAIN_ID, verifyingContract: WALLET_ADDRESS },
      types: { Msg: [{ name: 'v', type: 'string' }] },
      primaryType: 'Msg',
      message: { v: 'hi' },
    };
    expect(await provider.request({ method: 'eth_signTypedData_v4', params: [address, JSON.stringify(typedData)] as never })).toMatch(/^0x/);
    expect(await provider.request({ method: 'eth_signTypedData_v4', params: [address, typedData] as never })).toMatch(/^0x/);
  });
});

describe('reads: eth_call & signed_eth_call', () => {
  it('eth_call delegates to the public client', async () => {
    const { provider } = buildProvider(mock.authenticator);
    expect(await provider.request({ method: 'eth_call', params: [{ to: WALLET_ADDRESS, data: '0x12345678' }] as never })).toBe('0x');
  });

  it('signed_eth_call falls back to a plain call when disconnected', async () => {
    const { provider } = buildProvider(mock.authenticator);
    expect(await provider.request({ method: 'signed_eth_call', params: [{ to: WALLET_ADDRESS, data: '0x12345678' }] as never })).toBe('0x');
  });

  it('signed_eth_call falls back to a plain call when the account is not deployed', async () => {
    const { provider } = buildProvider(mock.authenticator, { transportOptions: { code: (i) => (i < 2 ? '0xabcd' : '0x') } });
    await connect(provider); // uses deployed code for the connect checks
    // subsequent getCode returns '0x' → treated as undeployed → fallback
    expect(await provider.request({ method: 'signed_eth_call', params: [{ to: WALLET_ADDRESS, data: '0x12345678' }] as never })).toBe('0x');
  });

  it('signed_eth_call performs an authenticated static call when deployed', async () => {
    const { provider } = buildProvider(mock.authenticator, { transportOptions: { code: '0xabcd', staticCallResult: '0xc0ffee' } });
    await connect(provider);
    const result = await provider.request({ method: 'signed_eth_call', params: [{ to: '0x1111111111111111111111111111111111111111', data: '0xabcd' }] as never });
    expect(result).toBe('0xc0ffee');
  });

  it('signed_eth_call requires to and data', async () => {
    const { provider } = buildProvider(mock.authenticator, { transportOptions: { code: '0xabcd' } });
    await connect(provider);
    await expect(provider.request({ method: 'signed_eth_call', params: [{ data: '0xabcd' } as never] })).rejects.toThrow(/`transaction.to` is required/);
    await expect(provider.request({ method: 'signed_eth_call', params: [{ to: WALLET_ADDRESS } as never] })).rejects.toThrow(/`transaction.data` is required/);
  });
});

describe('request routing & events', () => {
  it('delegates unknown methods to the public client', async () => {
    const onRequest = vi.fn();
    const { provider } = buildProvider(mock.authenticator, { transportOptions: { onRequest } });
    await provider.request({ method: 'eth_chainId' as never }); // handled locally
    await provider.request({ method: 'eth_getCode', params: [WALLET_ADDRESS, 'latest'] } as never); // pass-through
    expect(onRequest).toHaveBeenCalledWith('eth_getCode', expect.anything());
  });

  it('logs and rethrows handler errors via the injected logger', async () => {
    const logger = { debug: vi.fn(), warn: vi.fn(), error: vi.fn() };
    const { provider } = buildProvider(mock.authenticator, { overrides: { logger } });
    await expect(provider.request({ method: 'eth_sendTransaction', params: [{ to: '0x1111111111111111111111111111111111111111' }] as never })).rejects.toThrow();
    expect(logger.error).toHaveBeenCalled();
  });

  it('removeListener detaches a handler', async () => {
    const { provider } = buildProvider(mock.authenticator);
    const handler = vi.fn();
    provider.on('connect', handler);
    provider.removeListener('connect', handler);
    await connect(provider);
    expect(handler).not.toHaveBeenCalled();
  });

  it('uses a custom estimateFeesPerGas fallback', async () => {
    const estimateFeesPerGas = vi.fn(async () => ({ maxFeePerGas: parseGwei('5'), maxPriorityFeePerGas: parseGwei('1') }));
    const { provider } = buildProvider(mock.authenticator, { overrides: { estimateFeesPerGas } });
    await connect(provider);
    await provider.request({ method: 'eth_prepareUserOperation', params: [[{ to: '0x1111111111111111111111111111111111111111', value: 0n, data: '0x' }]] as never });
    expect(estimateFeesPerGas).toHaveBeenCalled();
  });
});
