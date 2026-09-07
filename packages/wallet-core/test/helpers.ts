import { gianoSmartWalletAbi, gianoSmartWalletFactoryAbi } from '@appliedblockchain/giano-contracts';
import {
  type Address,
  type Chain,
  type Hex,
  createPublicClient,
  custom,
  encodeFunctionResult,
  getAbiItem,
  toFunctionSelector,
} from 'viem';
import { toWebAuthnAccount } from 'viem/account-abstraction';
import type { WebAuthnAccount } from 'viem/account-abstraction';
import { toGianoSmartAccount } from '../src/account';
import type { GianoProviderInjection } from '../src/provider-injection';
import { MockAuthenticator } from './webauthn-mock';

export const TEST_CHAIN_ID = 31337;
export const FACTORY_ADDRESS = '0x00000000000000000000000000000000f00d5678' as Address;
export const WALLET_ADDRESS = '0x000000000000000000000000000000000000abcd' as Address;

export const testChain: Chain = {
  id: TEST_CHAIN_ID,
  name: 'giano-test',
  nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
  rpcUrls: { default: { http: ['http://localhost:8545'] } },
};

const selectorOf = (abi: readonly unknown[], name: string): Hex =>
  toFunctionSelector(getAbiItem({ abi, name } as never) as never);

const FACTORY_GET_ADDRESS = selectorOf(gianoSmartWalletFactoryAbi, 'getAddress');
const WALLET_SIGNATURE_LIFETIME = selectorOf(gianoSmartWalletAbi, 'getSignatureLifetime');
const WALLET_SIGNED_STATIC_CALL = selectorOf(gianoSmartWalletAbi, 'signedStaticCall');

export type MockClientOptions = {
  /** Address the factory's `getAddress` returns (the counterfactual wallet address). */
  walletAddress?: Address;
  /**
   * Bytecode returned by `eth_getCode`. A function receives the 0-based call index so a
   * test can flip "not deployed" → "deployed" across polls.
   */
  code?: Hex | ((callIndex: number) => Hex);
  /** Value returned by `getSignatureLifetime` (seconds). */
  signatureLifetime?: bigint;
  /** Raw bytes returned by `signedStaticCall`. */
  staticCallResult?: Hex;
  /** Observe every JSON-RPC request the client makes. */
  onRequest?: (method: string, params: unknown) => void;
};

/**
 * A hand-rolled viem transport that answers the exact `eth_call`/`eth_getCode`
 * requests the Giano account + provider make, with correctly ABI-encoded
 * results, so no real chain is needed.
 */
export function createMockTransport(options: MockClientOptions = {}) {
  const {
    walletAddress = WALLET_ADDRESS,
    code = '0x',
    signatureLifetime = 3600n,
    staticCallResult = '0x',
    onRequest,
  } = options;

  let getCodeCalls = 0;

  const request = async ({ method, params }: { method: string; params: unknown }): Promise<unknown> => {
    onRequest?.(method, params);
    switch (method) {
      case 'eth_chainId':
        return `0x${TEST_CHAIN_ID.toString(16)}`;
      case 'eth_getCode': {
        const value = typeof code === 'function' ? code(getCodeCalls) : code;
        getCodeCalls += 1;
        return value;
      }
      case 'eth_call': {
        const data = (params as [{ data: Hex }])[0].data;
        const selector = data.slice(0, 10) as Hex;
        if (selector === FACTORY_GET_ADDRESS)
          return encodeFunctionResult({ abi: gianoSmartWalletFactoryAbi, functionName: 'getAddress', result: walletAddress });
        if (selector === WALLET_SIGNATURE_LIFETIME)
          return encodeFunctionResult({ abi: gianoSmartWalletAbi, functionName: 'getSignatureLifetime', result: signatureLifetime });
        if (selector === WALLET_SIGNED_STATIC_CALL)
          return encodeFunctionResult({ abi: gianoSmartWalletAbi, functionName: 'signedStaticCall', result: staticCallResult });
        return '0x';
      }
      default:
        throw new Error(`mock transport: unhandled method ${method}`);
    }
  };

  return { transport: custom({ request }, { retryCount: 0 }), getCodeCallCount: () => getCodeCalls };
}

/**
 * A viem PublicClient backed by {@link createMockTransport}.
 */
export function createMockClient(options: MockClientOptions = {}) {
  const { transport, getCodeCallCount } = createMockTransport(options);
  const client = createPublicClient({ chain: testChain, transport, pollingInterval: 5 });
  return { client, getCodeCallCount };
}

export type MockBundlerOptions = {
  userOpHash?: Hex;
  onSend?: (userOp: unknown) => void;
  receiptSuccess?: boolean;
};

/** A minimal ERC-4337 bundler client stub covering the calls the provider makes. */
export function createMockBundler(options: MockBundlerOptions = {}) {
  const { userOpHash = `0x${'11'.repeat(32)}` as Hex, onSend, receiptSuccess = true } = options;
  const gas = { callGasLimit: 100_000n, verificationGasLimit: 900_000n, preVerificationGas: 50_000n };
  const sent: unknown[] = [];

  const bundler = {
    async sendUserOperation(userOp: unknown) {
      sent.push(userOp);
      onSend?.(userOp);
      return userOpHash;
    },
    async estimateUserOperationGas() {
      return gas;
    },
    async prepareUserOperation(userOp: Record<string, unknown>) {
      return {
        sender: (userOp.sender as Address) ?? WALLET_ADDRESS,
        nonce: 0n,
        callData: (userOp.callData as Hex) ?? '0x',
        ...gas,
        maxFeePerGas: (userOp.maxFeePerGas as bigint) ?? 0n,
        maxPriorityFeePerGas: (userOp.maxPriorityFeePerGas as bigint) ?? 0n,
        signature: '0x' as Hex,
      };
    },
    async waitForUserOperationReceipt() {
      return { receipt: { transactionHash: `0x${'22'.repeat(32)}` }, success: receiptSuccess } as never;
    },
  };

  return { bundler: bundler as never, sentUserOps: sent };
}

/** Builds a WebAuthn owner (real-crypto keypair) via the mock authenticator, ready for toGianoSmartAccount. */
export async function createWebAuthnOwner(authenticator: MockAuthenticator): Promise<{ owner: WebAuthnAccount; rawId: ArrayBuffer }> {
  const created = await authenticator.create({
    publicKey: {
      rp: { id: 'localhost', name: 'giano' },
      user: { id: new Uint8Array([1, 2, 3, 4]), name: 'test', displayName: 'test' },
      challenge: new Uint8Array([1, 2, 3, 4]),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    },
  } as CredentialCreationOptions);
  const { x, y } = authenticator.getPublicKeyXY(created.rawId);
  const owner = toWebAuthnAccount({ credential: { id: created.id, publicKey: `0x${x.slice(2)}${y.slice(2)}` } });
  return { owner, rawId: created.rawId };
}

/** Builds a Giano smart account with a real-crypto WebAuthn owner against the mock client. */
export async function createTestGianoAccount(authenticator: MockAuthenticator, clientOptions: MockClientOptions = {}) {
  const { client } = createMockClient(clientOptions);
  const { owner } = await createWebAuthnOwner(authenticator);
  const account = await toGianoSmartAccount({ client, owners: [owner], factoryAddress: FACTORY_ADDRESS });
  return { account, client };
}

/**
 * A reference `GianoProviderInjection` backed by the WebAuthn mock authenticator:
 * public keys come from the real mock keypairs, so sign-in/registration are genuine.
 */
export function createMockInjection(
  authenticator: MockAuthenticator,
  overrides: Partial<GianoProviderInjection> & { credentialId?: BufferSource | null } = {},
): GianoProviderInjection {
  const challenge = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]);
  return {
    getNameForCredential: () => 'Test Passkey',
    getCredentialInfo: async () => ({
      credentialId: overrides.credentialId ?? null,
      challenge,
    }),
    onCredentialCreated: async () => null,
    encodeUserId: (id: string) => new TextEncoder().encode(id.padEnd(37, '0')),
    decodeUserId: () => ({ userId: 'x', walletFactoryAddress: FACTORY_ADDRESS, chainType: 0 }),
    onCredentialSignedIn: async () => true,
    getPublicKeyByCredentialId: async (rawId: ArrayBuffer) => authenticator.getPublicKeyXY(rawId),
    onCredentialKey: async () => {},
    ...overrides,
  };
}
