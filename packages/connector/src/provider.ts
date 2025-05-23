import { credentialKeyMapperAbi } from '@appliedblockchain/giano-contracts';
import type { Hex, PublicClient } from 'viem';
import type { Call } from 'viem';
import {
  type Address,
  type Chain,
  concatHex,
  createPublicClient,
  type EIP1193Provider,
  encodeFunctionData,
  type Hash,
  keccak256,
  parseGwei,
  toHex,
  type Transport,
} from 'viem';
import type { BundlerClient, SmartAccount, WebAuthnAccount } from 'viem/account-abstraction';
import { createWebAuthnCredential, toWebAuthnAccount } from 'viem/account-abstraction';
import type { EIP1193Parameters } from 'viem/types/eip1193';
import type { GianoSmartAccountImplementation } from './account';
import { toGianoSmartAccount } from './account';

type PublicKeyAssertion = PublicKeyCredential & { response: AuthenticatorAssertionResponse };

const credentialMapperContract = {
  abi: credentialKeyMapperAbi,
  address: '0x2BF3Ec07f07C52df9DE3Ac40e142d64F95762ECB' as const,
};

const generateRandomChallenge = () => {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  return challenge;
};

function extractXYCoords(key: Uint8Array | Hex): { x: Hex; y: Hex } {
  if (key instanceof Uint8Array) {
    key = toHex(key.slice(-64), { size: 64 });
  }
  return { x: `0x${key.slice(-128, -64)}`, y: `0x${key.slice(-64)}` };
}

export type CreateGianoProviderParams = {
  initialChainId: number;
  bundler: BundlerClient;
  paymaster?: Address;
  chains: readonly Chain[];
  transports: Record<number, Transport> | undefined;
};

export const createGianoProvider = ({ transports, chains, initialChainId, paymaster, bundler }: CreateGianoProviderParams) => {
  let smartAccount: SmartAccount<GianoSmartAccountImplementation> | null;
  let account: string | null = null;
  let chain: Chain | undefined;
  let transport: Transport | undefined;
  let client: PublicClient | undefined;

  const getPublicKeyByCredentialId = async (id: Hash) =>
    client!.readContract({
      ...credentialMapperContract,
      functionName: 'getCredentialKey',
      args: [id],
    });

  const getWebAuthnAccount = async ({
    id,
    challenge,
  }: {
    id?: BufferSource;
    challenge?: BufferSource;
  } = {}): Promise<WebAuthnAccount | null> => {
    if (!challenge) {
      challenge = generateRandomChallenge();
    }

    try {
      const rawCredential = (await navigator.credentials.get({
        publicKey: {
          ...(id && { allowCredentials: [{ id, type: 'public-key' }] }),
          challenge,
        },
      })) as PublicKeyAssertion | null;
      if (!rawCredential) {
        return null;
      }
      const idHash = keccak256(new Uint8Array(rawCredential.rawId));
      const { x, y } = await getPublicKeyByCredentialId(idHash);
      console.log({ x, y });
      if (x === toHex(0, { size: 32 })) {
        throw new Error('Unknown credential ID');
      }
      return toWebAuthnAccount({
        credential: {
          id: rawCredential.id,
          publicKey: concatHex([x, y]),
        },
      });
    } catch (error) {
      if (['NotAllowedError', 'AbortError'].includes((error as Error).name)) {
        return null;
      }
      throw error;
    }
  };

  const methods: Record<string, (params?: any) => any> = {
    eth_accounts: async () => {
      return account ? ([account] as `0x${string}`[]) : [];
    },
    eth_chainId: async () => {
      console.log({ chain });
      return `0x${chain!.id.toString(16)}`;
    },
    wallet_addEthereumChain: () => {
      //TODO: implement
    },
    wallet_revokePermissions: () => {
      account = null;
    },
    wallet_switchEthereumChain: (params) => {
      const [{ chainId: chainIdHex }] = params;
      const chainId = parseInt(chainIdHex, 16);
      if (chainId === chain?.id) {
        return;
      }
      const newChain = chains.find((chain) => chain.id === chainId);
      if (!newChain) {
        throw new Error(`Unknown chain: ${chainId}`);
      }
      const newTransport = transports?.[newChain.id];
      if (!newTransport) {
        throw new Error('No transport for chain');
      }
      account = null;
      chain = newChain;
      transport = newTransport;
      client = createPublicClient({ transport, chain });
    },
    eth_requestAccounts: async () => {
      if (account) {
        return { accounts: [account], chainId: `0x${chain!.id.toString(16)}` };
      }
      let webAuthnAccount: WebAuthnAccount | null = await getWebAuthnAccount();
      if (!webAuthnAccount) {
        const credential = await createWebAuthnCredential({ name: 'Giano' });
        webAuthnAccount = toWebAuthnAccount({ credential });
        smartAccount = await toGianoSmartAccount({ client: client!, owners: [webAuthnAccount] });
        const idHash = keccak256(toHex(new Uint8Array(credential.raw.rawId)));
        const { x, y } = extractXYCoords(credential.publicKey);
        await methods.eth_sendTransaction([
          {
            to: credentialMapperContract.address,
            data: encodeFunctionData({ abi: credentialMapperContract.abi, functionName: 'setCredentialKey', args: [idHash, { x, y }] }),
          },
        ]);
      } else {
        smartAccount = await toGianoSmartAccount({ client: client!, owners: [webAuthnAccount] });
      }
      return [await smartAccount.getAddress()] as `0x${string}`[];
    },
    eth_sendTransaction: async (calls: Call[]) => {
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }
      const op = {
        ...(paymaster && {
          paymaster,
          paymasterPostOpGasLimit: 100_000n, // can this be calculated somehow?
          paymasterVerificationGasLimit: 100_000n,
        }),
        calls,
      };
      const estimate = await bundler.estimateUserOperationGas({ account: smartAccount, ...op });
      if (!estimate) {
        throw new Error('Could not estimate user operation');
      }
      const prepared = await bundler.prepareUserOperation({
        account: smartAccount,
        ...op,
        ...estimate,
      });
      const finalOp = {
        ...prepared,
        preVerificationGas: prepared.preVerificationGas + 1000n, // safety margin
        //TODO: implement callback to fetch these prices
        maxFeePerGas: parseGwei('200'),
        maxPriorityFeePerGas: parseGwei('400'),
      };
      const signature = await smartAccount.signUserOperation(finalOp);
      const hash = await bundler.sendUserOperation({
        ...finalOp,
        signature,
      });

      const { receipt: txReceipt } = await bundler.waitForUserOperationReceipt({ hash });
      return txReceipt;
    },
  };

  methods.wallet_switchEthereumChain([{ chainId: initialChainId.toString(16) }]);

  const provider: EIP1193Provider = {
    request: async (args: EIP1193Parameters) => {
      const { method, params } = args;
      console.log('provide.request ->', { method, params });
      if (!(method in methods)) {
        return client!.request({ ...args } as any);
      }
      const response = await methods[method](params);
      console.log({ response });
      return response;
    },
    on: (event, listener) => {
      console.log('(STUB) on event', event);
      return provider;
    },
    removeListener: (event, listener) => {
      console.log('(STUB) remove listener', event);
      return provider;
    },
  };

  return provider;
};
