import {
  Call,
  Hex,
  PublicClient,
  Hash,
  createPublicClient,
  parseGwei,
  toHex,
  Address,
  Chain,
  concatHex,
  EIP1193Provider,
  Transport,
} from 'viem';
import type {
  BundlerClient,
  SendUserOperationParameters,
  SmartAccount,
  UserOperation,
  UserOperationReceipt,
  WebAuthnAccount,
} from 'viem/account-abstraction';
import { createWebAuthnCredential, toWebAuthnAccount } from 'viem/account-abstraction';
import type { EIP1193EventMap, EIP1193Parameters, EIP1193RequestFn } from 'viem/types/eip1193';
import type { GianoSmartAccountImplementation } from './account';
import { toGianoSmartAccount } from './account';
import { GianoEntryPointAddress, GianoEntryPointVersion } from './giano-entry-point'

export enum ChainType {
  HARDHAT = 0, // NOTE: This is just a placeholder for now
}

type PublicKeyAssertion = PublicKeyCredential & { response: AuthenticatorAssertionResponse };

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

export type GianoProviderInjection = {
  getNameForCredential(): string | Promise<string>;
  getCredentialInfo(): Promise<{
    credentialId?: BufferSource | null;
    challenge: BufferSource;
  }>;
  /**
   * @param credentialName - The name of the credential
   * @param challenge - The challenge used to create the credential
   * @param credential - The credential created
   * @returns Null or a wallet address. Returning a wallet address means
   *          that Giano does not proceed to create the smart wallet
   *          (the handler took care of that).
   */
  onCredentialCreated(
    credentialName: string,
    challenge: BufferSource,
    credential: Omit<PublicKeyCredential, 'toJSON'>,
  ): null | Promise<null> | Hex | Promise<Hex>;
  encodeUserId(id: string, gianoSmartWalletFactoryAddress: string, chainId: string, chainType: ChainType): Uint8Array;
  decodeUserId(userId: Uint8Array): {
    userId: string;
    walletFactoryAddress: string;
    chainId: number;
    chainType: ChainType;
  };
  onCredentialSignedIn(credential: PublicKeyCredential): Promise<boolean>; // method to control if the credential is signed in or not
  getPublicKeyByCredentialId(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex }>;
  onCredentialKey(rawId: ArrayBuffer, xyVector: { x: Hex; y: Hex }): Promise<void>;
  /**
   * Override for sending user operations manually.
   * When provided, this function will handle the submission of signed user operations
   * instead of sending them directly to the bundler.
   *
   * @param signedUserOp - The complete signed user operation ready for submission
   * @returns Promise that resolves to the user operation hash
   */
  submitUserOperation?: (signedUserOp: UserOperation<GianoEntryPointVersion>) => Promise<Hash>;
};

export type CreateGianoProviderParams = {
  initialChainId: number;
  bundler: BundlerClient;
  chains: readonly Chain[];
  transports: Record<number, Transport> | undefined;
  injection: GianoProviderInjection;
  gianoSmartWalletFactoryAddress: Address;
};

type EventHandler<E extends keyof EIP1193EventMap> = (payload: Parameters<EIP1193EventMap[E]>[0]) => void;
type EventListeners = {
  [E in keyof EIP1193EventMap]: Set<EventHandler<E>>;
};

type GianoProviderCustomMethods = [{
  Method: 'waitForUserOperationReceipt';
  Parameters: [hash: Hash];
  ReturnType: UserOperationReceipt;
}]

export type GianoProvider = EIP1193Provider & {
  request: EIP1193RequestFn<GianoProviderCustomMethods>
}

export const createGianoProvider = ({ transports, chains, initialChainId, bundler, injection, gianoSmartWalletFactoryAddress }: CreateGianoProviderParams) => {
  let smartAccount: SmartAccount<GianoSmartAccountImplementation> | null;
  let chain: Chain | undefined;
  let transport: Transport | undefined;
  let client: PublicClient | undefined;
  const eventListeners: Partial<EventListeners> = {};

  const submitUserOperation = async (
    userOpRequest: SendUserOperationParameters<SmartAccount<GianoSmartAccountImplementation>, undefined, Call[]> & {
      account: SmartAccount<GianoSmartAccountImplementation>
    }
  ) => {
    if (injection.submitUserOperation === undefined) {
      return await bundler.sendUserOperation(userOpRequest);
    }
    // Hook provided: prepare complete user operation, sign it, and use backend validation and submission

    // Prepare the user operation with gas estimates
    const estimate = await bundler.estimateUserOperationGas(userOpRequest);
    if (!estimate) {
      throw new Error('Could not estimate user operation');
    }

    const prepared = await bundler.prepareUserOperation({
      ...userOpRequest,
      ...estimate,
    });

    // Add default gas pricing if not provided
    const preparedWithGas: UserOperation<GianoEntryPointVersion> = {
      ...prepared,
      maxFeePerGas: userOpRequest.maxFeePerGas || parseGwei('200'),
      maxPriorityFeePerGas: userOpRequest.maxPriorityFeePerGas || parseGwei('400'),
    };

    // Sign the user operation
    const signature = await userOpRequest.account.signUserOperation(preparedWithGas);

    // Create the complete signed user operation
    const signedUserOp = {
      ...preparedWithGas,
      sender: await userOpRequest.account.getAddress(),
      signature,
      account: {
        entryPoint: {
          address: GianoEntryPointAddress,
        },
      },
    };

    return await injection.submitUserOperation(signedUserOp);
  };

  const emit = <E extends keyof EIP1193EventMap>(event: E, payload: Parameters<EIP1193EventMap[E]>[0]) => {
    eventListeners[event]?.forEach((listener) => listener(payload));
  };

  const ensureAccountDeployed = async (): Promise<boolean> => {
    if (!smartAccount) return false;

    try {
      const accountAddress = await smartAccount.getAddress();
      const accountCode = await client!.getCode({ address: accountAddress });
      return !!(accountCode && accountCode !== '0x');
    } catch (error) {
      console.warn('Failed to check account deployment status:', error);
      return false;
    }
  };

  const getWebAuthnAccount = async ({
    credentialId,
    challenge,
  }: {
    credentialId?: BufferSource;
    challenge?: BufferSource;
  } = {}): Promise<WebAuthnAccount | null> => {
    try {
      const rawCredential = (await navigator.credentials.get({
        publicKey: {
          ...(credentialId && { allowCredentials: [{ id: credentialId, type: 'public-key' }] }),
          challenge: challenge || generateRandomChallenge(),
          userVerification: 'discouraged',
        },
        mediation: 'silent',
      })) as PublicKeyAssertion | null;

      if (!rawCredential) {
        return null;
      }

      // call the method injected and wait for the result true or false to continue or not
      const isSignedIn = await injection.onCredentialSignedIn(rawCredential);
      if (!isSignedIn) {
        throw new Error('Failed to sign in with credential');
      }

      const { x, y } = await injection.getPublicKeyByCredentialId(rawCredential.rawId);

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
      return smartAccount ? [await smartAccount.getAddress()] : [];
    },
    eth_chainId: async () => {
      return `0x${chain!.id.toString(16)}`;
    },
    eth_call: async ([call, blockTag]) => {
      console.log('eth_call', { call, blockTag });
      return client!.request({ method: 'eth_call', params: [call, blockTag] });
    },
    wallet_addEthereumChain: () => {
      //TODO: implement
    },
    wallet_revokePermissions: () => {
      smartAccount = null;
      emit('accountsChanged', [])
      emit('disconnect', {
        code: 4900,
        name: 'Disconnected',
        message: 'User disconnected',
        details: 'User disconnected',
      });
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
      smartAccount = null;
      chain = newChain;
      transport = newTransport;
      client = createPublicClient({ transport, chain });

      emit('chainChanged', `0x${chainId.toString(16)}`);
    },
    eth_requestAccounts: async () => {
      if (smartAccount) {
        return [await smartAccount.getAddress()];
      }

      const credentialInfo = await injection.getCredentialInfo();

      if (credentialInfo.credentialId) {
        const challenge = credentialInfo.challenge;
        const webAuthnAccount = await getWebAuthnAccount({ credentialId: credentialInfo.credentialId, challenge });
        if (!webAuthnAccount) {
          throw new Error('Invalid credential');
        }
        smartAccount = await toGianoSmartAccount({ client: client!, owners: [webAuthnAccount], factoryAddress: gianoSmartWalletFactoryAddress })
        const smartAccountAddress = await smartAccount.getAddress()

        emit('connect', { chainId: `0x${chain!.id.toString(16)}` });
        emit('accountsChanged', [smartAccountAddress]);

        return [smartAccountAddress];
      }

      const credentialName = await injection.getNameForCredential();
      const newCredentialInfo = await injection.getCredentialInfo();
      const chainId = `0x${chain!.id.toString(16)}`;
      const credential = await createWebAuthnCredential({
        user: {
          name: credentialName,
          id: injection.encodeUserId(self.crypto.randomUUID().replace(/-/g, ''), gianoSmartWalletFactoryAddress, chainId, ChainType.HARDHAT),
        },
        challenge: newCredentialInfo.challenge,
      });

      const handlerCreatedAddress = await injection.onCredentialCreated(credentialName, newCredentialInfo.challenge, credential.raw);

      if (handlerCreatedAddress) {
        smartAccount = await toGianoSmartAccount({
          client: client!,
          owners: [toWebAuthnAccount({ credential })],
          address: handlerCreatedAddress,
          factoryAddress: gianoSmartWalletFactoryAddress,
        });

        emit('connect', { chainId });
        emit('accountsChanged', [handlerCreatedAddress]);
        return [handlerCreatedAddress];
      }

      smartAccount = await toGianoSmartAccount({
        client: client!,
        owners: [toWebAuthnAccount({ credential })],
        factoryAddress: gianoSmartWalletFactoryAddress,
      });
      const smartAccountAddress = await smartAccount.getAddress();

      const xyVector = extractXYCoords(credential.publicKey);

      // Check if the smart account is already deployed
      const accountAddress = await smartAccount.getAddress();
      const accountCode = await client!.getCode({ address: accountAddress });
      const isDeployed = accountCode && accountCode !== '0x';

      // NOTE: this is needed to deploy the smart account if we want to use it for read calls right away
      // if not, the account will be deployed on the first actual transaction
      if (!isDeployed) {
        // Deploy the smart account with a minimal transaction
        // Option 1: Send 0 ETH to self (minimal deployment transaction)
        const deploymentTx = {
          to: accountAddress,
          value: '0x0',
          data: '0x', // Empty data
        };

        try {
          console.log('Deploying smart account...');
          const deploymentHash = await methods.eth_sendTransaction([deploymentTx]);
          console.log('Smart account deployment submitted with hash:', deploymentHash);

          // Wait for the deployment transaction to be confirmed
          const deploymentReceipt = await bundler.waitForUserOperationReceipt({ hash: deploymentHash });
          console.log('Smart account deployed successfully:', deploymentReceipt);
        } catch (error) {
          console.warn('Failed to deploy smart account:', error);
          // If deployment fails, the account will be deployed on the first actual transaction
        }
      } else {
        console.log('Smart account already deployed');
      }

      // Always call the injection callback regardless of deployment status
      await injection.onCredentialKey(credential.raw.rawId, xyVector);

      emit('connect', { chainId: `0x${chain!.id.toString(16)}` });
      emit('accountsChanged', [smartAccountAddress]);
      return [smartAccountAddress];
    },
    eth_sendTransaction: async (calls: Call[]): Promise<Hash> => {
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }

      return await submitUserOperation({ calls, account: smartAccount });
    },
    waitForUserOperationReceipt: async ([hash]: [Hash]) => {
      return bundler.waitForUserOperationReceipt({ hash });
    },
    personal_sign: async ([message, address]: [string, Address]) => {
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }
      const accountAddress = await smartAccount.getAddress();
      if (address.toLowerCase() !== accountAddress.toLowerCase()) {
        throw new Error('Address mismatch');
      }

      // Convert hex string message to bytes if needed
      const messageBytes = message.startsWith('0x') ? message : toHex(message);
      return smartAccount.signMessage({ message: messageBytes });
    },
    eth_sign: async ([address, message]: [Address, string]) => {
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }
      const accountAddress = await smartAccount.getAddress();
      if (address.toLowerCase() !== accountAddress.toLowerCase()) {
        throw new Error('Address mismatch');
      }

      // eth_sign expects raw message hash, not prefixed
      return smartAccount.signMessage({ message });
    },
    eth_signTypedData: async ([address, typedData]: [Address, any]) => {
      console.log('eth_signTypedData', { address, typedData });
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }
      const accountAddress = await smartAccount.getAddress();
      if (address.toLowerCase() !== accountAddress.toLowerCase()) {
        throw new Error('Address mismatch');
      }

      return smartAccount.signTypedData(typedData);
    },
    eth_signTypedData_v4: async ([address, typedData]: [Address, string]) => {
      console.log('eth_signTypedData_v4', { address, typedData });
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }
      const accountAddress = await smartAccount.getAddress();
      if (address.toLowerCase() !== accountAddress.toLowerCase()) {
        throw new Error('Address mismatch');
      }

      // Parse the JSON string if it's a string
      const parsedTypedData = typeof typedData === 'string' ? JSON.parse(typedData) : typedData;
      return smartAccount.signTypedData(parsedTypedData);
    },
    eth_signUserOperation: async ([userOp]: [any]) => {
      console.log('eth_signUserOperation', { userOp });
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }

      return smartAccount.signUserOperation({ ...userOp });
    },
    eth_sendSignedUserOperation: async ([signedUserOp]: [UserOperation<GianoEntryPointVersion>]) => {
      console.log('eth_sendSignedUserOperation', { signedUserOp });
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }

      return await submitUserOperation({
        account: smartAccount,
        ...signedUserOp
      });
    },
    eth_prepareUserOperation: async ([calls, options = {}]: [Call[], any]) => {
      console.log('eth_prepareUserOperation', { calls, options });
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }

      const op = {
        calls,
        ...options,
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

      return {
        ...prepared,
        preVerificationGas: prepared.preVerificationGas,
        maxFeePerGas: options.maxFeePerGas || parseGwei('200'),
        maxPriorityFeePerGas: options.maxPriorityFeePerGas || parseGwei('400'),
      };
    },
  };

  methods.wallet_switchEthereumChain([{ chainId: initialChainId.toString(16) }]);

  const provider: GianoProvider = {
    request: async (args: EIP1193Parameters) => {
      const { method, params } = args;

      if (!(method in methods)) {
        return client!.request({ ...args } as any);
      }
      try {
        const response = await methods[method](params);
        return response;
      } catch (e) {
        console.error(e);
        throw e;
      }
    },
    on: <E extends keyof EIP1193EventMap>(event: E, listener: EventHandler<E>) => {
      if (!eventListeners[event]) {
        eventListeners[event] = new Set();
      }
      eventListeners[event]!.add(listener);
      return provider;
    },
    removeListener: <E extends keyof EIP1193EventMap>(event: E, listener: EventHandler<E>) => {
      eventListeners[event]?.delete(listener);
      return provider;
    },
  };

  return <const>{
    gianoClient: client!,
    gianoProvider: provider,
  };
};
