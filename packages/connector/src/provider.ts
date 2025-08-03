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
  EIP1193Provider,
  Transport,
} from 'viem';
import type {
  BundlerClient,
  SendUserOperationParameters,
  SmartAccount,
  UserOperation,
  UserOperationReceipt,
} from 'viem/account-abstraction';
import { createWebAuthnCredential, toWebAuthnAccount } from 'viem/account-abstraction';
import type { EIP1193EventMap, EIP1193Parameters, EIP1193RequestFn } from 'viem/types/eip1193';
import type { GianoSmartAccountImplementation } from './account';
import { toGianoSmartAccount } from './account';
import { GianoEntryPointAddress, GianoEntryPointVersion } from './giano-entry-point'
import {
  DEFAULT_RESIDENT_KEY_REQUIREMENT,
  DEFAULT_USER_VERIFICATION_REQUIREMENT,
  GianoProviderInjection,
} from './provider-injection'
import { withValidation } from './provider-injection/_with-validation'
import { v4 as uuidv4 } from 'uuid';
import { getWebAuthnAccount } from './account'

export enum ChainType {
  HARDHAT = 0, // NOTE: This is just a placeholder for now
}

export const isChainType = (x: unknown): x is ChainType => {
  return typeof x === 'number' && Object.values(ChainType).includes(x)
}

function extractXYCoords(key: Uint8Array | Hex): { x: Hex; y: Hex } {
  if (key instanceof Uint8Array) {
    key = toHex(key.slice(-64), { size: 64 });
  }
  return { x: `0x${key.slice(-128, -64)}`, y: `0x${key.slice(-64)}` };
}

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
  getSmartAccount: () => SmartAccount<GianoSmartAccountImplementation> | null;
}

export const createGianoProvider = (options: CreateGianoProviderParams) => {
  const injection = withValidation(options.injection)
  const {
    transports,
    chains,
    initialChainId,
    bundler,
    gianoSmartWalletFactoryAddress,
  } = options

  let smartAccount: SmartAccount<GianoSmartAccountImplementation> | null;
  let chain: Chain | undefined;
  let transport: Transport | undefined;
  let client: PublicClient | undefined;
  let staticSignature: Hex | null = null
  let staticSignatureSignedAt = 0
  let staticSignatureLifetime = 0n
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

  const emit = <E extends keyof EIP1193EventMap>(event: E, payload: Parameters<EIP1193EventMap[E]>[0]) => {
    eventListeners[event]?.forEach((listener) => listener(payload));
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
    signed_eth_call: async ([call, blockTag]) => {    
      // Check if smartAccount is available before proceeding with authenticated calls
      if (!smartAccount) {
        console.warn('Smart account not available, falling back to regular call')
        return client!.request({ method: 'eth_call', params: [call, blockTag] })
      }
    
      // Check if the account is deployed before attempting authenticated calls
      const isDeployed = await ensureAccountDeployed()
      if (!isDeployed) {
        console.warn('Smart account not deployed yet, falling back to regular call')
        return client!.request({ method: 'eth_call', params: [call, blockTag] })
      }
    
      // if the lifetime of the static signature is not known, fetch and cache it
      if (staticSignatureLifetime === 0n) {
        staticSignatureLifetime = await client!.readContract({
          address: await smartAccount.getAddress(),
          abi: smartAccount.abi,
          functionName: 'getSignatureLifetime',
        })
      }
      const staticSignatureAge = BigInt(Date.now() - staticSignatureSignedAt * 1000)
      // no cached signature or it's expired? request a new on
      if (!staticSignature || staticSignatureAge > staticSignatureLifetime * 1000n) {
        const { signature, signedAt } = await smartAccount.signStaticCallPermission()
        staticSignature = signature
        staticSignatureSignedAt = signedAt
      }
      // encode the intended call and forward it to the Giano account contract
      const result = await client!.readContract({
        abi: smartAccount.abi,
        address: smartAccount.address,
        functionName: 'signedStaticCall',
        args: [{ target: call.to, data: call.data!, signedAt: BigInt(staticSignatureSignedAt), signature: staticSignature }],
      })
      return result    
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

      if (credentialInfo.credentialId !== null) {
        const webAuthnAccount = await getWebAuthnAccount(credentialInfo, injection);
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
      const chainId = `0x${chain!.id.toString(16)}`;
      const residentKey = credentialInfo.residentKey ?? DEFAULT_RESIDENT_KEY_REQUIREMENT
      const userVerification = credentialInfo.userVerification ?? DEFAULT_USER_VERIFICATION_REQUIREMENT

      const credential = await createWebAuthnCredential({
        user: {
          name: credentialName,
          id: await injection.encodeUserId(
            uuidv4().replace(/-/g, ''),
            gianoSmartWalletFactoryAddress,
            chainId,
            ChainType.HARDHAT,
          ),
        },
        challenge: credentialInfo.challenge,
        authenticatorSelection: {
          userVerification,
          residentKey,
          requireResidentKey: residentKey === 'required',
        },
      });

      const handlerCreatedAddress = await injection.onCredentialCreated(
        credentialName,
        credentialInfo.challenge,
        credential.raw,
      );

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
    getSmartAccount: () => smartAccount,
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
    }
  };

  return <const>{
    gianoClient: client!,
    gianoProvider: provider,
  };
};
