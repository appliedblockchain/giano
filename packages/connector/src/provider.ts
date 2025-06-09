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
  toFunctionSelector,
  toHex,
  type Transport,
} from 'viem';
import type { BundlerClient, SmartAccount, WebAuthnAccount } from 'viem/account-abstraction';
import { createWebAuthnCredential, toWebAuthnAccount } from 'viem/account-abstraction';
import type { EIP1193Parameters } from 'viem/types/eip1193';
import type { GianoSmartAccountImplementation } from './account';
import { toGianoSmartAccount } from './account';

type PublicKeyAssertion = PublicKeyCredential & { response: AuthenticatorAssertionResponse };

// Add modal event types
type ModalEvent =
  | { type: 'show_connection_modal' }
  | { type: 'show_loading'; message: string }
  | { type: 'show_error'; error: string }
  | { type: 'show_transaction_confirmation'; transaction: TransactionDetails }
  | { type: 'show_read_confirmation'; operation: ReadOperation }
  | { type: 'show_passkey_selection'; credentials: { id: string; name?: string }[] }
  | { type: 'hide_modal' };

type EventListener = (event: ModalEvent) => void;

type TransactionDetails = {
  to: string;
  data: string;
  value?: string;
  functionName?: string;
  args?: any[];
  description?: string;
};

type ReadOperation = {
  contract: string;
  functionName: string;
  description: string;
};

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
  let staticSignature: Hex | null = null;
  let staticSignatureSignedAt = 0;
  let staticSignatureLifetime = 0n;
  
  // Event listeners for modal
  const eventListeners: EventListener[] = [];
  
  const emitEvent = (event: ModalEvent) => {
    console.log('Provider emitting event:', event, 'to', eventListeners.length, 'listeners');
    eventListeners.forEach((listener) => listener(event));
  };

  const clearSignatureCache = () => {
    staticSignature = null;
    staticSignatureSignedAt = 0;
    staticSignatureLifetime = 0n;
  };

  const getPublicKeyByCredentialId = async (id: Hash) =>
    client!.readContract({
      ...credentialMapperContract,
      functionName: 'getCredentialKey',
      args: [id],
    });

  const getWebAuthnAccount = async ({
    id,
    challenge,
    showUI = true,
  }: {
    id?: BufferSource;
    challenge?: BufferSource;
    showUI?: boolean;
  } = {}): Promise<WebAuthnAccount | null> => {
    if (!challenge) {
      challenge = generateRandomChallenge();
    }

    try {
      if (showUI) {
        emitEvent({ type: 'show_loading', message: 'Please authenticate with your passkey' });
      }

      const rawCredential = (await navigator.credentials.get({
        publicKey: {
          ...(id && { allowCredentials: [{ id, type: 'public-key' }] }),
          challenge,
          timeout: 60000, // 1 minute timeout
          userVerification: 'preferred',
        },
      })) as PublicKeyAssertion | null;
      
      if (!rawCredential) {
        if (showUI) {
          emitEvent({ type: 'hide_modal' });
        }
        return null;
      }
      
      const idHash = keccak256(new Uint8Array(rawCredential.rawId));
      const { x, y } = await getPublicKeyByCredentialId(idHash);
      
      if (x === toHex(0, { size: 32 })) {
        throw new Error('Unknown credential ID');
      }
      
      if (showUI) {
        emitEvent({ type: 'hide_modal' });
      }
      
      return toWebAuthnAccount({
        credential: {
          id: rawCredential.id,
          publicKey: concatHex([x, y]),
        },
      });
    } catch (error) {
      if (showUI) {
        if (['NotAllowedError', 'AbortError'].includes((error as Error).name)) {
          emitEvent({ type: 'hide_modal' });
        } else {
          emitEvent({ type: 'show_error', error: (error as Error).message });
        }
      }
      
      if (['NotAllowedError', 'AbortError'].includes((error as Error).name)) {
        return null;
      }
      throw error;
    }
  };

  const createNewPasskey = async (name?: string): Promise<WebAuthnAccount> => {
    emitEvent({ type: 'show_loading', message: 'Creating new passkey...' });

    try {
      const credential = await createWebAuthnCredential({
        name: name || 'Giano Wallet' + Math.random().toString(36).substring(2, 15),
      });

      const webAuthnAccount = toWebAuthnAccount({ credential });

      // Set up smart account
      smartAccount = await toGianoSmartAccount({ client: client!, owners: [webAuthnAccount] });
      
      // Set the account address
      account = await smartAccount.getAddress();

      // Register credential mapping on-chain
      const idHash = keccak256(toHex(new Uint8Array(credential.raw.rawId)));
      const { x, y } = extractXYCoords(credential.publicKey);

      emitEvent({ type: 'show_loading', message: 'Registering passkey on-chain...' });

      await methods.eth_sendTransaction(
        [
          {
            to: credentialMapperContract.address,
            data: encodeFunctionData({
              abi: credentialMapperContract.abi,
              functionName: 'setCredentialKey',
              args: [idHash, { x, y }],
            }),
          },
        ],
        true,
      );

      emitEvent({ type: 'hide_modal' });
      return webAuthnAccount;
    } catch (error) {
      emitEvent({ type: 'show_error', error: (error as Error).message });
      throw error;
    }
  };

  const methods: Record<string, (params?: any, skipModal?: boolean) => any> = {
    eth_accounts: async () => {
      return account ? ([account] as `0x${string}`[]) : [];
    },
    eth_chainId: async () => {
      console.log({ chain });
      return `0x${chain!.id.toString(16)}`;
    },
    eth_call: async ([call, blockTag]) => {
      console.log('eth_call', { call });
      //TODO: Provide a way to configure when to trigger signature authentication of read calls
      const selector = toFunctionSelector('function balanceOf(address)');
      if (!call.data!.startsWith(selector)) {
        // passthrough non whitelisted requests to the underlying client
        return client!.request({ method: 'eth_call', params: call, blockTag });
      }

      // Ensure we have a smart account
      if (!smartAccount) {
        throw new Error('Smart account not initialized');
      }

      try {
        // if the lifetime of the static signature is not known, fetch and cache it
        if (staticSignatureLifetime === 0n) {
          staticSignatureLifetime = await client!.readContract({
            address: await smartAccount.getAddress(),
            abi: smartAccount.abi,
            functionName: 'getSignatureLifetime',
          });
        }
      } catch (error) {
        console.error('Failed to get signature lifetime:', error);
        throw new Error(`Failed to get signature lifetime: ${(error as Error).message}`);
      }

      const staticSignatureAge = BigInt(Date.now() - staticSignatureSignedAt * 1000);
      // Check if we need a new signature (no cached signature or it's expired)
      const needsAuthentication = !staticSignature || staticSignatureAge > staticSignatureLifetime * 1000n;

      if (needsAuthentication) {
        // Show read confirmation dialog only when authentication is needed
        const readOperation: ReadOperation = {
          contract: call.to!,
          functionName: 'balanceOf',
          description: 'Check your token balance',
        };

        emitEvent({ type: 'show_read_confirmation', operation: readOperation });

        // Wait for user approval
        const approved = await new Promise<boolean>((resolve) => {
          (provider as any)._handleReadApproval = (approved: boolean) => {
            resolve(approved);
          };
        });

        if (!approved) {
          emitEvent({ type: 'hide_modal' });
          throw new Error('User rejected the read operation');
        }

        try {
          emitEvent({ type: 'show_loading', message: 'Authenticating with your passkey...' });
          const { signature, signedAt } = await smartAccount.signStaticCallPermission();
          staticSignature = signature;
          staticSignatureSignedAt = signedAt;
        } catch (error) {
          console.error('Failed to sign static call permission:', error);
          emitEvent({ type: 'show_error', error: (error as Error).message });
          throw error;
        }
      }

      // Check that we have a valid signature before proceeding
      if (!staticSignature) {
        throw new Error('Failed to obtain authentication signature');
      }

      try {
        // encode the intended call and forward it to the Giano account contract
        const result = await client!.readContract({
          abi: smartAccount.abi,
          address: smartAccount.address,
          functionName: 'signedStaticCall',
          args: [{ target: call.to, data: call.data!, signedAt: BigInt(staticSignatureSignedAt), signature: staticSignature }],
        });
        console.log({ result });

        if (needsAuthentication) {
          emitEvent({ type: 'hide_modal' });
        }
        return result;
      } catch (error) {
        console.error('Failed to execute signed static call:', error);
        emitEvent({ type: 'show_error', error: (error as Error).message });
        throw error;
      }
    },
    wallet_addEthereumChain: () => {
      //TODO: implement
    },
    wallet_revokePermissions: () => {
      account = null;
      smartAccount = null;
      clearSignatureCache();
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
      smartAccount = null;
      clearSignatureCache();
      chain = newChain;
      transport = newTransport;
      client = createPublicClient({ transport, chain });
    },
    eth_requestAccounts: async () => {
      console.log('eth_requestAccounts');

      if (account) {
        return [account] as `0x${string}`[];
      }

      // Show simple modal asking if user wants to use existing passkey or create new one
      emitEvent({ type: 'show_connection_modal' });

      return new Promise((resolve, reject) => {
        const handleChoice = async (choice: 'existing' | 'new') => {
          try {
            // Clear any cached signature from previous account
            clearSignatureCache();
            
            let webAuthnAccount: WebAuthnAccount | null = null;

            if (choice === 'existing') {
              // Let browser show its native credential picker
              webAuthnAccount = await getWebAuthnAccount();
              if (webAuthnAccount) {
                smartAccount = await toGianoSmartAccount({ client: client!, owners: [webAuthnAccount] });
                account = await smartAccount.getAddress();
              }
            } else if (choice === 'new') {
              // Create new passkey (this already sets up smartAccount and account)
              webAuthnAccount = await createNewPasskey();
              // Account is already set in createNewPasskey, just get it
              if (smartAccount) {
                account = await smartAccount.getAddress();
              }
            }

            if (webAuthnAccount && account) {
              resolve([account] as `0x${string}`[]);
            } else {
              emitEvent({ type: 'hide_modal' });
              resolve([]);
            }
          } catch (error) {
            emitEvent({ type: 'show_error', error: (error as Error).message });
            reject(new Error((error as Error).message));
          }
        };

        // Expose choice handler for UI
        (provider as any)._handleConnectionChoice = handleChoice;
      });
    },
    eth_sendTransaction: async (calls: Call[], skipModal = false) => {
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }

      try {
        if (!skipModal) {
          // Parse the first call to show transaction details
          const call = calls[0];
          let transactionDetails: TransactionDetails = {
            to: call.to,
            data: call.data!,
            value: call.value?.toString(),
          };

          // Try to decode common function calls
          if (call.data && call.data.startsWith('0xa0712d68')) {
            // mint function signature
            const amount = call.data.slice(34); // Remove function selector and padding
            const amountBigInt = BigInt('0x' + amount);
            const amountEther = (Number(amountBigInt) / 1e18).toString();

            transactionDetails = {
              ...transactionDetails,
              functionName: 'mint',
              args: [amountEther + ' tokens'],
              description: `Mint ${amountEther} tokens to your account`,
            };
          } else {
            transactionDetails.description = 'Execute smart contract function';
          }

          emitEvent({ type: 'show_transaction_confirmation', transaction: transactionDetails });

          // Wait for user approval
          const approved = await new Promise<boolean>((resolve) => {
            (provider as any)._handleTransactionApproval = (approved: boolean) => {
              resolve(approved);
            };
          });

          if (!approved) {
            emitEvent({ type: 'hide_modal' });
            throw new Error('User rejected the transaction');
          }
        }

        emitEvent({ type: 'show_loading', message: 'Preparing transaction...' });

        emitEvent({ type: 'show_loading', message: 'Sign with your passkey to confirm...' });

        const op = {
          ...(paymaster && {
            paymaster,
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
          preVerificationGas: prepared.preVerificationGas,
          //TODO: implement callback to fetch these prices
          maxFeePerGas: parseGwei('200'),
          maxPriorityFeePerGas: parseGwei('400'),
        };
        const signature = await smartAccount.signUserOperation(finalOp);
        const signedOp = {
          ...finalOp,
          signature,
        };
        console.log({ signedOp });

        emitEvent({ type: 'show_loading', message: 'Submitting transaction...' });

        const hash = await bundler.sendUserOperation(signedOp);

        emitEvent({ type: 'show_loading', message: 'Waiting for confirmation...' });

        const { receipt: txReceipt } = await bundler.waitForUserOperationReceipt({ hash });

        emitEvent({ type: 'hide_modal' });

        return txReceipt;
      } catch (error) {
        emitEvent({ type: 'show_error', error: (error as Error).message });
        throw error;
      }
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
      try {
        const response = await methods[method](params);
        console.log({ response });
        return response;
      } catch (e) {
        console.error(e);
        throw e;
      }
    },
    on: (event, listener) => {
      console.log('(STUB) on event', event);
      return provider;
    },
    removeListener: (event, listener) => {
      console.log('(STUB) remove listener', event);
      return provider;
    },
    // Add modal event subscription
    onModalEvent: (listener: EventListener) => {
      eventListeners.push(listener);
      return () => {
        const index = eventListeners.indexOf(listener);
        if (index > -1) eventListeners.splice(index, 1);
      };
    },
  } as EIP1193Provider & { 
    onModalEvent: (listener: EventListener) => () => void;
  };

  return provider;
};
