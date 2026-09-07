import {
  Call,
  Hex,
  PublicClient,
  Hash,
  concatHex,
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
import type { EIP1193EventMap, EIP1193Parameters, EIP1193RequestFn, EIP1474Methods } from 'viem';
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
import { toBase64Url } from './provider-injection/wallet-api/serialization'
import { ensureSmartAccountIsDeployed, isSmartAccountDeployed } from './account/deployment'
import { GianoError } from './giano-error'
import type { GianoLogger } from './logger'
import { defaultGianoLogger } from './logger'
import { TransactionRequest } from 'viem'
import { ExactPartial } from 'viem'
import { RpcTransactionRequest } from 'viem'

/**
 * Chain family encoded into the WebAuthn user id (1 byte). EVM covers every chain Giano
 * currently deploys to; the byte exists so a future non-EVM family can be distinguished
 * without changing the id layout. `HARDHAT` is kept as a deprecated alias of the EVM
 * value so existing encoded ids keep decoding.
 */
export enum ChainType {
  EVM = 0,
  /** @deprecated use EVM — retained as a 0-valued alias for backward compatibility */
  HARDHAT = 0,
}

type PrepareUserOperationOptions = Partial<
  Omit<
    SendUserOperationParameters<SmartAccount<GianoSmartAccountImplementation>, undefined, TransactionRequest[]>,
    'account' | 'calls' | 'callData'
  >
>

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
  /**
   * One bundler per chain. A map even when one chain is configured: submission is a
   * chain-bound resource, and no operation for one chain may ever be submitted through
   * another chain's endpoint (MC-43, MC-58).
   */
  bundlers: Record<number, BundlerClient>;
  chains: readonly Chain[];
  transports: Record<number, Transport> | undefined;
  injection: GianoProviderInjection;
  /**
   * One factory address per chain. Deliberately a map even though address identity (MC-19)
   * guarantees the values are equal on a canonical deployment: passing one address would
   * encode the invariant in the type where nothing checks it, and a deployment that is NOT
   * address-identical must still be expressible.
   */
  factoryAddresses: Record<number, Address>;
  /** Optional logger; defaults to silent-except-errors. */
  logger?: GianoLogger;
  /**
   * Fallback fee estimation used when neither the request nor the bundler's
   * prepared op carries fees, resolved per chain — fee levels differ between chains
   * by orders of magnitude, so one figure cannot serve them all.
   */
  estimateFeesPerGas?: (chainId: number) => Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }>;
};

type EventHandler<E extends keyof EIP1193EventMap> = (payload: Parameters<EIP1193EventMap[E]>[0]) => void;
type EventListeners = {
  [E in keyof EIP1193EventMap]: Set<EventHandler<E>>;
};

type GianoProviderCustomMethods = [
  {
    Method: 'waitForUserOperationReceipt'
    Parameters: [hash: Hash]
    ReturnType: UserOperationReceipt
  },
  {
    /**
     * Silently rebuilds the in-memory smart account from the stored public key and the
     * persisted wallet-api session — no passkey ceremony. Used to recover a connected
     * account after the wallet page was reloaded/reopened. Returns the account address,
     * or an empty array when it cannot be restored without a fresh sign-in.
     */
    Method: 'giano_restoreAccount'
    Parameters: []
    ReturnType: Address[]
  },
  {
    Method: 'signed_eth_call'
    Parameters: readonly  [call: ExactPartial<RpcTransactionRequest>]
    ReturnType: Hex
  },
  {
    Method: 'eth_prepareUserOperation'
    Parameters: [calls: Call[], options?: PrepareUserOperationOptions]
    ReturnType: UserOperation<GianoEntryPointVersion>
  },
  {
    Method: 'eth_signUserOperation'
    Parameters: [userOp: UserOperation<GianoEntryPointVersion>]
    ReturnType: Hex
  },
  {
    Method: 'eth_sendSignedUserOperation'
    Parameters: [signedUserOp: UserOperation<GianoEntryPointVersion>]
    ReturnType: Hash
  },
]

export type ProviderRequestMethod<
  T extends EIP1474Methods | GianoProviderCustomMethods,
  Name extends T[number]['Method']
> = (
  params: Extract<
    T[number],
    { Method: Name }
  >['Parameters']
) => Promise<Extract<T[number], { Method: Name }>['ReturnType']>

/**
 * EIP1474 methods as optional
 * Giano custom methods as required
 **/
type GianoProviderMethodsMap = Partial<{
  [T in EIP1474Methods[number] as T['Method']]: ProviderRequestMethod<EIP1474Methods, T['Method']>
}> & Required<{
  [T in GianoProviderCustomMethods[number] as T['Method']]: ProviderRequestMethod<GianoProviderCustomMethods, T['Method']>
}>

export type GianoProvider = EIP1193Provider & {
  request: EIP1193RequestFn<GianoProviderCustomMethods>
  getSmartAccount: () => SmartAccount<GianoSmartAccountImplementation> | null;
}

export type FeeValues = { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint };

/** Fee precedence: explicit request > bundler-prepared > fallback estimation. */
export function resolveUserOpFees(
  requested: Partial<FeeValues>,
  prepared: Partial<FeeValues>,
  fallback: FeeValues,
): FeeValues {
  return {
    maxFeePerGas: requested.maxFeePerGas || prepared.maxFeePerGas || fallback.maxFeePerGas,
    maxPriorityFeePerGas: requested.maxPriorityFeePerGas || prepared.maxPriorityFeePerGas || fallback.maxPriorityFeePerGas,
  };
}

export const createGianoProvider = (options: CreateGianoProviderParams) => {
  const injection = withValidation(options.injection)
  const {
    transports,
    chains,
    initialChainId,
    bundlers,
    factoryAddresses,
  } = options
  const logger = options.logger ?? defaultGianoLogger
  const estimateFeesPerGas =
    options.estimateFeesPerGas ??
    (async (_chainId: number) => ({ maxFeePerGas: parseGwei('200'), maxPriorityFeePerGas: parseGwei('2') }))

  let smartAccount: SmartAccount<GianoSmartAccountImplementation> | null;
  let chain: Chain | undefined;
  let transport: Transport | undefined;
  let client: PublicClient | undefined;
  // Chain-bound state, swapped as one unit by wallet_switchEthereumChain. Leaving any of it
  // behind on a chain change is the latent defect this fixes: with two chains configured it
  // would silently submit user operations to the PREVIOUS chain's bundler.
  let bundler: BundlerClient | undefined;
  let factoryAddress: Address | undefined;
  let staticSignature: Hex | null = null
  let staticSignatureSignedAt = 0
  let staticSignatureLifetime = 0n
  const eventListeners: Partial<EventListeners> = {};

  const submitUserOperation = async (
    userOpRequest: SendUserOperationParameters<SmartAccount<GianoSmartAccountImplementation>, undefined, TransactionRequest[]> & {
      account: SmartAccount<GianoSmartAccountImplementation>
    }
  ) => {
    if (injection.submitUserOperation === undefined) {
      return await bundler!.sendUserOperation(userOpRequest);
    }
    // Hook provided: prepare complete user operation, sign it, and use backend validation and submission

    /*
     * Fees are resolved BEFORE estimating and preparing, not after.
     *
     * A validating paymaster signs the operation's gas fees, and viem runs the paymaster hooks
     * inside `prepareUserOperation`. Resolving fees afterwards would issue an authorisation over
     * one set of fees and submit the operation with another — which the paymaster rejects on chain
     * as `AA34`, long after anything could explain why. It also let the paymaster be asked to
     * authorise an operation whose cost was not yet known, which is not a question it can answer.
     *
     * Doing it first is also simply more correct for the unsponsored path: the gas estimate is
     * computed against the fees the operation will actually carry.
     */
    const fees = resolveUserOpFees(userOpRequest, {}, await estimateFeesPerGas(chain!.id));
    const requestWithFees = { ...userOpRequest, ...fees };

    /*
     * One `prepareUserOperation`, not an `estimateUserOperationGas` followed by a prepare.
     *
     * `prepareUserOperation` estimates gas itself, so the separate estimate was always redundant —
     * but with a paymaster attached it is actively harmful: each call runs the paymaster hooks, and
     * viem picks a fresh random nonce key each time. Against a validating paymaster that means two
     * *signed* authorisations and two balance reservations per transaction, only one of which is
     * ever submitted. The unused one holds the tenant's funds until its TTL expires, so a tenant's
     * effective available balance is silently halved.
     */
    const prepared = await bundler!.prepareUserOperation(requestWithFees);
    if (!prepared) {
      throw new Error('Could not prepare user operation');
    }

    const preparedWithGas: UserOperation<GianoEntryPointVersion> = {
      ...prepared,
      // Still applied over `prepared`, because `prepareUserOperation` may echo its own fee values
      // and the authorisation was issued against these.
      ...fees,
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

    // The chain the operation was hashed and signed for travels with the submission: the
    // injection is chain-agnostic, and the backend refuses to guess (MC-53).
    return await injection.submitUserOperation(signedUserOp, chain!.id);
  };

  const emit = <E extends keyof EIP1193EventMap>(event: E, payload: Parameters<EIP1193EventMap[E]>[0]) => {
    eventListeners[event]?.forEach((listener) => listener(payload));
  };

  const methods = {
    eth_accounts: async () => {
      return smartAccount ? [await smartAccount.getAddress()] : [];
    },
    giano_restoreAccount: async () => {
      if (smartAccount) {
        return [await smartAccount.getAddress()];
      }
      try {
        const credentialInfo = await injection.getCredentialInfo();
        // Only a single stored credential can be restored silently; anything else
        // (none registered, an explicit user-pick, or an ambiguous list) needs the
        // full sign-in ceremony via eth_requestAccounts.
        const { credentialId } = credentialInfo;
        const rawId =
          credentialId instanceof Array
            ? credentialId[0]
            : credentialId === null || credentialId === 'user-pick'
              ? null
              : credentialId;
        if (!rawId) {
          return [];
        }

        // Rebuild from the stored public key using the persisted wallet-api session.
        // No `navigator.credentials.get` here — the only passkey prompt happens later,
        // when a user operation or message is actually signed.
        const { x, y } = await injection.getPublicKeyByCredentialId(rawId as ArrayBuffer);
        if (x === toHex(0, { size: 32 })) {
          // wallet-api has no public key for this credential (or the session is invalid)
          return [];
        }

        smartAccount = await toGianoSmartAccount({
          client: client!,
          owners: [toWebAuthnAccount({ credential: { id: toBase64Url(rawId as ArrayBuffer), publicKey: concatHex([x, y]) } })],
          factoryAddress: factoryAddress!,
        });

        const smartAccountAddress = await smartAccount.getAddress();
        emit('connect', { chainId: `0x${chain!.id.toString(16)}` });
        emit('accountsChanged', [smartAccountAddress]);
        return [smartAccountAddress];
      } catch (error) {
        // Best-effort: any failure (expired session, network, unknown credential) just
        // means "not restorable silently" — the caller should fall back to a sign-in.
        logger.warn('giano_restoreAccount: silent restore failed', error);
        smartAccount = null;
        return [];
      }
    },
    eth_chainId: async () => {
      return `0x${chain!.id.toString(16)}`;
    },
    eth_call: async (params) => {
      logger.debug('eth_call', params)

      return client!.request({ method: 'eth_call', params })
    },
    signed_eth_call: async (params) => {
      // Check if smartAccount is available before proceeding with authenticated calls
      if (!smartAccount) {
        logger.warn('Smart account not available, falling back to regular call')
        return client!.request({ method: 'eth_call', params })
      }

      // Check if the account is deployed before attempting authenticated calls
      const isDeployed = await isSmartAccountDeployed(client!, smartAccount)
      if (!isDeployed) {
        logger.warn('Smart account not deployed yet, falling back to regular call')
        return client!.request({ method: 'eth_call', params })
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

      const [transaction] = params

      if (!transaction.to) {
        throw new GianoError('signed_eth_call: `transaction.to` is required')
      }
      if (!transaction.data) {
        throw new GianoError('signed_eth_call: `transaction.data` is required')
      }

      // encode the intended call and forward it to the Giano account contract
      const result = await client!.readContract({
        abi: smartAccount.abi,
        address: smartAccount.address,
        functionName: 'signedStaticCall',
        args: [{
          target: transaction.to,
          data: transaction.data,
          signedAt: BigInt(staticSignatureSignedAt),
          signature: staticSignature,
        }],
      })
      return result    
    },
    wallet_addEthereumChain: async () => {
      // MC-14: an explicit, typed refusal — never a silent no-op that appears to succeed.
      // A chain is a member of the deployment's closed configured list (D8), never a value
      // a caller adds at runtime.
      throw new GianoError('wallet_addEthereumChain is not supported: Giano serves a closed, configured list of chains')
    },
    wallet_revokePermissions: async ([permissions]) => {
      // ignoring permissions, revoking all
      // we only support one connected account per provider instance
      smartAccount = null
      emit('accountsChanged', [])
      emit('disconnect', {
        code: 4900,
        name: 'Disconnected',
        message: 'User disconnected',
        details: 'User disconnected',
      })

      return null
    },
    wallet_switchEthereumChain: async ([{ chainId: chainIdHex }]) => {
      const chainId = parseInt(chainIdHex, 16);
      if (chainId === chain?.id) {
        return null
      }
      const newChain = chains.find((chain) => chain.id === chainId);
      if (!newChain) {
        throw new Error(`Unknown chain: ${chainId}`);
      }
      const newTransport = transports?.[newChain.id];
      if (!newTransport) {
        throw new Error('No transport for chain');
      }
      // Throwing rather than falling back is deliberate: a chain configured for reads but
      // not for submission is a misconfiguration, and silently keeping the previous chain's
      // bundler is exactly the defect this closes (MC-113) — a "switched" provider would
      // keep submitting user operations to the OLD chain's bundler and deriving addresses
      // from the OLD chain's factory.
      const newBundler = bundlers[newChain.id];
      if (!newBundler) {
        throw new Error(`No bundler for chain ${chainId}`);
      }
      const newFactory = factoryAddresses[newChain.id];
      if (!newFactory) {
        throw new Error(`No factory address for chain ${chainId}`);
      }
      smartAccount = null;
      // The cached authenticated-read signature was produced against a specific account on a
      // specific chain, with a lifetime read from that account. Carrying it across a chain
      // change would present a signature from one chain to a contract on another.
      staticSignature = null;
      staticSignatureSignedAt = 0;
      staticSignatureLifetime = 0n;
      chain = newChain;
      transport = newTransport;
      client = createPublicClient({ transport, chain });
      bundler = newBundler;
      factoryAddress = newFactory;

      emit('chainChanged', `0x${chainId.toString(16)}`)
      return null
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
        smartAccount = await toGianoSmartAccount({ client: client!, owners: [webAuthnAccount], factoryAddress: factoryAddress! })
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
          // The handle deliberately carries NO chain id (MC-78): the credential it names is
          // valid on every chain the deployment serves, and the handle can never be rewritten.
          id: await injection.encodeUserId(
            uuidv4().replace(/-/g, ''),
            factoryAddress!,
            ChainType.EVM,
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
          factoryAddress: factoryAddress!,
        });

        emit('connect', { chainId });
        emit('accountsChanged', [handlerCreatedAddress]);
        return [handlerCreatedAddress];
      }

      smartAccount = await toGianoSmartAccount({
        client: client!,
        owners: [toWebAuthnAccount({ credential })],
        factoryAddress: factoryAddress!,
      });

      const xyVector = extractXYCoords(credential.publicKey);

      // NOTE: it is needed to deploy the smart account if we want to
      // use it for read calls or to receive funds right away, if not,
      // the account will be deployed on the first actual transaction
      try {
        await ensureSmartAccountIsDeployed(
          smartAccount, client!, methods.eth_sendTransaction,
        )
      } catch (error) {
        logger.error('Failed to ensure smart account is deployed:', error)
      }

      // Always call the injection callback regardless of deployment status
      await injection.onCredentialKey(credential.raw.rawId, xyVector);

      const smartAccountAddress = await smartAccount.getAddress();

      emit('connect', { chainId: `0x${chain!.id.toString(16)}` });
      emit('accountsChanged', [smartAccountAddress]);
      return [smartAccountAddress];
    },
    eth_sendTransaction: async ([transaction]) => {
      if (!smartAccount) {
        throw new GianoError('Giano not connected')
      }

      if (!transaction.to) {
        throw new GianoError('eth_sendTransaction: `to` field is required');
      }

      const calls: Call[] = [{
        to: transaction.to,
        value: transaction.value === undefined
          ? 0n
          : BigInt(transaction.value),
        data: transaction.data ?? '0x',
      }]

      return await submitUserOperation({ calls, account: smartAccount })
    },
    waitForUserOperationReceipt: async ([hash]: [Hash]) => {
      return bundler!.waitForUserOperationReceipt({ hash });
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
    eth_signTypedData_v4: async ([address, typedData]: [Address, string]) => {
      logger.debug('eth_signTypedData_v4', { address, typedData });
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
      logger.debug('eth_signUserOperation', { userOp });
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }

      return smartAccount.signUserOperation({ ...userOp });
    },
    eth_sendSignedUserOperation: async ([signedUserOp]: [UserOperation<GianoEntryPointVersion>]) => {
      logger.debug('eth_sendSignedUserOperation', { signedUserOp });
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }

      return await submitUserOperation({
        account: smartAccount,
        ...signedUserOp
      });
    },
    eth_prepareUserOperation: async ([calls, options = {}]) => {
      logger.debug('eth_prepareUserOperation', { calls, options });
      if (!smartAccount) {
        throw new Error('Giano not connected');
      }

      const op = {
        calls,
        ...options,
      };

      const estimate = await bundler!.estimateUserOperationGas({ account: smartAccount, ...op });
      if (!estimate) {
        throw new Error('Could not estimate user operation');
      }

      const prepared = await bundler!.prepareUserOperation({
        account: smartAccount,
        ...op,
        ...estimate,
      });

      return {
        ...prepared,
        preVerificationGas: prepared.preVerificationGas,
        ...resolveUserOpFees(options, prepared, await estimateFeesPerGas(chain!.id)),
      };
    },
  } satisfies GianoProviderMethodsMap

  methods.wallet_switchEthereumChain([{ chainId: initialChainId.toString(16) }]);

  const provider: GianoProvider = {
    getSmartAccount: () => smartAccount,
    request: (async (args: EIP1193Parameters) => {
      const { method, params } = args;

      if (!(method in methods)) {
        return client!.request({ ...args } as any);
      }
      try {
        const handler = (methods as Record<string, (params: unknown) => Promise<unknown>>)[method];
        const response = await handler(params);
        return response;
      } catch (e) {
        logger.error('provider request failed', e);
        throw e;
      }
    }) as GianoProvider['request'],
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
