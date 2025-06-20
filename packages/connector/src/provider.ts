import { credentialKeyMapperAbi } from '@appliedblockchain/giano-contracts'
import type { Call, Hex, PublicClient } from 'viem'
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
} from 'viem'
import type { BundlerClient, SmartAccount, WebAuthnAccount } from 'viem/account-abstraction'
import { createWebAuthnCredential, toWebAuthnAccount } from 'viem/account-abstraction'
import type { EIP1193EventMap, EIP1193Parameters } from 'viem/types/eip1193'
import type { GianoSmartAccountImplementation } from './account'
import { toGianoSmartAccount } from './account'

export enum ChainType {
  HARDHAT = 0, // NOTE: This is just a placeholder for now
}

type PublicKeyAssertion = PublicKeyCredential & { response: AuthenticatorAssertionResponse }

const generateRandomChallenge = () => {
  const challenge = new Uint8Array(32)
  crypto.getRandomValues(challenge)
  return challenge
}

function extractXYCoords(key: Uint8Array | Hex): { x: Hex; y: Hex } {
  if (key instanceof Uint8Array) {
    key = toHex(key.slice(-64), { size: 64 })
  }
  return { x: `0x${key.slice(-128, -64)}`, y: `0x${key.slice(-64)}` }
}

export interface GianoProviderInjection {
  getNameForCredential(): string | Promise<string>
  getCredentialId(): BufferSource | null | Promise<BufferSource | null>
  getChallenge(): BufferSource | Promise<BufferSource>
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
    credential: Omit<PublicKeyCredential, 'toJSON'>
  ): null | Promise<null> | Hex | Promise<Hex>
  encodeUserId(
    id: string,
    gianoSmartWalletFactoryAddress: string,
    chainId: string,
    chainType: ChainType
  ): Uint8Array
  decodeUserId(userId: Uint8Array): {
    userId: string
    walletFactoryAddress: string
    chainId: number
    chainType: ChainType
  }
  onCredentialSignedIn(credential: PublicKeyCredential): Promise<boolean> // method to control if the credential is signed in or not
}

export type CreateGianoProviderParams = {
  initialChainId: number
  bundler: BundlerClient
  paymaster?: Address
  chains: readonly Chain[]
  transports: Record<number, Transport> | undefined
  injection: GianoProviderInjection
  credentialKeyMapperAddress: Address
  gianoSmartWalletFactoryAddress: Address
}

type EventHandler<E extends keyof EIP1193EventMap> = (payload: Parameters<EIP1193EventMap[E]>[0]) => void
type EventListeners = {
  [E in keyof EIP1193EventMap]: Set<EventHandler<E>>
}

export const createGianoProvider = ({
  transports,
  chains,
  initialChainId,
  paymaster,
  bundler,
  injection,
  credentialKeyMapperAddress,
  gianoSmartWalletFactoryAddress,
}: CreateGianoProviderParams) => {
  let smartAccount: SmartAccount<GianoSmartAccountImplementation> | null
  let chain: Chain | undefined
  let transport: Transport | undefined
  let client: PublicClient | undefined
  let staticSignature: Hex | null = null
  let staticSignatureSignedAt = 0
  let staticSignatureLifetime = 0n
  const eventListeners: Partial<EventListeners> = {}

  const credentialMapperContract = {
    abi: credentialKeyMapperAbi,
    address: credentialKeyMapperAddress,
  };

  const emit = <E extends keyof EIP1193EventMap>(
    event: E,
    payload: Parameters<EIP1193EventMap[E]>[0],
  ) => {
    eventListeners[event]?.forEach(
      listener => listener(payload)
    )
  }

  const getPublicKeyByCredentialId = async (id: Hash) =>
    client!.readContract({
      ...credentialMapperContract,
      functionName: 'getCredentialKey',
      args: [id],
    })

  const getWebAuthnAccount = async ({
    credentialId,
    challenge,
  }: {
    credentialId?: BufferSource
    challenge?: BufferSource
  } = {}): Promise<WebAuthnAccount | null> => {

    try {
      const rawCredential = await navigator.credentials.get({
        publicKey: {
          ...(credentialId && { allowCredentials: [{ id: credentialId, type: 'public-key' }] }),
          challenge: challenge || generateRandomChallenge(),
          userVerification: 'discouraged',
        },
        mediation: 'silent',
      }) as PublicKeyAssertion | null

      if (!rawCredential) {
        return null
      }

      // call the method injected and wait for the result true or false to continue or not
      const isSignedIn = await injection.onCredentialSignedIn(rawCredential)
      if (!isSignedIn) {
        throw new Error('Failed to sign in with credential')
      }

      const idHash = keccak256(new Uint8Array(rawCredential.rawId))
      const { x, y } = await getPublicKeyByCredentialId(idHash)

      if (x === toHex(0, { size: 32 })) {
        throw new Error('Unknown credential ID')
      }
      return toWebAuthnAccount({
        credential: {
          id: rawCredential.id,
          publicKey: concatHex([x, y]),
        },
      })
    } catch (error) {
      if (['NotAllowedError', 'AbortError'].includes((error as Error).name)) {
        return null
      }
      throw error
    }
  }

  const methods: Record<string, (params?: any) => any> = {
    eth_accounts: async () => {
      return smartAccount
        ? [await smartAccount.getAddress()]
        : []
    },
    eth_chainId: async () => {
      return `0x${chain!.id.toString(16)}`
    },
    eth_call: async ([call, blockTag]) => {
      //TODO: Provide a way to configure when to trigger signature authentication of read calls
      const selector = toFunctionSelector('function balanceOf(address)')
      if (!call.data!.startsWith(selector)) {
        // passthrough non whitelisted requests to the underlying client
        return client!.request({ method: 'eth_call', params: [call, blockTag] })
      }
      
      // Check if smartAccount is available before proceeding with authenticated calls
      // If not available, try to restore with authentication if we have stored credentials
      if (!smartAccount) {
        const storedCredentialId = typeof window !== 'undefined' ? localStorage.getItem('giano_credential_id') : null
        const storedAccountAddress = typeof window !== 'undefined' ? localStorage.getItem('giano_account_address') : null

        if (storedCredentialId && storedAccountAddress) {
          try {
            const credentialIdBuffer = new Uint8Array(JSON.parse(storedCredentialId))
            const challenge = await injection.getChallenge()
            const webAuthnAccount = await getWebAuthnAccount({
              credentialId: credentialIdBuffer,
              challenge,
            })

            if (webAuthnAccount) {
              smartAccount = await toGianoSmartAccount({
                client: client!,
                owners: [webAuthnAccount],
                address: storedAccountAddress as Address,
                factoryAddress: gianoSmartWalletFactoryAddress,
              })
            }
          } catch (error) {
            console.warn('Failed to authenticate for call, falling back to regular call:', error)
            return client!.request({ method: 'eth_call', params: [call, blockTag] })
          }
        }

        if (!smartAccount) {
          console.warn('Smart account not available, falling back to regular call')
          return client!.request({ method: 'eth_call', params: [call, blockTag] })
        }
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
      smartAccount = null
      // Clear stored session data
      if (typeof window !== 'undefined') {
        localStorage.removeItem('giano_credential_id')
        localStorage.removeItem('giano_account_address')
      }
      emit('accountsChanged', [])
      emit('disconnect', {
        code: 4900,
        name: 'Disconnected',
        message: 'User disconnected',
        details: 'User disconnected',
      })
    },
    wallet_switchEthereumChain: (params) => {
      const [{ chainId: chainIdHex }] = params
      const chainId = parseInt(chainIdHex, 16)
      if (chainId === chain?.id) {
        return
      }
      const newChain = chains.find((chain) => chain.id === chainId)
      if (!newChain) {
        throw new Error(`Unknown chain: ${chainId}`)
      }
      const newTransport = transports?.[newChain.id]
      if (!newTransport) {
        throw new Error('No transport for chain')
      }
      smartAccount = null
      chain = newChain
      transport = newTransport
      client = createPublicClient({ transport, chain })

      emit('chainChanged', `0x${chainId.toString(16)}`)
    },
    eth_requestAccounts: async () => {
      if (smartAccount) {
        return [await smartAccount.getAddress()]
      }

      // Try to restore from localStorage first
      const storedCredentialId = typeof window !== 'undefined' ? localStorage.getItem('giano_credential_id') : null
      const storedAccountAddress = typeof window !== 'undefined' ? localStorage.getItem('giano_account_address') : null

      if (storedCredentialId && storedAccountAddress) {
        // For session restoration, just return the stored address without WebAuthn authentication
        // Authentication will happen when the user actually needs to sign something

        emit('connect', { chainId: `0x${chain!.id.toString(16)}` })
        emit('accountsChanged', [storedAccountAddress as `0x${string}`])

        return [storedAccountAddress]
      }

      // Fallback to original flow
      const credentialId = await injection.getCredentialId()

      if (credentialId) {
        const challenge = await injection.getChallenge()
        const webAuthnAccount = await getWebAuthnAccount({ credentialId: credentialId, challenge })
        if (!webAuthnAccount) {
          throw new Error('Invalid credential')
        }
        smartAccount = await toGianoSmartAccount({ client: client!, owners: [webAuthnAccount], factoryAddress: gianoSmartWalletFactoryAddress })
        const smartAccountAddress = await smartAccount.getAddress()

        // Store session data
        if (typeof window !== 'undefined') {
          let credentialIdArray: Uint8Array
          if (credentialId instanceof ArrayBuffer) {
            credentialIdArray = new Uint8Array(credentialId)
          } else if (credentialId instanceof Uint8Array) {
            credentialIdArray = credentialId
          } else {
            credentialIdArray = new Uint8Array((credentialId as any).buffer || credentialId)
          }
          localStorage.setItem('giano_credential_id', JSON.stringify(Array.from(credentialIdArray)))
          localStorage.setItem('giano_account_address', smartAccountAddress)
        }

        emit('connect', { chainId: `0x${chain!.id.toString(16)}` })
        emit('accountsChanged', [smartAccountAddress])

        return [smartAccountAddress]
      }

      const credentialName = await injection.getNameForCredential()
      const challenge = await injection.getChallenge()
      const chainId = `0x${chain!.id.toString(16)}`
      const credential = await createWebAuthnCredential({
        user: {
          name: credentialName,
          id: injection.encodeUserId(
            self.crypto.randomUUID().replace(/-/g, ''),
            gianoSmartWalletFactoryAddress,
            chainId,
            ChainType.HARDHAT,
          ),
        },
        challenge,
      })

      const handlerCreatedAddress = await injection.onCredentialCreated(
        credentialName, challenge, credential.raw,
      )

      if (handlerCreatedAddress) {
        smartAccount = await toGianoSmartAccount({
          client: client!,
          owners: [toWebAuthnAccount({ credential })],
          address: handlerCreatedAddress,
          factoryAddress: gianoSmartWalletFactoryAddress,
        })

        emit('connect', { chainId })
        emit('accountsChanged', [handlerCreatedAddress])
        return [handlerCreatedAddress]
      }

      smartAccount = await toGianoSmartAccount({
        client: client!,
        owners: [toWebAuthnAccount({ credential })],
        factoryAddress: gianoSmartWalletFactoryAddress,
      })
      const smartAccountAddress = await smartAccount.getAddress()

      const idHash = keccak256(toHex(new Uint8Array(credential.raw.rawId)))
      const xyVector = extractXYCoords(credential.publicKey)
      const setCredentialKeyTx = {
        to: credentialMapperContract.address,
        data: encodeFunctionData({
          abi: credentialMapperContract.abi,
          functionName: 'setCredentialKey',
          args: [idHash, xyVector],
        }),
      }

      await methods.eth_sendTransaction([setCredentialKeyTx])

      // Store session data for new credential
      if (typeof window !== 'undefined') {
        const rawId = credential.raw.rawId
        let rawIdArray: Uint8Array
        if (rawId instanceof ArrayBuffer) {
          rawIdArray = new Uint8Array(rawId)
        } else if ((rawId as unknown as any) instanceof Uint8Array) {
          rawIdArray = rawId
        } else {
          rawIdArray = new Uint8Array((rawId as any).buffer || rawId)
        }
        localStorage.setItem('giano_credential_id', JSON.stringify(Array.from(rawIdArray)))
        localStorage.setItem('giano_account_address', smartAccountAddress)
      }

      emit('connect', { chainId: `0x${chain!.id.toString(16)}` })
      emit('accountsChanged', [smartAccountAddress])
      return [smartAccountAddress]
    },
    eth_sendTransaction: async (calls: Call[]) => {
      if (!smartAccount) {
        // If no smart account but we have stored credentials, try to restore it with authentication
        const storedCredentialId = typeof window !== 'undefined' ? localStorage.getItem('giano_credential_id') : null
        const storedAccountAddress = typeof window !== 'undefined' ? localStorage.getItem('giano_account_address') : null

        if (storedCredentialId && storedAccountAddress) {
          try {
            const credentialIdBuffer = new Uint8Array(JSON.parse(storedCredentialId))
            const challenge = await injection.getChallenge()
            const webAuthnAccount = await getWebAuthnAccount({
              credentialId: credentialIdBuffer,
              challenge,
            })

            if (webAuthnAccount) {
              smartAccount = await toGianoSmartAccount({
                client: client!,
                owners: [webAuthnAccount],
                address: storedAccountAddress as Address,
                factoryAddress: gianoSmartWalletFactoryAddress
              })
            }
          } catch (error) {
            console.warn('Failed to authenticate for transaction:', error)
            throw new Error('Authentication failed')
          }
        }

        if (!smartAccount) {
          throw new Error('Giano not connected')
        }
      }
      const op = {
        ...(paymaster && {
          paymaster,
        }),
        calls,
      }
      const estimate = await bundler.estimateUserOperationGas({ account: smartAccount, ...op })
      if (!estimate) {
        throw new Error('Could not estimate user operation')
      }
      const prepared = await bundler.prepareUserOperation({
        account: smartAccount,
        ...op,
        ...estimate,
      })
      const finalOp = {
        ...prepared,
        preVerificationGas: prepared.preVerificationGas, // ! redundant
        //TODO: implement callback to fetch these prices
        maxFeePerGas: parseGwei('200'),
        maxPriorityFeePerGas: parseGwei('400'),
      }
      const signature = await smartAccount.signUserOperation(finalOp)
      const signedOp = {
        ...finalOp,
        signature,
      }
      const hash = await bundler.sendUserOperation(signedOp)

      const { receipt: txReceipt } = await bundler.waitForUserOperationReceipt({ hash })
      return txReceipt
    },
    personal_sign: async ([message, address]: [string, Address]) => {
      if (!smartAccount) {
        throw new Error('Giano not connected')
      }
      const accountAddress = await smartAccount.getAddress()
      if (address.toLowerCase() !== accountAddress.toLowerCase()) {
        throw new Error('Address mismatch')
      }
      
      // Convert hex string message to bytes if needed
      const messageBytes = message.startsWith('0x') ? message : toHex(message)
      return smartAccount.signMessage({ message: messageBytes })
    },
    eth_sign: async ([address, message]: [Address, string]) => {
      if (!smartAccount) {
        throw new Error('Giano not connected')
      }
      const accountAddress = await smartAccount.getAddress()
      if (address.toLowerCase() !== accountAddress.toLowerCase()) {
        throw new Error('Address mismatch')
      }
      
      // eth_sign expects raw message hash, not prefixed
      return smartAccount.signMessage({ message })
    },
    eth_signTypedData: async ([address, typedData]: [Address, any]) => {
      console.log('eth_signTypedData', { address, typedData })
      if (!smartAccount) {
        throw new Error('Giano not connected')
      }
      const accountAddress = await smartAccount.getAddress()
      if (address.toLowerCase() !== accountAddress.toLowerCase()) {
        throw new Error('Address mismatch')
      }
      
      return smartAccount.signTypedData(typedData)
    },
    eth_signTypedData_v4: async ([address, typedData]: [Address, string]) => {
      console.log('eth_signTypedData_v4', { address, typedData })
      if (!smartAccount) {
        throw new Error('Giano not connected')
      }
      const accountAddress = await smartAccount.getAddress()
      if (address.toLowerCase() !== accountAddress.toLowerCase()) {
        throw new Error('Address mismatch')
      }
      
      // Parse the JSON string if it's a string
      const parsedTypedData = typeof typedData === 'string' ? JSON.parse(typedData) : typedData
      return smartAccount.signTypedData(parsedTypedData)
    },
    eth_signUserOperation: async ([userOp]: [any]) => {
      console.log('eth_signUserOperation', { userOp })
      if (!smartAccount) {
        throw new Error('Giano not connected')
      }
      
      return smartAccount.signUserOperation(userOp)
    },
    eth_sendSignedUserOperation: async ([signedUserOp]: [any]) => {
      console.log('eth_sendSignedUserOperation', { signedUserOp })
      if (!smartAccount) {
        throw new Error('Giano not connected')
      }
      
      const hash = await bundler.sendUserOperation(signedUserOp)
      const { receipt: txReceipt } = await bundler.waitForUserOperationReceipt({ hash })
      return txReceipt
    },
    eth_prepareUserOperation: async ([calls, options = {}]: [Call[], any]) => {
      console.log('eth_prepareUserOperation', { calls, options })
      if (!smartAccount) {
        throw new Error('Giano not connected')
      }
      
      const op = {
        ...(paymaster && { paymaster }),
        calls,
        ...options,
      }
      
      const estimate = await bundler.estimateUserOperationGas({ account: smartAccount, ...op })
      if (!estimate) {
        throw new Error('Could not estimate user operation')
      }
      
      const prepared = await bundler.prepareUserOperation({
        account: smartAccount,
        ...op,
        ...estimate,
      })
      
      return {
        ...prepared,
        preVerificationGas: prepared.preVerificationGas,
        maxFeePerGas: options.maxFeePerGas || parseGwei('200'),
        maxPriorityFeePerGas: options.maxPriorityFeePerGas || parseGwei('400'),
      }
    },
  }

  methods.wallet_switchEthereumChain([{ chainId: initialChainId.toString(16) }])

  const provider: EIP1193Provider = {
    request: async (args: EIP1193Parameters) => {
      const { method, params } = args

      if (!(method in methods)) {
        return client!.request({ ...args } as any)
      }
      try {
        const response = await methods[method](params)
        return response
      } catch (e) {
        console.error(e)
        throw e
      }
    },
    on: <E extends keyof EIP1193EventMap>(
      event: E,
      listener: EventHandler<E>
    ) => {
      if (!eventListeners[event]) {
        eventListeners[event] = new Set()
      }
      eventListeners[event]!.add(listener)
      return provider
    },
    removeListener: <E extends keyof EIP1193EventMap>(
      event: E,
      listener: EventHandler<E>,
    ) => {
      eventListeners[event]?.delete(listener)
      return provider
    },
  }

  return <const>{
    gianoClient: client!,
    gianoProvider: provider,
  }
}
