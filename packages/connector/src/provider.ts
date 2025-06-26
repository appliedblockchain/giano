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
import { createBundlerClient, createWebAuthnCredential, toCoinbaseSmartAccount, toWebAuthnAccount } from 'viem/account-abstraction'
import type { EIP1193EventMap, EIP1193Parameters } from 'viem/types/eip1193'
import type { GianoSmartAccountImplementation } from './account'
import { toGianoSmartAccount } from './account'

type PublicKeyAssertion = PublicKeyCredential & { response: AuthenticatorAssertionResponse }

const credentialMapperContract = {
  abi: credentialKeyMapperAbi,
  address: <const>'0xCA9db0fE32EF30bEAFcD047cF97581edc78E65Fa',
}

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
  onCredentialLoggedIn(
    credentialId: BufferSource,
    challenge: BufferSource,
    credential: Omit<PublicKeyCredential, 'toJSON'>,
  ): boolean | Promise<boolean>
}

export type CreateGianoProviderParams = {
  initialChainId: number
  bundler: BundlerClient
  paymaster?: Address
  chains: readonly Chain[]
  transports: Record<number, Transport> | undefined
  injection: GianoProviderInjection
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
}: CreateGianoProviderParams) => {
  let smartAccount: SmartAccount<GianoSmartAccountImplementation> | null
  let chain: Chain | undefined
  let transport: Transport | undefined
  let client: PublicClient | undefined
  let staticSignature: Hex | null = null
  let staticSignatureSignedAt = 0
  let staticSignatureLifetime = 0n
  const eventListeners: Partial<EventListeners> = {}

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
    console.log('getWebAuthnAccount', { credentialId, challenge })

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

      const success = await injection.onCredentialLoggedIn(rawCredential.rawId, challenge!, rawCredential)
      if (!success) {
        return null
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
      console.log({ chain })
      return `0x${chain!.id.toString(16)}`
    },
    eth_call: async ([call, blockTag]) => {
      console.log('eth_call', { call })
      //TODO: Provide a way to configure when to trigger signature authentication of read calls
      const selector = toFunctionSelector('function balanceOf(address)')
      if (!call.data!.startsWith(selector)) {
        // passthrough non whitelisted requests to the underlying client
        return client!.request({ method: 'eth_call', params: call, blockTag })
      }
      // if the lifetime of the static signature is not known, fetch and cache it
      if (staticSignatureLifetime === 0n) {
        staticSignatureLifetime = await client!.readContract({
          address: await smartAccount!.getAddress(),
          abi: smartAccount!.abi,
          functionName: 'getSignatureLifetime',
        })
      }
      const staticSignatureAge = BigInt(Date.now() - staticSignatureSignedAt * 1000)
      // no cached signature or it's expired? request a new on
      if (!staticSignature || staticSignatureAge > staticSignatureLifetime * 1000n) {
        const { signature, signedAt } = await smartAccount!.signStaticCallPermission()
        staticSignature = signature
        staticSignatureSignedAt = signedAt
      }
      // encode the intended call and forward it to the Giano account contract
      const result = await client!.readContract({
        abi: smartAccount!.abi,
        address: smartAccount!.address,
        functionName: 'signedStaticCall',
        args: [{ target: call.to, data: call.data!, signedAt: BigInt(staticSignatureSignedAt), signature: staticSignature }],
      })
      console.log({ result })
      return result
    },
    wallet_addEthereumChain: () => {
      //TODO: implement
    },
    wallet_revokePermissions: () => {
      console.log('wallet_revokePermissions')
      smartAccount = null
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
      console.log('eth_requestAccounts')
      if (smartAccount) {
        return { accounts: [smartAccount], chainId: `0x${chain!.id.toString(16)}` }
      }
      const credentialId = await injection.getCredentialId()

      if (credentialId) {
        const challenge = await injection.getChallenge()
        const webAuthnAccount = await getWebAuthnAccount({ credentialId: credentialId, challenge })
        if (!webAuthnAccount) {
          throw new Error('Invalid credential')
        }
        smartAccount = await toGianoSmartAccount({ client: client!, owners: [webAuthnAccount] })
        const smartAccountAddress = await smartAccount.getAddress()

        emit('connect', { chainId: `0x${chain!.id.toString(16)}` })
        emit('accountsChanged', [smartAccountAddress])

        console.log('returning', [smartAccountAddress])

        return [smartAccountAddress]
      }

      const credentialName = await injection.getNameForCredential()
      const challenge = await injection.getChallenge()
      const credential = await createWebAuthnCredential({
        name: credentialName, challenge,
      })

      const handlerCreatedAddress = await injection.onCredentialCreated(
        credentialName, challenge, credential.raw,
      )

      if (handlerCreatedAddress) {
        smartAccount = await toGianoSmartAccount({
          client: client!,
          owners: [toWebAuthnAccount({ credential })],
          address: handlerCreatedAddress,
        })

        emit('connect', { chainId: `0x${chain!.id.toString(16)}` })
        emit('accountsChanged', [handlerCreatedAddress])
        return [handlerCreatedAddress]
      }

      smartAccount = await toGianoSmartAccount({
        client: client!,
        owners: [toWebAuthnAccount({ credential })],
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

      emit('connect', { chainId: `0x${chain!.id.toString(16)}` })
      emit('accountsChanged', [smartAccountAddress])
      return [smartAccountAddress]
    },
    eth_sendTransaction: async (calls: Call[]) => {
      if (!smartAccount) {
        throw new Error('Giano not connected')
      }
      try {
        // For ERC-4337, we should calculate gas fees differently than regular transactions
        // Calculate conservative gas fees for ERC-4337
        const block = await client!.getBlock({ blockTag: 'latest' })
        const baseFeePerGas = block.baseFeePerGas || 0n

        const maxPriorityFeePerGas = parseGwei('1') // 1 gwei priority fee
        const maxFeePerGas = baseFeePerGas + maxPriorityFeePerGas + parseGwei('1') // baseFee + priority + buffer

        const op = {
          calls,
          maxFeePerGas,
          maxPriorityFeePerGas,
          // Initial gas estimates for paymaster estimation
          callGasLimit: 100_000n,
          verificationGasLimit: 100_000n,
          preVerificationGas: 50_000n,
        }
        const estimate = await bundler.estimateUserOperationGas({ account: smartAccount, ...op })
        if (!estimate) {
          throw new Error('Could not estimate user operation')
        }
        console.warn('WHELELE estimate', { estimate }) // try bumping up by 10%
        const preparedUserOp = await bundler.prepareUserOperation({
          account: smartAccount,
          ...op,
          ...estimate,
        })
        const signature = await smartAccount.signUserOperation(preparedUserOp)
        const signedOp = {
          ...preparedUserOp,
          signature,
        }
        console.log({ signedOp })
        const hash = await bundler.sendUserOperation(signedOp)

        const { receipt: txReceipt } = await bundler.waitForUserOperationReceipt({ hash })
        return txReceipt
      } catch (e) {
        await window.alert('Error sending transaction: ' + String(e))
        console.error('Error sending transaction', e)
        throw e
      }
    },
  }

  methods.wallet_switchEthereumChain([{ chainId: initialChainId.toString(16) }])

  const provider: EIP1193Provider = {
    request: async (args: EIP1193Parameters) => {
      const { method, params } = args

      console.log('provide.request ->', { method, params })
      if (!(method in methods)) {
        return client!.request({ ...args } as any)
      }
      try {
        const response = await methods[method](params)
        console.log({ response })
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
