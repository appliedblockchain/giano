import { GianoProviderInjection } from "../injection"
import {
  assertCredentialInfo,
  assertDecodedUserId,
  assertNonEmptyBufferSource,
  assertXYVector,
  assertHex,
  assertHexAddress,
  assertHexHash,
} from '../types'

type ValidationHook<
  // F extends (...args: any[]) => any,
  HookKey extends keyof GianoProviderInjection,
> = (
  this: GianoProviderInjection & {
    // if a safety hook is being used, then the implementation has it defined
    // thus why the use of NonNullable here (and the hook only needs to know
    // that the implementation has that specific hook defined)
    readonly implementation: NonNullable<GianoProviderInjection[HookKey]>
  },
  hookKey: HookKey,
  ...args: Parameters<NonNullable<GianoProviderInjection[HookKey]>>
) => ReturnType<NonNullable<GianoProviderInjection[HookKey]>>

export const validationHooks: {
  readonly [K in keyof GianoProviderInjection]: ValidationHook<K>
} = Object.freeze({
  getNameForCredential: async function (hookKey, ...args) {
    const hookFn = this.implementation[hookKey]
    const name = await hookFn.apply(this.implementation, args)

    if (typeof name !== 'string' || name.length === 0) {
      throw new Error('The credential name must be a non-empty string')
    }
    return name
  },
  getCredentialInfo: async function (hookKey, ...args) {
    const hookFn = this.implementation[hookKey]
    const info = await hookFn.apply(this.implementation, args)

    assertCredentialInfo(info)

    return info
  },
  onCredentialCreated: async function (hookKey, ...args) {
    const hookFn = this.implementation[hookKey]
    const address = await hookFn.apply(this.implementation, args)

    if (address === null) {
      return null
    }
    assertHexAddress(address, { descriptor: 'The wallet address' })

    return address
  },
  encodeUserId: async function (hookKey, ...args) {
    const hookFn = this.implementation[hookKey]
    const encodedUserId = await hookFn.apply(this.implementation, args)

    assertNonEmptyBufferSource(encodedUserId, {
      descriptor: 'The encoded user ID'
    })

    return encodedUserId
  },
  decodeUserId: async function (hookKey, ...args) {
    const hookFn = this.implementation[hookKey]
    const decoded = await hookFn.apply(this.implementation, args)

    assertDecodedUserId(decoded)

    return decoded
  },
  onCredentialSignedIn: async function (hookKey, ...args) {
    const hookFn = this.implementation[hookKey]
    const value = await hookFn.apply(this.implementation, args)

    if (typeof value !== 'boolean') {
      throw new Error('onCredentialSignedIn must return a boolean')
    }

    return value
  },
  getPublicKeyByCredentialId: async function (hookKey, ...args) {
    const hookFn = this.implementation[hookKey]
    const xyVector = await hookFn.apply(this.implementation, args)

    assertXYVector(xyVector)

    return xyVector
  },
  onCredentialKey: async function (hookKey, ...args) {
    const hookFn = this.implementation[hookKey]
    return await hookFn.apply(this.implementation, args)
  },
  submitUserOperation: async function (hookKey, ...args) {
    const hookFn = this.implementation[hookKey]
    const hash = await hookFn.apply(this.implementation, args)

    assertHexHash(hash, { descriptor: 'User operation hash' })

    return hash
  },
})
