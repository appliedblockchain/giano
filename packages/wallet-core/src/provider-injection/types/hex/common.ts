import { Address, Hash } from 'viem'
import { assertHex } from './assert-hex'
import { AssertHexBaseOptions } from './types'

export function assertHexAddress(value: unknown, options?: AssertHexBaseOptions): asserts value is Address {
  assertHex(value, { ...options, bytes: 20 })
}

export function assertHexHash(value: unknown, options?: AssertHexBaseOptions): asserts value is Hash {
  assertHex(value, { ...options, bytes: 32 })
}
