import { Hex } from 'viem'
import { assertHex } from './hex'

export type XYVector = {
  /** The x-coordinate of the public key (32-byte hex string) */
  x: Hex
  /** The y-coordinate of the public key (32-byte hex string) */
  y: Hex
}

export function assertXYVector(value: unknown): asserts value is XYVector {
  if (typeof value !== 'object' || value === null) {
    throw new Error('XY vector must be an object')
  }

  const { x, y } = value as XYVector

  assertHex(x, { bytes: 32, descriptor: 'X-coordinate' })
  assertHex(y, { bytes: 32, descriptor: 'Y-coordinate' })
}
