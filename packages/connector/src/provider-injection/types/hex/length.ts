import { AssertHexOptions } from './types'

type HexLength = {
  digits: number
  originalUnit: 'digit' | 'byte'
}

export function getHexAssertionLength(
  options: AssertHexOptions
): HexLength | undefined {
  if ('digits' in options && options.digits !== undefined) {
    if (typeof options.digits !== 'number') {
      throw new Error('`options.digits` must be a number')
    }

    return {
      digits: options.digits,
      originalUnit: 'digit'
    }
  }

  if ('bytes' in options && options.bytes !== undefined) {
    if (typeof options.bytes !== 'number') {
      throw new Error('`options.bytes` must be a number')
    }

    return {
      digits: options.bytes * 2,
      originalUnit: 'byte'
    }
  }

  return undefined
}

/**
 * Formats the length to: 'X-byte hex' | 'X-digit hex', or 'hex' if the length is undefined
 * @param length - The length to format
 * @returns The formatted length
 */
export function getHexAssertionLengthMessage(length: HexLength | undefined): string {
  if (length === undefined) {
    return 'hex'
  }

  const valueInOriginalUnit = length.digits / (
    length.originalUnit === 'digit' ? 1 : 2
  )

  // formats to: 'X-byte hex' | 'X-digit hex'
  return `${valueInOriginalUnit}-${length.originalUnit} hex`
}