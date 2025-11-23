import { Hex, isHex } from 'viem'
import { getHexAssertionLength, getHexAssertionLengthMessage } from './length'
import { AssertHexOptions } from './types'

export function assertHex(
  value: unknown,
  options: AssertHexOptions = {},
): asserts value is Hex {
  const lengthAssertion = getHexAssertionLength(options)

  if (
    typeof value === 'string' &&
    (!lengthAssertion || value.length === lengthAssertion.digits + 2) && // + '0x' prefix
    isHex(value, { strict: true })
  ) {
    return // all good
  }

  const lengthMessage = getHexAssertionLengthMessage(lengthAssertion)
  const errorMessage = options.descriptor
    ? `${options.descriptor} must be a valid ${lengthMessage} string`
    : `Must be a valid ${lengthMessage} string`

  throw new Error(errorMessage)
}
