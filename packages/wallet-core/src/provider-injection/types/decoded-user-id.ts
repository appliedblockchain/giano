import { Address } from 'viem'
import { ChainType, isChainType } from '../../provider'
import { assertHexAddress } from './hex'

/**
 * The WebAuthn user handle, decoded. Every field is chain-independent by design (MC-78):
 * a credential is valid on EVERY chain its deployment serves, so the handle carries no
 * chain id — a value that is misleading by construction will eventually be trusted.
 * `chainType` denotes the chain FAMILY (EVM), not a chain, and stays.
 */
export type DecodedUserId = {
  userId: string
  walletFactoryAddress: Address
  chainType: ChainType
}

export function assertDecodedUserId(value: unknown): asserts value is DecodedUserId {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Decoded user ID must be an object')
  }
  const {
    userId, walletFactoryAddress, chainType
  } = value as DecodedUserId

  if (typeof userId !== 'string' || userId.length === 0) {
    throw new Error('`DecodedUserId.userId` must be a non-empty string')
  }

  assertHexAddress(walletFactoryAddress, {
    descriptor: '`DecodedUserId.walletFactoryAddress`'
  })

  if (!isChainType(chainType)) {
    throw new Error('`DecodedUserId.chainType` must be a valid chain type')
  }
}
