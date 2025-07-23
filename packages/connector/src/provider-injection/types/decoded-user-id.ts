import { Address } from 'viem'
import { ChainType, isChainType } from '../../provider'
import { assertHexAddress } from './hex'

export type DecodedUserId = {
  userId: string
  walletFactoryAddress: Address
  chainId: number
  chainType: ChainType
}

export function assertDecodedUserId(value: unknown): asserts value is DecodedUserId {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Decoded user ID must be an object')
  }
  const {
    userId, walletFactoryAddress, chainId, chainType
  } = value as DecodedUserId

  if (typeof userId !== 'string' || userId.length === 0) {
    throw new Error('`DecodedUserId.userId` must be a non-empty string')
  }

  assertHexAddress(walletFactoryAddress, {
    descriptor: '`DecodedUserId.walletFactoryAddress`'
  })

  if (typeof chainId !== 'number') {
    throw new Error('`DecodedUserId.chainId` must be a number')
  }

  if (!isChainType(chainType)) {
    throw new Error('`DecodedUserId.chainType` must be a valid chain type')
  }
}
