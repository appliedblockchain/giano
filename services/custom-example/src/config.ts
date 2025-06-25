import { isAddress, type Hex } from 'viem'

function requiredAddress(s?: string): Hex {
  if (s === undefined) {
    throw new Error('Required address is not set')
  }
  if (!isAddress(s)) {
    throw new Error('Invalid address')
  }
  return s as Hex
}

export const config = {
  paymasterAddress: requiredAddress(process.env.NEXT_PUBLIC_PAYMASTER_ADDRESS),
  credentialKeyMapperAddress: requiredAddress(process.env.NEXT_PUBLIC_CREDENTIAL_KEY_MAPPER_ADDRESS),
  gianoSmartWalletFactoryAddress: requiredAddress(process.env.NEXT_PUBLIC_GIANO_SMART_WALLET_FACTORY_ADDRESS),
  privateErc20Address: requiredAddress(process.env.NEXT_PUBLIC_PRIVATE_ERC20_ADDRESS),
}
