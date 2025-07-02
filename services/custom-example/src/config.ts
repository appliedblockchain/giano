import { type Hex, isAddress } from 'viem';

function requiredAddress(s?: string): Hex {
  if (s === undefined) {
    throw new Error('Required address is not set');
  }
  if (!isAddress(s)) {
    throw new Error('Invalid address');
  }
  return s;
}
if (!process.env.NEXT_PUBLIC_BUNDLER_RPC_URL) {
  throw new Error('NEXT_PUBLIC_BUNDLER_RPC_URL is not set');
}

export const config = {
  bundlerRpcUrl: process.env.NEXT_PUBLIC_BUNDLER_RPC_URL,
  configKey: process.env.NEXT_PUBLIC_CONFIG_KEY ?? 'hardhat',
  paymasterAddress: process.env.NEXT_PUBLIC_PAYMASTER_ADDRESS,
  credentialKeyMapperAddress: requiredAddress(process.env.NEXT_PUBLIC_CREDENTIAL_KEY_MAPPER_ADDRESS),
  gianoSmartWalletFactoryAddress: requiredAddress(process.env.NEXT_PUBLIC_GIANO_SMART_WALLET_FACTORY_ADDRESS),
  privateErc20Address: requiredAddress(process.env.NEXT_PUBLIC_PRIVATE_ERC20_ADDRESS),
};
