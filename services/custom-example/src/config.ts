if (!process.env.NEXT_PUBLIC_BUNDLER_RPC_URL) {
  throw new Error('NEXT_PUBLIC_BUNDLER_RPC_URL is not set');
}

export const config = {
  hardhatRpcUrl: process.env.NEXT_PUBLIC_HARDHAT_RPC_URL || 'http://localhost:8545',
  bundlerRpcUrl: process.env.NEXT_PUBLIC_BUNDLER_RPC_URL,
  configKey: process.env.NEXT_PUBLIC_CONFIG_KEY ?? 'hardhat',
  paymasterAddress: process.env.NEXT_PUBLIC_PAYMASTER_ADDRESS,
  gianoSmartWalletFactoryAddress: process.env.NEXT_PUBLIC_GIANO_SMART_WALLET_FACTORY_ADDRESS ?? '0x5A1dd8C52Daaa27D9ced48f7F96b2b05dD6dB0B0',
  privateErc20Address: process.env.NEXT_PUBLIC_PRIVATE_ERC20_ADDRESS ?? '0x768F92504EDbACaf0502354ea8F75BD627301519',
};
