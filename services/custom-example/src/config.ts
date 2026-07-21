import { gianoAddresses } from '@appliedblockchain/giano-contracts';

if (!process.env.NEXT_PUBLIC_BUNDLER_RPC_URL) {
  throw new Error('NEXT_PUBLIC_BUNDLER_RPC_URL is not set');
}

const configKey = process.env.NEXT_PUBLIC_CONFIG_KEY ?? 'hardhat';

const chainIdByConfigKey: Record<string, number> = {
  hardhat: 31337,
  baseSepolia: 84532,
  base: 8453,
  'sdr-testnet': 381185,
};

// Registry fallbacks; local hardhat (31337) is never in the committed registry,
// so its addresses must always come from env.
const deployment = gianoAddresses[chainIdByConfigKey[configKey]];

export const config = {
  hardhatRpcUrl: process.env.NEXT_PUBLIC_HARDHAT_RPC_URL || 'http://localhost:8545',
  bundlerRpcUrl: process.env.NEXT_PUBLIC_BUNDLER_RPC_URL,
  walletApiUrl: process.env.NEXT_PUBLIC_WALLET_API_URL || 'http://localhost:8080',
  configKey,
  paymasterAddress: process.env.NEXT_PUBLIC_PAYMASTER_ADDRESS ?? deployment?.paymaster,
  gianoSmartWalletFactoryAddress: process.env.NEXT_PUBLIC_GIANO_SMART_WALLET_FACTORY_ADDRESS ?? deployment?.factory,
  privateErc20Address: process.env.NEXT_PUBLIC_PRIVATE_ERC20_ADDRESS ?? deployment?.testErc20,
};

if (!config.gianoSmartWalletFactoryAddress) {
  throw new Error(`No factory address: set NEXT_PUBLIC_GIANO_SMART_WALLET_FACTORY_ADDRESS (no registry entry for config key "${configKey}")`);
}
