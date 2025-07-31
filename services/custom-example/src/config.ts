// Define supported EntryPoint versions
export type SupportedEntryPointVersion = '0.7' | '0.8';

if (!process.env.NEXT_PUBLIC_BUNDLER_RPC_URL) {
  throw new Error('NEXT_PUBLIC_BUNDLER_RPC_URL is not set');
}

export const config = {
  hardhatRpcUrl: process.env.NEXT_PUBLIC_HARDHAT_RPC_URL || 'http://localhost:8545',
  bundlerRpcUrl: process.env.NEXT_PUBLIC_BUNDLER_RPC_URL,
  configKey: process.env.NEXT_PUBLIC_CONFIG_KEY ?? 'hardhat',
  paymasterAddress: process.env.NEXT_PUBLIC_PAYMASTER_ADDRESS,
  // Legacy single factory address - kept for backward compatibility (using v0.7 as default)
  gianoSmartWalletFactoryAddress: process.env.NEXT_PUBLIC_GIANO_SMART_WALLET_FACTORY_ADDRESS ?? '0x56E97c186603242C616698c684937A891A22f672',
  privateErc20Address: process.env.NEXT_PUBLIC_PRIVATE_ERC20_ADDRESS ?? '0x2eeD4959fB632694150C67b527e070921EEcb29F',
  // Default EntryPoint version - can be overridden via URL parameter or user selection
  defaultEntryPointVersion: (process.env.NEXT_PUBLIC_DEFAULT_ENTRYPOINT_VERSION as SupportedEntryPointVersion) ?? '0.7' as SupportedEntryPointVersion,
};

// Version-specific contract addresses
export const VERSION_SPECIFIC_ADDRESSES = {
  '0.7': {
    gianoSmartWalletFactoryAddress: '0x56E97c186603242C616698c684937A891A22f672',
    gianoSmartWalletImplementationAddress: '0xe40e09560701Df4D7D9876946B1eeD6e3b0fd387',
    paymasterAddress: '0x6943Bc5b52b51AfC9718aBB31EAA18A1352D5595',
  },
  '0.8': {
    gianoSmartWalletFactoryAddress: '0x91F95265a4D6cCDb56e502cFCd2C9Da80714d16e',
    gianoSmartWalletImplementationAddress: '0xD21c53250a6De37008Bee5378F2396d8e210d3De',
    paymasterAddress: '0xEfc107516CD5c0731f8Ce364bCdaD8A235794069',
  },
} as const;

// Helper function to get version-specific addresses
export function getVersionSpecificAddresses(version: SupportedEntryPointVersion) {
  return VERSION_SPECIFIC_ADDRESSES[version];
}

// Helper function to get factory address for a specific version
export function getFactoryAddress(version: SupportedEntryPointVersion): string {
  return VERSION_SPECIFIC_ADDRESSES[version].gianoSmartWalletFactoryAddress;
}

// Helper function to get implementation address for a specific version
export function getImplementationAddress(version: SupportedEntryPointVersion): string {
  return VERSION_SPECIFIC_ADDRESSES[version].gianoSmartWalletImplementationAddress;
}

// Helper function to get paymaster address for a specific version
export function getPaymasterAddress(version: SupportedEntryPointVersion): string {
  return VERSION_SPECIFIC_ADDRESSES[version].paymasterAddress;
}

// EntryPoint version configuration for different environments
export const ENTRYPOINT_VERSION_CONFIGS = {
  '0.7': {
    name: 'EntryPoint v0.7',
    description: 'Stable version with PackedUserOperation support',
    supported: true,
  },
  '0.8': {
    name: 'EntryPoint v0.8',
    description: 'Latest version with enhanced features (experimental)',
    supported: true,
  },
} as const;
