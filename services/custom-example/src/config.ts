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
  privateErc20Address: process.env.NEXT_PUBLIC_PRIVATE_ERC20_ADDRESS ?? '0x2eeD4959fB632694150C67b527e070921EEcb29F', // PrivateERC20 (matches deployed)
  // Default EntryPoint version - can be overridden via URL parameter or user selection
  defaultEntryPointVersion: (process.env.NEXT_PUBLIC_DEFAULT_ENTRYPOINT_VERSION as SupportedEntryPointVersion) ?? '0.7' as SupportedEntryPointVersion,
};

// Proxy upgrade pattern addresses - UPDATED WITH DEPLOYED CONTRACTS
export const PROXY_UPGRADE_ADDRESSES = {
  // Single factory that always deploys V07 proxies (users upgrade implementations later)
  gianoSmartWalletFactoryAddress: '0xa49bA0d38E200524Da7A438705D9F34Ad245eF3a',
  
  // Implementation addresses for proxy upgrades
  implementations: {
    '0.7': '0x296B00290826aDaC27474d99023FB4Df27914059', // V07 Implementation (GianoSmartWallet)
    '0.8': '0xA2496b69798997Fb5297d4a8C08f28FF2668645D', // V08 Implementation (GianoSmartWalletV08Implementation)
  },
  
  // EntryPoint-specific configurations 
  entryPoints: {
    '0.7': {
      address: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
      paymasterAddress: '0x6943Bc5b52b51AfC9718aBB31EAA18A1352D5595', // PermissivePaymasterV07
    },
    '0.8': {
      address: '0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108', 
      paymasterAddress: '0xEfc107516CD5c0731f8Ce364bCdaD8A235794069', // PermissivePaymasterV08
    },
  },
} as const;

// Legacy - for backward compatibility (remove after migration)
export const VERSION_SPECIFIC_ADDRESSES = {
  '0.7': {
    gianoSmartWalletFactoryAddress: PROXY_UPGRADE_ADDRESSES.gianoSmartWalletFactoryAddress,
    gianoSmartWalletImplementationAddress: PROXY_UPGRADE_ADDRESSES.implementations['0.7'],
    paymasterAddress: PROXY_UPGRADE_ADDRESSES.entryPoints['0.7'].paymasterAddress,
  },
  '0.8': {
    gianoSmartWalletFactoryAddress: PROXY_UPGRADE_ADDRESSES.gianoSmartWalletFactoryAddress, // Same factory!
    gianoSmartWalletImplementationAddress: PROXY_UPGRADE_ADDRESSES.implementations['0.8'],
    paymasterAddress: PROXY_UPGRADE_ADDRESSES.entryPoints['0.8'].paymasterAddress,
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

// Helper function to get paymaster address for a specific version (legacy)
export function getPaymasterAddress(version: SupportedEntryPointVersion): string {
  return VERSION_SPECIFIC_ADDRESSES[version].paymasterAddress;
}

// NEW: Proxy upgrade pattern helpers
export function getProxyFactoryAddress(): string {
  return PROXY_UPGRADE_ADDRESSES.gianoSmartWalletFactoryAddress;
}

export function getImplementationAddress(version: SupportedEntryPointVersion): string {
  return PROXY_UPGRADE_ADDRESSES.implementations[version];
}

export function getEntryPointAddress(version: SupportedEntryPointVersion): string {
  return PROXY_UPGRADE_ADDRESSES.entryPoints[version].address;
}

export function getEntryPointPaymasterAddress(version: SupportedEntryPointVersion): string {
  return PROXY_UPGRADE_ADDRESSES.entryPoints[version].paymasterAddress;
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
