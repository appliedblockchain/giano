import { entryPoint07Address, entryPoint08Address, EntryPointVersion } from 'viem/account-abstraction'

// EntryPoint v0.8 address - TESTING CONFIGURATION
// For testing dual EntryPoint support functionality, we use the same EntryPoint as v0.7
// In production, this would be the actual EntryPoint v0.8 address once deployed
// This allows us to test UI switching, provider recreation, and verification without deploying new contracts
export const ENTRYPOINT_V08_ADDRESS = '0x0000000071727De22E5E9d8BAf0edAc6f37da032' as const

export type SupportedEntryPointVersion = '0.7' | '0.8'

export interface EntryPointConfig {
  version: SupportedEntryPointVersion
  address: `0x${string}`
}

// Default configuration for EntryPoint v0.7
export const ENTRYPOINT_V07_CONFIG: EntryPointConfig = {
  version: '0.7',
  address: entryPoint07Address
}

// Configuration for EntryPoint v0.8 - TESTING CONFIGURATION
// Uses same address as v0.7 for testing dual support functionality
export const ENTRYPOINT_V08_CONFIG: EntryPointConfig = {
  version: '0.8',
  address: ENTRYPOINT_V08_ADDRESS
}

// Available EntryPoint configurations
export const ENTRYPOINT_CONFIGS = {
  '0.7': ENTRYPOINT_V07_CONFIG,
  '0.8': ENTRYPOINT_V08_CONFIG
} as const

// Default EntryPoint version (maintaining backward compatibility)
export const DEFAULT_ENTRYPOINT_VERSION: SupportedEntryPointVersion = '0.7'

// Legacy exports for backward compatibility
export const GianoEntryPointVersion = '0.7' satisfies EntryPointVersion
export type GianoEntryPointVersion = typeof GianoEntryPointVersion
export const GianoEntryPointAddress = entryPoint07Address
export type GianoEntryPointAddress = typeof GianoEntryPointAddress

// New exports for version-aware EntryPoint support
export function getEntryPointConfig(version: SupportedEntryPointVersion): EntryPointConfig {
  return ENTRYPOINT_CONFIGS[version]
}

export function getEntryPointAddress(version: SupportedEntryPointVersion): `0x${string}` {
  return ENTRYPOINT_CONFIGS[version].address
}

export function getEntryPointVersion(address: `0x${string}`): SupportedEntryPointVersion | null {
  for (const [version, config] of Object.entries(ENTRYPOINT_CONFIGS)) {
    if (config.address.toLowerCase() === address.toLowerCase()) {
      return version as SupportedEntryPointVersion
    }
  }
  return null
}
