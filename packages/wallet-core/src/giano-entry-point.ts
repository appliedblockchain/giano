import {
  entryPoint07Abi,
  entryPoint07Address,
  EntryPointVersion,
} from 'viem/account-abstraction'

export const GianoEntryPointVersion = '0.7' satisfies EntryPointVersion
export type GianoEntryPointVersion = typeof GianoEntryPointVersion

export const GianoEntryPointAbi = entryPoint07Abi

export const GianoEntryPointAddress = entryPoint07Address
export type GianoEntryPointAddress = typeof GianoEntryPointAddress
