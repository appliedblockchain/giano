import {
	type EntryPointVersion,
	entryPoint09Abi,
	entryPoint09Address,
} from "viem/account-abstraction";

export const GianoEntryPointVersion: "0.9" = "0.9" satisfies EntryPointVersion;
export type GianoEntryPointVersion = typeof GianoEntryPointVersion;

export const GianoEntryPointAbi: typeof entryPoint09Abi = entryPoint09Abi;

export const GianoEntryPointAddress: typeof entryPoint09Address =
	entryPoint09Address;
export type GianoEntryPointAddress = typeof GianoEntryPointAddress;
