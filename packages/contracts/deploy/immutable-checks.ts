/**
 * Every immutable a release contract embeds, and how its value is checked.
 *
 * Release fingerprints (release-fingerprints.ts) mask immutables, so a match proves the code is a
 * release's but says nothing about the values filled in at deployment. Each immutable must
 * therefore either be checked semantically against the chain's own addresses, or be harmless to
 * mask, and this table records which. immutable-checks.test.ts fails when a release embeds an
 * immutable that is not listed here: a new immutable needs a decision, and usually a new check in
 * wallet-api's chain verification and in giano-doctor.
 */
import type { ReleaseContractName } from "../release-fingerprints";

export const IMMUTABLE_CHECKS: Partial<
	Record<ReleaseContractName, Record<string, string>>
> = {
	GianoSmartWalletFactory: {
		"GianoSmartWalletFactory.implementation":
			"factory.implementation() must equal the chain's registered wallet implementation (wallet-api chain-verify, giano-doctor)",
	},
	GianoSmartWallet: {
		"CallContextChecker.__self":
			"Solady UUPS self-address: always the contract's own address, so masking it loses nothing",
	},
	GianoPaymaster: {
		"UUPSUpgradeable.__self":
			"OpenZeppelin UUPS self-address: always the contract's own address, so masking it loses nothing",
	},
	PermissivePaymaster: {
		"BasePaymaster.entryPoint":
			"test fixture: entryPoint() must equal the chain's EntryPoint (giano-doctor)",
		"BasePaymaster._entryPoint":
			"test fixture: entryPoint() must equal the chain's EntryPoint (giano-doctor)",
	},
};
