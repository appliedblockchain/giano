import { type Address, isAddress } from "viem";
import { assertNonEmptyBufferSource } from "../buffer-source";
import { assertCredentialMediationRequirement } from "./credential-mediation-requirement";
// JSDocs links
import {
	DEFAULT_CREDENTIAL_MEDIATION_REQUIREMENT, // `BaseCredentialInfo.mediation`
	DEFAULT_USER_VERIFICATION_REQUIREMENT, // `BaseCredentialInfo.userVerification`
} from "./defaults";
import { assertUserVerificationRequirement } from "./user-verification-requirement";

export type BaseCredentialInfo = {
	/**
	 * Only `'required'` is accepted: wallet-api and the wallet contract reject any passkey response
	 * without user verification. When not provided, defaults to
	 * {@link DEFAULT_USER_VERIFICATION_REQUIREMENT}.
	 */
	userVerification?: "required";
	/**
	 * When not provided, defaults to {@link DEFAULT_CREDENTIAL_MEDIATION_REQUIREMENT}
	 */
	mediation?: CredentialMediationRequirement;
	challenge: BufferSource;
	/**
	 * The smart account to connect to. Set it when the credential may be a secondary owner, added
	 * with `addOwnerPublicKey`: that owner was never part of the factory salt, so the address
	 * derived from its passkey is a different, empty account. Before it connects, the provider
	 * checks that the credential owns this account, and fails if it does not. It never falls back
	 * to the derived address.
	 *
	 * When not provided, the provider uses the address derived from the credential, as before.
	 * Only for an existing credential: a credential that is being created owns no account yet.
	 */
	address?: Address;
};

export function assertBaseCredentialInfo(
	info: unknown,
): asserts info is BaseCredentialInfo {
	if (typeof info !== "object" || info === null) {
		throw new Error("Credential info must be an object");
	}

	const { userVerification, mediation, challenge, address } =
		info as BaseCredentialInfo;

	if (userVerification !== undefined) {
		assertUserVerificationRequirement(userVerification, {
			descriptor: "userVerification",
		});
	}

	if (mediation !== undefined) {
		assertCredentialMediationRequirement(mediation, {
			descriptor: "mediation",
		});
	}

	assertNonEmptyBufferSource(challenge, { descriptor: "challenge" });

	// An all-lowercase address is valid. A mixed-case address must carry a correct EIP-55
	// checksum (viem's default strict mode), so a mistyped address fails here rather than later.
	if (
		address !== undefined &&
		(typeof address !== "string" || !isAddress(address))
	) {
		throw new Error("`address` must be a 20-byte hex address");
	}
}
