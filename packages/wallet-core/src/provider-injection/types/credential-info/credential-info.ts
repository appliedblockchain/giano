import { isNonEmptyBufferSource } from "../buffer-source";
import {
	assertBaseCredentialInfo,
	type BaseCredentialInfo,
} from "./base-credential-info";
// JSDocs links
import {
	DEFAULT_RESIDENT_KEY_REQUIREMENT, // `CredentialInfoCreate.residentKey`
} from "./defaults";
import { assertResidentKeyRequirement } from "./resident-key-requirement";

export type CredentialInfoUse = BaseCredentialInfo & {
	credentialId: BufferSource | BufferSource[];
};
export type CredentialInfoCreate = BaseCredentialInfo & {
	credentialId: null;
	/** A new credential owns no account yet, so it cannot connect to a given one. */
	address?: undefined;
	/**
	 * When not provided, defaults to {@link DEFAULT_RESIDENT_KEY_REQUIREMENT}
	 */
	residentKey?: ResidentKeyRequirement;
};
export type CredentialInfoUserPick = BaseCredentialInfo & {
	credentialId: "user-pick";
};
export type CredentialInfo =
	| CredentialInfoUse
	| CredentialInfoCreate
	| CredentialInfoUserPick;

export function assertCredentialInfo(
	value: unknown,
): asserts value is CredentialInfo {
	if (typeof value !== "object" || value === null) {
		throw new Error("Credential info must be an object");
	}

	assertBaseCredentialInfo(value);

	const info = value as CredentialInfo;
	const { credentialId } = info;

	if (credentialId === null) {
		// Refused before the passkey ceremony: the new credential could never pass the ownership
		// check, and by then the user would have a registered passkey and no connection.
		if ((info as BaseCredentialInfo).address !== undefined) {
			throw new Error(
				"`address` applies only to an existing credential: a credential that is being created (`credentialId: null`) owns no account yet",
			);
		}
		if (info.residentKey !== undefined) {
			assertResidentKeyRequirement(info.residentKey, {
				descriptor: "residentKey",
			});
		}
		return;
	}

	if (
		credentialId === "user-pick" ||
		isNonEmptyBufferSource(credentialId) ||
		// array of non-empty BufferSource items
		(credentialId instanceof Array &&
			credentialId.every((x) => isNonEmptyBufferSource(x)))
	) {
		return;
	}

	throw new Error(
		"`credentialId` must be one of: `'user-pick'`, `null`, non-empty `BufferSource`, or an array of non-empty `BufferSource`",
	);
}
