import {
	type PasskeyDevicePreference,
	withPasskeyDevicePreference,
} from "../passkey-device-preference";
import {
	type CredentialInfoUse,
	type CredentialInfoUserPick,
	DEFAULT_CREDENTIAL_MEDIATION_REQUIREMENT,
	DEFAULT_USER_VERIFICATION_REQUIREMENT,
} from "../provider-injection";

const getAllowCredentials = (
	credentialId: "user-pick" | BufferSource | BufferSource[],
): undefined | PublicKeyCredentialDescriptor[] => {
	if (credentialId === "user-pick") {
		return undefined;
	}

	const allowedIds =
		credentialId instanceof Array ? credentialId : [credentialId];

	return allowedIds.map((id) => <const>{ type: "public-key", id });
};

export const getCredential = async (
	options: CredentialInfoUse | CredentialInfoUserPick,
	preference?: PasskeyDevicePreference,
): Promise<PublicKeyCredential | null> => {
	const requestOptions: CredentialRequestOptions = {
		mediation: options.mediation ?? DEFAULT_CREDENTIAL_MEDIATION_REQUIREMENT,
		publicKey: {
			challenge: options.challenge,
			userVerification:
				options.userVerification ?? DEFAULT_USER_VERIFICATION_REQUIREMENT,
			allowCredentials: getAllowCredentials(options.credentialId),
		},
	};

	return <PublicKeyCredential | null>(
		await navigator.credentials.get(
			withPasskeyDevicePreference(requestOptions, preference),
		)
	);
};
