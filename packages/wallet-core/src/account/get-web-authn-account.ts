import { type Address, concatHex, isAddress, toHex } from "viem";
import {
	toWebAuthnAccount,
	type WebAuthnAccount,
} from "viem/account-abstraction";
import {
	type PasskeyDevicePreference,
	passkeyCredentialGet,
} from "../passkey-device-preference";
import type {
	CredentialInfoUse,
	CredentialInfoUserPick,
	GianoProviderInjection,
} from "../provider-injection";
import { getCredential } from "./get-credential";

type SignInInjection = Pick<
	GianoProviderInjection,
	"onCredentialSignedIn" | "getPublicKeyByCredentialId"
>;

/** A passkey sign-in: the account that signs with the passkey, and the smart account it signs for. */
export type WebAuthnSignIn = {
	account: WebAuthnAccount;
	/**
	 * The smart account the injection says this credential signs for. Undefined when the injection
	 * returned `true` and left the choice to the caller.
	 */
	address: Address | undefined;
};

/**
 * Runs the passkey ceremony, signs the credential in and builds its WebAuthn account. Returns
 * null when the user cancelled the ceremony or the authenticator holds none of the allowed
 * credentials.
 */
export const signInWithWebAuthn = async (
	options: CredentialInfoUse | CredentialInfoUserPick,
	injection: SignInInjection,
	preference?: PasskeyDevicePreference,
): Promise<WebAuthnSignIn | null> => {
	try {
		const credential = await getCredential(options, preference);
		if (!credential) {
			return null;
		}

		const signedIn = await injection.onCredentialSignedIn(credential);
		// Only `true` or a wallet address is a sign-in. A plain-JavaScript injection that returns
		// anything else (undefined, null, a malformed address) has not signed in.
		if (
			signedIn !== true &&
			!(typeof signedIn === "string" && isAddress(signedIn))
		) {
			throw new Error("Failed to sign in with credential");
		}

		const { x, y } = await injection.getPublicKeyByCredentialId(
			credential.rawId,
		);
		if (x === toHex(0, { size: 32 })) {
			throw new Error("Unknown credential ID");
		}

		return {
			account: toWebAuthnAccount({
				getFn: passkeyCredentialGet(preference),
				credential: {
					id: credential.id,
					publicKey: concatHex([x, y]),
				},
			}),
			address: signedIn === true ? undefined : signedIn,
		};
	} catch (error) {
		if (["NotAllowedError", "AbortError"].includes((error as Error).name)) {
			return null;
		}
		throw error;
	}
};

export const getWebAuthnAccount = async (
	options: CredentialInfoUse | CredentialInfoUserPick,
	injection: SignInInjection,
	preference?: PasskeyDevicePreference,
): Promise<WebAuthnAccount | null> =>
	(await signInWithWebAuthn(options, injection, preference))?.account ?? null;
