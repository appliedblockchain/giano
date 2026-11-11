import type { Hex } from "viem";
import { createWebAuthnCredential } from "viem/account-abstraction";
import { GianoError } from "../giano-error";
import {
	DEFAULT_RESIDENT_KEY_REQUIREMENT,
	DEFAULT_USER_VERIFICATION_REQUIREMENT,
} from "../provider-injection";
import { fromBase64Url } from "../provider-injection/wallet-api/serialization";
import type { WalletManagementApi } from "./api";
import { ownerFingerprint } from "./fingerprint";
import { publicKeyOwnerBytes } from "./owners";
import { parseP256PublicKey } from "./p256-public-key";

/**
 * Thrown when wallet-api reports a different key for the deposited passkey than the one this
 * device created. Nothing is returned, so no add-owner call can be built from that key.
 */
export class PendingAdditionKeyMismatchError extends GianoError {}

export type DepositPasskeyParameters = {
	api: WalletManagementApi;
	claimCode: string;
	/** The WebAuthn user handle for the new credential (the caller packs it — see encodeUserId). */
	userId: BufferSource;
	/** Display name the authenticator shows for the passkey. */
	userName: string;
};

export type DepositedPasskey = {
	/** The key AS CREATED on this device. wallet-api's copy must match it, or the deposit throws. */
	publicKey: { x: Hex; y: Hex };
	/**
	 * Computed from the key AS CREATED on this device — what this device displays for the
	 * user to compare against the authorising device's screen (WM-20, WM-21).
	 */
	fingerprint: string;
};

/**
 * The new device's half of a pending addition (D8, phase 4): resolve the claim code to a
 * registration challenge, create the passkey, deposit it into the slot — where it stays
 * INERT until the authorising device's user confirms the fingerprint and signs.
 *
 * Also the whole of the same-device flow (WM-14): the authorising device runs this itself
 * with the claim code it was just issued, then proceeds straight to consent.
 */
export async function depositPasskeyIntoPendingAddition(
	parameters: DepositPasskeyParameters,
): Promise<DepositedPasskey> {
	const { api, claimCode, userId, userName } = parameters;
	const claimed = await api.claimPendingAddition(claimCode);
	const credential = await createWebAuthnCredential({
		challenge: fromBase64Url(claimed.challenge),
		user: { id: userId, name: userName },
		authenticatorSelection: {
			userVerification: DEFAULT_USER_VERIFICATION_REQUIREMENT,
			residentKey: DEFAULT_RESIDENT_KEY_REQUIREMENT,
			// Passing a custom authenticatorSelection replaces ox's default wholesale, so set the
			// deprecated-but-still-honoured requireResidentKey explicitly for older CTAP
			// authenticators — matching how the connect flow (provider.ts) builds it.
			requireResidentKey: DEFAULT_RESIDENT_KEY_REQUIREMENT === "required",
		},
	});
	// Parse the key before it is deposited: a malformed key fails here and never reaches the slot.
	const local = parseP256PublicKey(credential.publicKey);
	const filled = await api.fillPendingAddition(claimCode, credential.raw);
	// The same-device flow (WM-14) signs the add-owner call with the key returned here, and its
	// screen shows the fingerprint returned here. Both come from the key this device created, so
	// the user approves the key that is added. wallet-api's copy must be the same key: if it is
	// not, the backend stored a different key, and the deposit stops (WM-20).
	if (
		BigInt(filled.publicKey.x) !== BigInt(local.x) ||
		BigInt(filled.publicKey.y) !== BigInt(local.y)
	) {
		throw new PendingAdditionKeyMismatchError(
			"wallet-api reported a different key for the deposited passkey than the one this device created",
		);
	}
	return {
		publicKey: local,
		fingerprint: ownerFingerprint(publicKeyOwnerBytes(local.x, local.y)),
	};
}
