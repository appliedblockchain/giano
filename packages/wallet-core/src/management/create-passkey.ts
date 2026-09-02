import { createWebAuthnCredential } from 'viem/account-abstraction';
import type { Hex } from 'viem';
import {
  DEFAULT_RESIDENT_KEY_REQUIREMENT,
  DEFAULT_USER_VERIFICATION_REQUIREMENT,
} from '../provider-injection';
import { fromBase64Url } from '../provider-injection/wallet-api/serialization';
import type { WalletManagementApi } from './api';
import { ownerFingerprint } from './fingerprint';
import { publicKeyOwnerBytes } from './owners';

export type DepositPasskeyParameters = {
  api: WalletManagementApi;
  claimCode: string;
  /** The WebAuthn user handle for the new credential (the caller packs it — see encodeUserId). */
  userId: BufferSource;
  /** Display name the authenticator shows for the passkey. */
  userName: string;
};

export type DepositedPasskey = {
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
export async function depositPasskeyIntoPendingAddition(parameters: DepositPasskeyParameters): Promise<DepositedPasskey> {
  const { api, claimCode, userId, userName } = parameters;
  const claimed = await api.claimPendingAddition(claimCode);
  const credential = await createWebAuthnCredential({
    challenge: fromBase64Url(claimed.challenge),
    user: { id: userId, name: userName },
    authenticatorSelection: {
      userVerification: DEFAULT_USER_VERIFICATION_REQUIREMENT,
      residentKey: DEFAULT_RESIDENT_KEY_REQUIREMENT,
    },
  });
  const filled = await api.fillPendingAddition(claimCode, credential.raw);
  return {
    publicKey: filled.publicKey,
    // From the LOCAL credential, not the server's echo: the point of the fingerprint is
    // that this device vouches for the key it created, not for what the backend stored.
    fingerprint: ownerFingerprint(localOwnerBytes(credential.publicKey) ?? publicKeyOwnerBytes(filled.publicKey.x, filled.publicKey.y)),
  };
}

/** The 64-byte x‖y from viem's credential publicKey (which may carry a prefix). */
function localOwnerBytes(publicKey: Hex): Hex | null {
  const hex = publicKey.replace(/^0x/, '');
  if (hex.length < 128) return null;
  return `0x${hex.slice(-128)}` as Hex;
}
