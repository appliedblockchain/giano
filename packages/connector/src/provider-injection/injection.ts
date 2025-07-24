import type { Hash, Hex } from 'viem';
import type { EntryPointVersion, UserOperation } from 'viem/account-abstraction';
import type { GianoEntryPointVersion } from '../giano-entry-point';
import type { ChainType } from '../provider';
import type { DecodedUserId, XYVector } from './types';

export type GianoProviderInjection<EPVersion extends EntryPointVersion = GianoEntryPointVersion> = {
  getNameForCredential(): string | Promise<string>;
  /**
   * Retrieves credential information for WebAuthn operations.
   *
   * This method is called during both credential creation and sign-in flows to determine:
   * - Whether an existing credential should be used for sign-in
   * - What challenge to use for the WebAuthn operation
   * - Whether to show a list of available credentials for selection
   *
   * For sign-in flows: Returns the stored credential ID and a new challenge
   * For new credential creation: Returns null credential ID and a new challenge
   *
   * The challenge is used to prevent replay attacks and should be cryptographically secure.
   *
   * @returns Promise resolving to credential information:
   *  - credentialId: Existing credential ID for sign-in, or null for new credential creation
   *  - challenge: Cryptographically secure random challenge for the WebAuthn operation
   *  - showListCredentials: Optional flag that when set to true shows a list of credential IDs to be used instead of forcing one from storage
   */
  getCredentialInfo(): Promise<{
    credentialId?: BufferSource | null;
    challenge: BufferSource;
    showListCredentials?: boolean;
  }>;
  /**
   * @param credentialName - The name of the credential
   * @param challenge - The challenge used to create the credential
   * @param credential - The credential created
   * @returns Null or a wallet address. Returning a wallet address means
   *          that Giano does not proceed to create the smart wallet
   *          (the handler took care of that).
   */
  onCredentialCreated(credentialName: string, challenge: BufferSource, credential: Omit<PublicKeyCredential, 'toJSON'>): null | Hex | Promise<null | Hex>;
  encodeUserId(id: string, gianoSmartWalletFactoryAddress: string, chainId: string, chainType: ChainType): BufferSource | Promise<BufferSource>;
  decodeUserId(userId: BufferSource): DecodedUserId | Promise<DecodedUserId>;
  onCredentialSignedIn(credential: PublicKeyCredential): Promise<boolean>; // method to control if the credential is signed in or not
  getPublicKeyByCredentialId(rawId: ArrayBuffer): Promise<XYVector>;
  onCredentialKey(rawId: ArrayBuffer, xyVector: XYVector): Promise<void>;
  /**
   * Override for sending user operations manually.
   * When provided, this function will handle the submission of signed user operations
   * instead of sending them directly to the bundler.
   *
   * @param signedUserOp - The complete signed user operation ready for submission
   * @returns Promise that resolves to the user operation hash
   */
  submitUserOperation?: (signedUserOp: UserOperation<EPVersion>) => Promise<Hash>;
};

export const isGianoProviderInjection = (injection: unknown): injection is GianoProviderInjection => {
  if (typeof injection !== 'object' || !injection) {
    return false;
  }

  const typed = injection as GianoProviderInjection;

  return (
    typeof typed.getNameForCredential === 'function' &&
    typeof typed.getCredentialInfo === 'function' &&
    typeof typed.onCredentialCreated === 'function' &&
    typeof typed.encodeUserId === 'function' &&
    typeof typed.decodeUserId === 'function' &&
    typeof typed.onCredentialSignedIn === 'function' &&
    typeof typed.getPublicKeyByCredentialId === 'function' &&
    typeof typed.onCredentialKey === 'function' &&
    (typeof typed.submitUserOperation === 'function' || typeof typed.submitUserOperation === 'undefined')
  );
};
