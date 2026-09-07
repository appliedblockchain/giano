import type { Hash, Hex } from 'viem';
import type { EntryPointVersion, UserOperation } from 'viem/account-abstraction';
import type { GianoEntryPointVersion } from '../giano-entry-point';
import type { ChainType } from '../provider';
import type { CredentialInfo, DecodedUserId, XYVector } from './types';

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
   *  - credentialId:
   *    - A `BufferSource` to use a specific credential for sign-in
   *    - A `BufferSource[]` to choose from for sign-in
   *    - `null` to create a new credential
   *    - `'user-pick'` to show a list of credentials to choose from, instead of enforcing one from storage
   *  - challenge: Cryptographically secure random challenge for the WebAuthn operation
   */
  getCredentialInfo(): Promise<CredentialInfo>;
  /**
   * @param credentialName - The name of the credential
   * @param challenge - The challenge used to create the credential
   * @param credential - The credential created
   * @returns Null or a wallet address. Returning a wallet address means
   *          that Giano does not proceed to create the smart wallet
   *          (the handler took care of that).
   */
  onCredentialCreated(credentialName: string, challenge: BufferSource, credential: Omit<PublicKeyCredential, 'toJSON'>): null | Hex | Promise<null | Hex>;
  /**
   * Packs the WebAuthn user handle. Deliberately carries NO chain id (MC-78): the
   * credential is valid on every chain the deployment serves, so every field must be
   * chain-independent — the factory address is identical everywhere (MC-19) and
   * `chainType` names the chain family, not a chain.
   */
  encodeUserId(id: string, gianoSmartWalletFactoryAddress: string, chainType: ChainType): BufferSource | Promise<BufferSource>;
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
   * @param chainId - The chain the operation was built and signed FOR. The injection is
   *                  chain-agnostic (it holds the wallet-api session, MC-76), so the chain
   *                  must travel with each submission — the backend resolves it against its
   *                  configured registry before any work happens (MC-51).
   * @returns Promise that resolves to the user operation hash
   */
  submitUserOperation?: (signedUserOp: UserOperation<EPVersion>, chainId: number) => Promise<Hash>;
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
