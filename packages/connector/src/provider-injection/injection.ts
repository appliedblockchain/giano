import { Hash, Hex } from 'viem'
import { EntryPointVersion, UserOperation } from 'viem/account-abstraction'
import { GianoEntryPointVersion } from '../giano-entry-point'
import { ChainType } from '../provider'

export interface GianoProviderInjection<EPVersion extends EntryPointVersion = GianoEntryPointVersion> {
  getNameForCredential(): string | Promise<string>;
  getCredentialInfo(): Promise<{
    credentialId?: BufferSource | null;
    challenge: BufferSource;
  }>;
  /**
   * @param credentialName - The name of the credential
   * @param challenge - The challenge used to create the credential
   * @param credential - The credential created
   * @returns Null or a wallet address. Returning a wallet address means
   *          that Giano does not proceed to create the smart wallet
   *          (the handler took care of that).
   */
  onCredentialCreated(
    credentialName: string,
    challenge: BufferSource,
    credential: Omit<PublicKeyCredential, 'toJSON'>,
  ): null | Hex | Promise<null | Hex>;
  encodeUserId(
    id: string,
    gianoSmartWalletFactoryAddress: string,
    chainId: string,
    chainType: ChainType,
  ): BufferSource | Promise<BufferSource>;
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
    return false
  }

  const typed = injection as GianoProviderInjection

  return (
    typeof typed.getNameForCredential === 'function' &&
    typeof typed.getCredentialInfo === 'function' &&
    typeof typed.onCredentialCreated === 'function' &&
    typeof typed.encodeUserId === 'function' &&
    typeof typed.decodeUserId === 'function' &&
    typeof typed.onCredentialSignedIn === 'function' &&
    typeof typed.getPublicKeyByCredentialId === 'function' &&
    typeof typed.onCredentialKey === 'function' &&
    (
      typeof typed.submitUserOperation === 'function' ||
      typeof typed.submitUserOperation === 'undefined'
    )
  )
}
